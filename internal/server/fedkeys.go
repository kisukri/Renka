package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Other servers' keys. Requests need a current key; events need one that
// was valid when they were sent (old_verify_keys count). If a server is
// gone we ask the notary (trusted_key_servers).

const maxFedBody = 4 << 20 // a transaction is at most 50 PDUs of 64 KiB plus EDUs

type keyInfo struct {
	pub        ed25519.PublicKey
	validUntil int64 // signatures made up to this time (ms) are good
	old        bool  // retired key: only for checking old events
}

type keySet struct {
	keys      map[string]keyInfo
	fetchedAt int64
	refreshAt int64
}

// keyFetchRetry is how long a failed or missing key isn't looked up again.
const keyFetchRetry = 5 * 60 * 1000

func (k keyInfo) usable(at int64, forRequest bool) bool {
	if forRequest {
		return !k.old && k.validUntil > at
	}
	return k.validUntil >= at
}

// serverKey returns the key a request from server must be signed with.
func (s *Server) serverKey(ctx context.Context, server, keyID string) (ed25519.PublicKey, error) {
	return s.lookupKey(ctx, server, keyID, time.Now().UnixMilli(), true)
}

// eventKey returns the key for a signature made at time ts (ms).
func (s *Server) eventKey(ctx context.Context, server, keyID string, ts int64) (ed25519.PublicKey, error) {
	return s.lookupKey(ctx, server, keyID, ts, false)
}

func (s *Server) lookupKey(ctx context.Context, server, keyID string, at int64, forRequest bool) (ed25519.PublicKey, error) {
	if server == s.cfg.ServerName {
		if keyID == s.fedKey.id && s.fedKey.priv != nil {
			return s.fedKey.public(), nil
		}
		return nil, fmt.Errorf("not our key: %s", keyID)
	}
	now := time.Now().UnixMilli()
	check := func(ks *keySet) (ed25519.PublicKey, bool) {
		if ks == nil {
			return nil, false
		}
		k, ok := ks.keys[keyID]
		if !ok || !k.usable(at, forRequest) {
			return nil, false
		}
		return k.pub, true
	}
	s.fedMu.Lock()
	ks := s.fedKeys[server]
	s.fedMu.Unlock()
	if pub, ok := check(ks); ok && now < ks.refreshAt {
		return pub, nil
	}
	if ks != nil && now-ks.fetchedAt < keyFetchRetry {
		if pub, ok := check(ks); ok {
			return pub, nil
		}
		return nil, fmt.Errorf("%s has no usable key %s", server, keyID)
	}
	fresh, err := s.fetchKeySet(ctx, server, keyID)
	if err != nil {
		// remember the failure so a dead server isn't asked for every event
		fresh = &keySet{keys: map[string]keyInfo{}, fetchedAt: now, refreshAt: now + keyFetchRetry}
		if ks != nil { // keep what we knew
			fresh.keys = ks.keys
		}
	}
	s.storeKeySet(server, fresh)
	if pub, ok := check(fresh); ok {
		return pub, nil
	}
	if err != nil {
		return nil, fmt.Errorf("keys of %s: %w", server, err)
	}
	return nil, fmt.Errorf("%s has no usable key %s", server, keyID)
}

func (s *Server) storeKeySet(server string, ks *keySet) {
	s.fedMu.Lock()
	defer s.fedMu.Unlock()
	if len(s.fedKeys) > 20000 {
		s.fedKeys = map[string]*keySet{}
	}
	s.fedKeys[server] = ks
}

// fetchKeySet asks the server itself, then the notaries, for its keys.
func (s *Server) fetchKeySet(ctx context.Context, server, want string) (*keySet, error) {
	var resp map[string]any
	err := s.fedGetKeys(ctx, server, &resp)
	if err == nil {
		ks, perr := parseKeyResponse(server, resp)
		if perr == nil {
			if _, ok := ks.keys[want]; ok || len(s.cfg.TrustedKeyServers) == 0 {
				return ks, nil
			}
		}
		err = perr
		if err == nil {
			err = fmt.Errorf("no key %s", want)
		}
	}
	for _, notary := range s.cfg.TrustedKeyServers {
		if notary == server || notary == s.cfg.ServerName {
			continue
		}
		ks, nerr := s.notaryKeys(ctx, notary, server)
		if nerr == nil {
			return ks, nil
		}
		err = fmt.Errorf("%v; notary %s: %v", err, notary, nerr)
	}
	return nil, err
}

// parseKeyResponse checks server_name and the self-signatures.
func parseKeyResponse(server string, resp map[string]any) (*keySet, error) {
	if resp["server_name"] != server {
		return nil, fmt.Errorf("key response names %v", resp["server_name"])
	}
	now := time.Now().UnixMilli()
	until := toInt(resp["valid_until_ts"], 0)
	ks := &keySet{keys: map[string]keyInfo{}, fetchedAt: now}
	vks, _ := resp["verify_keys"].(map[string]any)
	for id, v := range vks {
		m, _ := v.(map[string]any)
		str, _ := m["key"].(string)
		pub, err := decodeB64(str)
		if err != nil || len(pub) != ed25519.PublicKeySize || !strings.HasPrefix(id, "ed25519:") {
			continue
		}
		if verifyJSON(resp, server, id, pub) != nil {
			continue // every current key must sign the list
		}
		ks.keys[id] = keyInfo{pub: pub, validUntil: until}
	}
	if len(ks.keys) == 0 {
		return nil, errors.New("no valid self-signed keys")
	}
	olds, _ := resp["old_verify_keys"].(map[string]any)
	for id, v := range olds {
		m, _ := v.(map[string]any)
		str, _ := m["key"].(string)
		pub, err := decodeB64(str)
		if err != nil || len(pub) != ed25519.PublicKeySize || !strings.HasPrefix(id, "ed25519:") {
			continue
		}
		if _, cur := ks.keys[id]; cur {
			continue
		}
		ks.keys[id] = keyInfo{pub: pub, validUntil: toInt(m["expired_ts"], 0), old: true}
	}
	// refetch at least weekly
	ks.refreshAt = min(until, now+7*24*3600*1000)
	if ks.refreshAt < now+keyFetchRetry {
		ks.refreshAt = now + keyFetchRetry
	}
	return ks, nil
}

// notaryKeys: answer must be signed by the server and by the notary.
func (s *Server) notaryKeys(ctx context.Context, notary, server string) (*keySet, error) {
	var out struct {
		ServerKeys []map[string]any `json:"server_keys"`
	}
	body := map[string]any{"server_keys": map[string]any{server: map[string]any{}}}
	if err := s.fedRequest(ctx, "POST", notary, "/_matrix/key/v2/query", body, &out); err != nil {
		return nil, err
	}
	for _, raw := range out.ServerKeys {
		// re-decode with exact numbers for signature checks
		b, err := canonicalJSON(raw)
		if err != nil {
			continue
		}
		v, _ := decodeJSONNumbers(b)
		resp, _ := v.(map[string]any)
		if resp["server_name"] != server {
			continue
		}
		ks, err := parseKeyResponse(server, resp)
		if err != nil {
			continue
		}
		sigs, _ := resp["signatures"].(map[string]any)
		theirs, _ := sigs[notary].(map[string]any)
		for id := range theirs {
			pub, err := s.serverKey(ctx, notary, id)
			if err == nil && verifyJSON(resp, notary, id, pub) == nil {
				return ks, nil
			}
		}
	}
	return nil, errors.New("no answer signed by the notary")
}

// prefetchKeys warms the cache before a big join.
func (s *Server) prefetchKeys(ctx context.Context, want map[string]map[string]int64) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for server, ids := range want {
		for id, ts := range ids {
			wg.Add(1)
			sem <- struct{}{}
			go func(server, id string, ts int64) {
				defer wg.Done()
				defer func() { <-sem }()
				s.eventKey(ctx, server, id, ts)
			}(server, id, ts)
			break // one lookup fetches the server's whole key list
		}
	}
	wg.Wait()
}
