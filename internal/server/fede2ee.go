package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

// E2EE across servers: device keys, one-time keys, to-device messages and
// device list updates. We send device_list_update without prev_id, so the
// other side just refetches everything. These EDUs are kept in fed_edus so
// a restart can't lose a room key. Device names never leave the server.

const (
	maxToDeviceTargets = 1000 // devices one incoming to-device EDU may address
	keysQueryTimeout   = 10 * time.Second
)

// sharesRoomWithServer: uid shares a room with server, or was invited by
// someone there (the inviter encrypts before we accept).
func sharesRoomWithServer(q querier, uid, server string) bool {
	var x int
	if q.QueryRow(`SELECT 1 FROM memberships a JOIN memberships b ON b.room_id = a.room_id
		WHERE a.user_id = ? AND a.membership IN ('join', 'invite') AND b.membership = 'join'
		AND substr(b.user_id, -length(?) - 1) = ':' || ? LIMIT 1`, uid, server, server).Scan(&x) == nil {
		return true
	}
	return q.QueryRow(`SELECT 1 FROM remote_invites r JOIN events e ON e.event_id = r.event_id
		WHERE r.user_id = ? AND substr(e.sender, -length(?) - 1) = ':' || ? LIMIT 1`, uid, server, server).Scan(&x) == nil
}

// serversSharingWith lists other servers with users in federated rooms uid is in.
func (s *Server) serversSharingWith(q querier, uid string) []string {
	rows, err := q.Query(`SELECT DISTINCT b.user_id FROM memberships a
		JOIN rooms r ON r.room_id = a.room_id AND r.federated = 1
		JOIN memberships b ON b.room_id = a.room_id
		WHERE a.user_id = ? AND a.membership IN ('join', 'invite') AND b.membership IN ('join', 'invite')`, uid)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var u string
		rows.Scan(&u)
		if d := domainOf(u); d != s.cfg.ServerName && validHostPort(d) {
			seen[d] = true
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// queueStoredEDU queues an EDU in the caller's transaction.
func (s *Server) queueStoredEDU(tx *sql.Tx, dest string, edu map[string]any) error {
	b, err := json.Marshal(edu)
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT INTO fed_edus (dest, edu) VALUES (?, ?)", dest, string(b))
	s.pendingEDUs = true
	return err
}

// announceDeviceChange tells other servers that uid's devices changed.
func (s *Server) announceDeviceChange(tx *sql.Tx, uid string, stream int64) error {
	if !s.cfg.Federation || !s.isLocal(uid) {
		return nil
	}
	dests := s.serversSharingWith(tx, uid)
	if len(dests) == 0 {
		return nil
	}
	var dev string
	tx.QueryRow("SELECT device_id FROM devices WHERE user_id = ? ORDER BY device_id LIMIT 1", uid).Scan(&dev)
	edu := map[string]any{"edu_type": "m.device_list_update", "content": map[string]any{
		"user_id": uid, "device_id": dev, "stream_id": stream, "prev_id": []any{}, "deleted": false}}
	for _, d := range dests {
		if err := s.queueStoredEDU(tx, d, edu); err != nil {
			return err
		}
	}
	return nil
}

// announceSigningKeys sends a local user's new cross-signing keys out.
func (s *Server) announceSigningKeys(tx *sql.Tx, uid string) error {
	if !s.cfg.Federation {
		return nil
	}
	content := map[string]any{"user_id": uid}
	for _, typ := range []string{"master", "self_signing"} {
		var k string
		if tx.QueryRow("SELECT keys FROM cross_signing WHERE user_id = ? AND key_type = ?", uid, typ).Scan(&k) == nil {
			content[typ+"_key"] = filterSignatures(json.RawMessage(k), uid)
		}
	}
	for _, d := range s.serversSharingWith(tx, uid) {
		if err := s.queueStoredEDU(tx, d, map[string]any{"edu_type": "m.signing_key_update", "content": content}); err != nil {
			return err
		}
	}
	return nil
}

// localDeviceKeys returns uid's device keys (all, or just want).
func localDeviceKeys(q querier, uid string, want []string, withNames bool) map[string]any {
	wantSet := map[string]bool{}
	for _, d := range want {
		wantSet[d] = true
	}
	devs := map[string]any{}
	rows, err := q.Query(`SELECT k.device_id, k.keys, d.display_name FROM device_keys k
		LEFT JOIN devices d ON d.user_id = k.user_id AND d.device_id = k.device_id WHERE k.user_id = ?`, uid)
	if err != nil {
		return devs
	}
	defer rows.Close()
	for rows.Next() {
		var id, keys string
		var name sql.NullString
		rows.Scan(&id, &keys, &name)
		if len(wantSet) > 0 && !wantSet[id] {
			continue
		}
		var obj map[string]any
		if json.Unmarshal([]byte(keys), &obj) != nil || obj == nil {
			continue
		}
		if withNames && name.Valid {
			obj["unsigned"] = map[string]any{"device_display_name": name.String}
		}
		devs[id] = obj
	}
	return devs
}

// ---- federation endpoints ----

func (s *Server) localUserFor(origin, uid string) bool {
	return s.isLocal(uid) && sharesRoomWithServer(s.db, uid, origin)
}

func (s *Server) hFedUserDevices(w http.ResponseWriter, r *http.Request, origin string, _ []byte) (any, error) {
	uid := r.PathValue("userId")
	if !s.localUserFor(origin, uid) {
		return nil, errNotFound("no such user")
	}
	var st sql.NullInt64
	s.db.QueryRow("SELECT MAX(stream) FROM device_list_changes WHERE user_id = ?", uid).Scan(&st)
	devs := []any{}
	for id, k := range localDeviceKeys(s.db, uid, nil, false) {
		devs = append(devs, map[string]any{"device_id": id, "keys": k})
	}
	out := map[string]any{"user_id": uid, "stream_id": st.Int64, "devices": devs}
	if k := s.crossSigningKey(uid, "master"); k != nil {
		out["master_key"] = filterSignatures(k, uid)
	}
	if k := s.crossSigningKey(uid, "self_signing"); k != nil {
		out["self_signing_key"] = k
	}
	return out, nil
}

func (s *Server) hFedKeysQuery(w http.ResponseWriter, r *http.Request, origin string, body []byte) (any, error) {
	var req struct {
		DeviceKeys map[string][]string `json:"device_keys"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errBadJSON("invalid body")
	}
	devKeys, master, selfSigning := map[string]any{}, map[string]any{}, map[string]any{}
	n := 0
	for uid, want := range req.DeviceKeys {
		if n++; n > 1000 || !s.localUserFor(origin, uid) {
			continue
		}
		devKeys[uid] = localDeviceKeys(s.db, uid, want, false)
		if k := s.crossSigningKey(uid, "master"); k != nil {
			master[uid] = filterSignatures(k, uid)
		}
		if k := s.crossSigningKey(uid, "self_signing"); k != nil {
			selfSigning[uid] = k
		}
	}
	return map[string]any{"device_keys": devKeys, "master_keys": master, "self_signing_keys": selfSigning}, nil
}

func (s *Server) hFedKeysClaim(w http.ResponseWriter, r *http.Request, origin string, body []byte) (any, error) {
	var req struct {
		OneTimeKeys map[string]map[string]string `json:"one_time_keys"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errBadJSON("invalid body")
	}
	allowed := map[string]map[string]string{}
	n := 0
	for uid, devs := range req.OneTimeKeys {
		if n += len(devs); n > 1000 || !s.localUserFor(origin, uid) {
			continue
		}
		allowed[uid] = devs
	}
	out, err := s.claimLocalKeys(allowed)
	return map[string]any{"one_time_keys": out}, err
}

// claimLocalKeys hands out one one-time key (or the fallback key) per device.
func (s *Server) claimLocalKeys(want map[string]map[string]string) (map[string]any, error) {
	out := map[string]any{}
	err := s.write(func(tx *sql.Tx) error {
		for uid, devs := range want {
			ud := map[string]any{}
			for dev, algo := range devs {
				var kid, key string
				err := tx.QueryRow(`SELECT key_id, key FROM one_time_keys WHERE user_id = ? AND device_id = ? AND algorithm = ?
					LIMIT 1`, uid, dev, algo).Scan(&kid, &key)
				if err == nil {
					if _, err := tx.Exec("DELETE FROM one_time_keys WHERE user_id = ? AND device_id = ? AND key_id = ?", uid, dev, kid); err != nil {
						return err
					}
				} else if tx.QueryRow(`SELECT key_id, key FROM fallback_keys WHERE user_id = ? AND device_id = ? AND algorithm = ?`,
					uid, dev, algo).Scan(&kid, &key) == nil {
					tx.Exec("UPDATE fallback_keys SET used = 1 WHERE user_id = ? AND device_id = ? AND algorithm = ?", uid, dev, algo)
				} else {
					continue
				}
				ud[dev] = map[string]any{kid: json.RawMessage(key)}
			}
			if len(ud) > 0 {
				out[uid] = ud
			}
		}
		return nil
	})
	return out, err
}

// ---- incoming EDUs ----

type seenIDs struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (s *seenIDs) firstTime(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil || len(s.seen) > 10000 {
		s.seen = map[string]bool{}
	}
	if s.seen[id] {
		return false
	}
	s.seen[id] = true
	return true
}

// handleE2EEDU handles the encryption EDUs; false if edu isn't one.
func (s *Server) handleE2EEDU(origin, typ string, raw json.RawMessage) bool {
	switch typ {
	case "m.direct_to_device":
		var c struct {
			Sender    string                                `json:"sender"`
			Type      string                                `json:"type"`
			MessageID string                                `json:"message_id"`
			Messages  map[string]map[string]json.RawMessage `json:"messages"`
		}
		if json.Unmarshal(raw, &c) != nil || domainOf(c.Sender) != origin || c.Type == "" || len(c.Type) > 255 {
			return true
		}
		if c.MessageID != "" && !s.toDeviceSeen.firstTime(origin+"\x00"+c.MessageID) {
			return true
		}
		err := s.write(func(tx *sql.Tx) error {
			n := 0
			for uid, devs := range c.Messages {
				if !s.isLocal(uid) || !sharesRoomWithServer(tx, uid, origin) {
					continue
				}
				for dev, content := range devs {
					if len(content) == 0 || content[0] != '{' || len(content) > 65536 {
						continue
					}
					var targets []string
					if dev == "*" {
						rows, err := tx.Query("SELECT device_id FROM devices WHERE user_id = ?", uid)
						if err != nil {
							return err
						}
						for rows.Next() {
							var d string
							rows.Scan(&d)
							targets = append(targets, d)
						}
						rows.Close()
					} else {
						var x int
						if tx.QueryRow("SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?", uid, dev).Scan(&x) == nil {
							targets = []string{dev}
						}
					}
					for _, d := range targets {
						if n++; n > maxToDeviceTargets {
							return nil
						}
						if _, err := tx.Exec("INSERT INTO to_device (stream, user_id, device_id, sender, type, content) VALUES (?,?,?,?,?,?)",
							s.nextFor(change{user: uid}), uid, d, c.Sender, c.Type, string(content)); err != nil {
							return err
						}
					}
				}
			}
			return nil
		})
		if err != nil {
			log.Printf("federation: to-device from %s: %v", origin, err)
		}
	case "m.device_list_update", "m.signing_key_update":
		var c struct {
			UserID string `json:"user_id"`
		}
		if json.Unmarshal(raw, &c) != nil || domainOf(c.UserID) != origin || !isUserID(c.UserID) {
			return true
		}
		s.remoteKeys.invalidate(c.UserID)
		// only users we share a room with matter to our clients
		var x int
		if s.db.QueryRow("SELECT 1 FROM memberships WHERE user_id = ? AND membership IN ('join', 'invite') LIMIT 1", c.UserID).Scan(&x) != nil {
			return true
		}
		s.write(func(tx *sql.Tx) error {
			_, err := tx.Exec("INSERT INTO device_list_changes (stream, user_id) VALUES (?, ?)", s.nextFor(change{dev: c.UserID}), c.UserID)
			return err
		})
	default:
		return false
	}
	return true
}

// ---- other servers' keys, for our clients ----

// remoteKeyCache: keys/query answers, until a device update or 10 minutes.
type remoteKeyCache struct {
	mu      sync.Mutex
	entries map[string]remoteKeyEntry
}

type remoteKeyEntry struct {
	devices, master, selfSigning json.RawMessage
	at                           time.Time
}

func (c *remoteKeyCache) get(uid string) (remoteKeyEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[uid]
	return e, ok && time.Since(e.at) < 10*time.Minute
}

func (c *remoteKeyCache) put(uid string, e remoteKeyEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) > 5000 {
		c.entries = map[string]remoteKeyEntry{}
	}
	e.at = time.Now()
	c.entries[uid] = e
}

func (c *remoteKeyCache) invalidate(uid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, uid)
}

// queryRemoteKeys asks other servers for keys, one request per server.
func (s *Server) queryRemoteKeys(ctx context.Context, viewer string, want map[string][]string,
	devKeys, master, selfSigning, failures map[string]any) {
	byServer := map[string]map[string][]string{}
	for uid, devs := range want {
		d := domainOf(uid)
		if !isUserID(uid) || !validHostPort(d) {
			continue
		}
		if e, ok := s.remoteKeys.get(uid); ok && len(devs) == 0 {
			s.mergeRemoteKeys(viewer, uid, e, devKeys, master, selfSigning)
			continue
		}
		if byServer[d] == nil {
			byServer[d] = map[string][]string{}
		}
		byServer[d][uid] = devs
	}
	if len(byServer) > 50 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, keysQueryTimeout)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for server, users := range byServer {
		wg.Add(1)
		go func(server string, users map[string][]string) {
			defer wg.Done()
			var resp struct {
				DeviceKeys  map[string]json.RawMessage `json:"device_keys"`
				Master      map[string]json.RawMessage `json:"master_keys"`
				SelfSigning map[string]json.RawMessage `json:"self_signing_keys"`
			}
			err := s.fedRequest(ctx, "POST", server, "/_matrix/federation/v1/user/keys/query",
				map[string]any{"device_keys": users}, &resp)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures[server] = map[string]any{"status": 503, "message": "couldn't reach the server"}
				return
			}
			for uid, devs := range users {
				if domainOf(uid) != server {
					continue
				}
				e := remoteKeyEntry{devices: resp.DeviceKeys[uid], master: resp.Master[uid], selfSigning: resp.SelfSigning[uid]}
				if e.devices == nil {
					e.devices = json.RawMessage("{}")
				}
				if len(devs) == 0 {
					s.remoteKeys.put(uid, e)
				}
				s.mergeRemoteKeys(viewer, uid, e, devKeys, master, selfSigning)
			}
		}(server, users)
	}
	wg.Wait()
}

// mergeRemoteKeys keeps only keys that belong to uid and adds the viewer's
// own signature on their master key.
func (s *Server) mergeRemoteKeys(viewer, uid string, e remoteKeyEntry, devKeys, master, selfSigning map[string]any) {
	var devs map[string]map[string]any
	json.Unmarshal(e.devices, &devs)
	clean := map[string]any{}
	for id, k := range devs {
		if k["user_id"] == uid && k["device_id"] == id {
			delete(k, "unsigned")
			clean[id] = k
		}
	}
	devKeys[uid] = clean
	if mk := keyOwnedBy(e.master, uid); mk != nil {
		master[uid] = s.withViewerSignatures(viewer, uid, mk)
	}
	if sk := keyOwnedBy(e.selfSigning, uid); sk != nil {
		selfSigning[uid] = sk
	}
}

func keyOwnedBy(raw json.RawMessage, uid string) map[string]any {
	var k map[string]any
	if json.Unmarshal(raw, &k) != nil || k == nil || k["user_id"] != uid {
		return nil
	}
	return k
}

// withViewerSignatures adds the viewer's stored signatures on a remote master key.
func (s *Server) withViewerSignatures(viewer, uid string, key map[string]any) map[string]any {
	keys, _ := key["keys"].(map[string]any)
	for kid := range keys {
		var sigs string
		if s.db.QueryRow("SELECT sigs FROM remote_signatures WHERE user_id = ? AND key_id = ? AND signer = ?",
			uid, kid, viewer).Scan(&sigs) != nil {
			continue
		}
		var mine map[string]any
		if json.Unmarshal([]byte(sigs), &mine) != nil {
			continue
		}
		all, _ := key["signatures"].(map[string]any)
		if all == nil {
			all = map[string]any{}
		}
		all[viewer] = mine
		key["signatures"] = all
	}
	return key
}

// claimRemoteKeys claims one-time keys of users of other servers.
func (s *Server) claimRemoteKeys(ctx context.Context, want map[string]map[string]string, out, failures map[string]any) {
	byServer := map[string]map[string]map[string]string{}
	for uid, devs := range want {
		d := domainOf(uid)
		if !isUserID(uid) || !validHostPort(d) {
			continue
		}
		if byServer[d] == nil {
			byServer[d] = map[string]map[string]string{}
		}
		byServer[d][uid] = devs
	}
	if len(byServer) > 50 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, keysQueryTimeout)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for server, users := range byServer {
		wg.Add(1)
		go func(server string, users map[string]map[string]string) {
			defer wg.Done()
			var resp struct {
				OneTimeKeys map[string]map[string]json.RawMessage `json:"one_time_keys"`
			}
			err := s.fedRequest(ctx, "POST", server, "/_matrix/federation/v1/user/keys/claim",
				map[string]any{"one_time_keys": users}, &resp)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures[server] = map[string]any{"status": 503, "message": "couldn't reach the server"}
				return
			}
			for uid, devs := range resp.OneTimeKeys {
				if domainOf(uid) != server || users[uid] == nil {
					continue
				}
				out[uid] = devs
			}
		}(server, users)
	}
	wg.Wait()
}

// queueToDevice queues one EDU per remote server.
func (s *Server) queueToDevice(tx *sql.Tx, sender, typ string, msgs map[string]map[string]json.RawMessage) error {
	if !s.cfg.Federation {
		return nil
	}
	byServer := map[string]map[string]map[string]json.RawMessage{}
	for uid, devs := range msgs {
		d := domainOf(uid)
		if s.isLocal(uid) || !isUserID(uid) || !validHostPort(d) {
			continue
		}
		if byServer[d] == nil {
			byServer[d] = map[string]map[string]json.RawMessage{}
		}
		byServer[d][uid] = devs
	}
	for d, users := range byServer {
		edu := map[string]any{"edu_type": "m.direct_to_device", "content": map[string]any{
			"sender": sender, "type": typ, "message_id": strconv.FormatInt(time.Now().UnixNano(), 36) + randString(6),
			"messages": users}}
		if err := s.queueStoredEDU(tx, d, edu); err != nil {
			return err
		}
	}
	return nil
}
