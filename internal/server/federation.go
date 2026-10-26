package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// Federation basics: signing key, canonical JSON, signatures, server
// discovery, X-Matrix auth, profile/alias queries. Off unless federation = true.

// ---- canonical JSON ----

// canonicalJSON: sorted keys, no spaces, integers only. Not encoding/json,
// which escapes <, >, & and U+2028/9 and would change the signed bytes.
func canonicalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := encodeCanonical(&b, v, 0); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// canonicalizeRaw re-encodes JSON text canonically.
func canonicalizeRaw(raw []byte) ([]byte, error) {
	v, err := decodeJSONNumbers(raw)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(v)
}

func decodeJSONNumbers(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

const maxCanonicalDepth = 100

func encodeCanonical(b *bytes.Buffer, v any, depth int) error {
	if depth > maxCanonicalDepth {
		return errors.New("JSON nested too deeply")
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeCanonicalString(b, x)
	case json.Number:
		n, err := canonicalNumber(string(x))
		if err != nil {
			return err
		}
		b.WriteString(n)
	case float64:
		if x != math.Trunc(x) || math.Abs(x) > maxSafeInt {
			return fmt.Errorf("number %v is not an integer in range", x)
		}
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int:
		return encodeCanonical(b, int64(x), depth)
	case int64:
		if x > maxSafeInt || x < -maxSafeInt {
			return fmt.Errorf("integer %d out of range", x)
		}
		b.WriteString(strconv.FormatInt(x, 10))
	case json.RawMessage:
		inner, err := decodeJSONNumbers(x)
		if err != nil {
			return err
		}
		return encodeCanonical(b, inner, depth)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // byte order of UTF-8 == codepoint order
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonicalString(b, k)
			b.WriteByte(':')
			if err := encodeCanonical(b, x[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, el := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encodeCanonical(b, el, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case []string:
		arr := make([]any, len(x))
		for i, s := range x {
			arr[i] = s
		}
		return encodeCanonical(b, arr, depth)
	case map[string]string:
		m := make(map[string]any, len(x))
		for k, s := range x {
			m[k] = s
		}
		return encodeCanonical(b, m, depth)
	default:
		// anything else (structs, typed maps): go through encoding/json first
		raw, err := json.Marshal(x)
		if err != nil {
			return err
		}
		inner, err := decodeJSONNumbers(raw)
		if err != nil {
			return err
		}
		return encodeCanonical(b, inner, depth)
	}
	return nil
}

// canonicalNumber writes integral numbers ("1e3", "-0") as plain integers.
func canonicalNumber(s string) (string, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n > maxSafeInt || n < -maxSafeInt {
			return "", fmt.Errorf("integer %s out of range", s)
		}
		return strconv.FormatInt(n, 10), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f != math.Trunc(f) || math.Abs(f) > maxSafeInt {
		return "", fmt.Errorf("number %s is not an integer in range", s)
	}
	return strconv.FormatInt(int64(f), 10), nil
}

// writeCanonicalString escapes only what JSON requires.
func writeCanonicalString(b *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte(hex[r>>4])
			b.WriteByte(hex[r&0xf])
		case r == utf8.RuneError && size == 1:
			b.WriteString("�") // invalid UTF-8 can't be signed as-is
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	b.WriteByte('"')
}

// ---- JSON signatures ----

type signingKey struct {
	id   string // "ed25519:abc123"
	priv ed25519.PrivateKey
}

func (k signingKey) public() ed25519.PublicKey { return k.priv.Public().(ed25519.PublicKey) }

var b64 = base64.RawStdEncoding

// decodeB64 accepts unpadded or padded, standard or URL-safe base64.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// signedBytes is what gets signed: the object without signatures and unsigned.
func signedBytes(obj map[string]any) ([]byte, error) {
	stripped := make(map[string]any, len(obj))
	for k, v := range obj {
		if k != "signatures" && k != "unsigned" {
			stripped[k] = v
		}
	}
	return canonicalJSON(stripped)
}

// signJSON adds signer's signature to obj["signatures"][server][key id].
func signJSON(obj map[string]any, server string, key signingKey) error {
	msg, err := signedBytes(obj)
	if err != nil {
		return err
	}
	sigs, _ := obj["signatures"].(map[string]any)
	if sigs == nil {
		sigs = map[string]any{}
	}
	mine, _ := sigs[server].(map[string]any)
	if mine == nil {
		mine = map[string]any{}
	}
	mine[key.id] = b64.EncodeToString(ed25519.Sign(key.priv, msg))
	sigs[server] = mine
	obj["signatures"] = sigs
	return nil
}

// verifyJSON checks obj["signatures"][server][keyID] against pub.
func verifyJSON(obj map[string]any, server, keyID string, pub ed25519.PublicKey) error {
	sigs, _ := obj["signatures"].(map[string]any)
	theirs, _ := sigs[server].(map[string]any)
	sigStr, _ := theirs[keyID].(string)
	if sigStr == "" {
		return fmt.Errorf("no signature from %s with %s", server, keyID)
	}
	sig, err := decodeB64(sigStr)
	if err != nil || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return errors.New("malformed signature")
	}
	msg, err := signedBytes(obj)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// loadSigningKey returns this server's federation key, creating it on first use.
func loadSigningKey(q querier) (signingKey, error) {
	var stored string
	if q.QueryRow("SELECT v FROM kv WHERE k = 'signing_key'").Scan(&stored) == nil {
		id, seedB64, ok := strings.Cut(stored, " ")
		seed, err := decodeB64(seedB64)
		if !ok || err != nil || len(seed) != ed25519.SeedSize || !strings.HasPrefix(id, "ed25519:") {
			return signingKey{}, errors.New("stored signing key is corrupt")
		}
		return signingKey{id: id, priv: ed25519.NewKeyFromSeed(seed)}, nil
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return signingKey{}, err
	}
	k := signingKey{id: "ed25519:a_" + randString(4), priv: ed25519.NewKeyFromSeed(seed)}
	if _, err := q.Exec("INSERT INTO kv (k, v) VALUES ('signing_key', ?)", k.id+" "+b64.EncodeToString(seed)); err != nil {
		return signingKey{}, err
	}
	return k, nil
}

// ---- our keys ----

const keyValidity = 24 * time.Hour

func (s *Server) hServerKeys(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	if id := r.PathValue("keyId"); id != "" && id != s.fedKey.id {
		return nil, errNotFound("unknown key")
	}
	obj := map[string]any{
		"server_name":     s.cfg.ServerName,
		"verify_keys":     map[string]any{s.fedKey.id: map[string]any{"key": b64.EncodeToString(s.fedKey.public())}},
		"old_verify_keys": map[string]any{},
		"valid_until_ts":  time.Now().Add(keyValidity).UnixMilli(),
	}
	if err := signJSON(obj, s.cfg.ServerName, s.fedKey); err != nil {
		return nil, err
	}
	return obj, nil
}

func (s *Server) hFedVersion(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	return map[string]any{"server": map[string]any{"name": "renka", "version": version}}, nil
}

func (s *Server) hWellKnownServer(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	return map[string]any{"m.server": s.fedAddress()}, nil
}

// fedAddress: federation_address, else public_base_url's host (port 443).
func (s *Server) fedAddress() string {
	if s.cfg.FederationAddress != "" {
		return s.cfg.FederationAddress
	}
	u, err := url.Parse(s.cfg.PublicBaseURL)
	if err != nil || u.Host == "" {
		return s.cfg.ServerName
	}
	if u.Port() != "" {
		return u.Host
	}
	return u.Hostname() + ":443"
}

// ---- finding other servers ----

type fedRoute struct {
	addr    string // where to connect (ip:port or host:port)
	tlsHost string // name the TLS certificate must be valid for (SNI)
	host    string // Host header
	expires time.Time
}

// resolveServer follows the spec's "Resolving server names" steps.
func (s *Server) resolveServer(ctx context.Context, name string) (fedRoute, error) {
	s.fedMu.Lock()
	if r, ok := s.fedRoutes[name]; ok && time.Now().Before(r.expires) {
		s.fedMu.Unlock()
		return r, nil
	}
	s.fedMu.Unlock()
	if !validHostPort(name) {
		return fedRoute{}, fmt.Errorf("invalid server name %q", name)
	}
	r, err := s.discover(ctx, name)
	if err != nil {
		return fedRoute{}, err
	}
	r.expires = time.Now().Add(24 * time.Hour)
	s.fedMu.Lock()
	if len(s.fedRoutes) > 10000 {
		s.fedRoutes = map[string]fedRoute{}
	}
	s.fedRoutes[name] = r
	s.fedMu.Unlock()
	return r, nil
}

func splitServerName(name string) (host, port string) {
	if h, p, err := net.SplitHostPort(name); err == nil {
		return strings.Trim(h, "[]"), p
	}
	return strings.Trim(name, "[]"), ""
}

func (s *Server) discover(ctx context.Context, name string) (fedRoute, error) {
	host, port := splitServerName(name)
	// 1-2: an IP literal, or an explicit port: connect directly
	if net.ParseIP(host) != nil || port != "" {
		if port == "" {
			port = "8448"
		}
		return fedRoute{addr: net.JoinHostPort(host, port), tlsHost: host, host: name}, nil
	}
	// 3: .well-known delegation
	if delegated, err := s.fedWellKnown(ctx, host); err == nil && validHostPort(delegated) {
		dh, dp := splitServerName(delegated)
		switch {
		case net.ParseIP(dh) != nil || dp != "":
			if dp == "" {
				dp = "8448"
			}
			return fedRoute{addr: net.JoinHostPort(dh, dp), tlsHost: dh, host: delegated}, nil
		default:
			if target, ok := s.srvTarget(ctx, dh); ok {
				return fedRoute{addr: target, tlsHost: dh, host: dh}, nil
			}
			return fedRoute{addr: net.JoinHostPort(dh, "8448"), tlsHost: dh, host: dh}, nil
		}
	}
	// 4-5: SRV, then the default port
	if target, ok := s.srvTarget(ctx, host); ok {
		return fedRoute{addr: target, tlsHost: host, host: host}, nil
	}
	return fedRoute{addr: net.JoinHostPort(host, "8448"), tlsHost: host, host: host}, nil
}

// srvTarget looks up _matrix-fed._tcp (then the deprecated _matrix._tcp).
func (s *Server) srvTarget(ctx context.Context, host string) (string, bool) {
	for _, svc := range []string{"matrix-fed", "matrix"} {
		_, addrs, err := s.fedLookupSRV(ctx, svc, "tcp", host)
		if err == nil && len(addrs) > 0 && addrs[0].Target != "." {
			return net.JoinHostPort(strings.TrimSuffix(addrs[0].Target, "."), strconv.Itoa(int(addrs[0].Port))), true
		}
	}
	return "", false
}

// fetchWellKnown reads https://host/.well-known/matrix/server.
func (s *Server) fetchWellKnown(ctx context.Context, host string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/.well-known/matrix/server", nil)
	resp, err := s.fedWellKnownClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("well-known: HTTP %d", resp.StatusCode)
	}
	var wk struct {
		Server string `json:"m.server"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&wk); err != nil || wk.Server == "" {
		return "", errors.New("well-known: no m.server")
	}
	return wk.Server, nil
}

// ---- outbound requests ----

type ctxKey int

const fedTargetKey ctxKey = 1

// fedTarget is where a request really goes (dial address + cert name). The
// URL host is just a pool key, so servers sharing an IP don't share conns.
type fedTarget struct{ addr, tlsHost string }

func (r fedRoute) urlBase() string {
	h := sha256.Sum256([]byte(r.tlsHost + "\n" + r.addr))
	return "https://" + hex.EncodeToString(h[:12]) + ".fed"
}

func (r fedRoute) context(ctx context.Context) context.Context {
	return context.WithValue(ctx, fedTargetKey, fedTarget{addr: r.addr, tlsHost: r.tlsHost})
}

// newFedTransport dials the discovered address, checks the cert against the
// server name, and refuses private IPs unless allowed.
func newFedTransport(allowPrivate bool, tlsConf *tls.Config) *http.Transport {
	dialer := &net.Dialer{Timeout: 15 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errPushAddress
		}
		ip := net.ParseIP(host)
		if ip == nil || (!allowPrivate && !publicIP(ip)) {
			return fmt.Errorf("federation: %s is not a public address", host)
		}
		return nil
	}}
	base := &tls.Config{MinVersion: tls.VersionTLS12}
	if tlsConf != nil {
		base = tlsConf.Clone()
	}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			name, _, _ := net.SplitHostPort(addr)
			if t, ok := ctx.Value(fedTargetKey).(fedTarget); ok {
				addr, name = t.addr, t.tlsHost
			}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			cfg := base.Clone()
			cfg.ServerName = strings.Trim(name, "[]")
			tc := tls.Client(conn, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tc, nil
		},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
	}
}

// requestAuth builds the X-Matrix Authorization header for a request.
func (s *Server) requestAuth(method, uri, dest string, content any) (string, error) {
	obj := map[string]any{"method": method, "uri": uri, "origin": s.cfg.ServerName, "destination": dest}
	if content != nil {
		obj["content"] = content
	}
	msg, err := canonicalJSON(obj)
	if err != nil {
		return "", err
	}
	sig := b64.EncodeToString(ed25519.Sign(s.fedKey.priv, msg))
	return fmt.Sprintf(`X-Matrix origin="%s",destination="%s",key="%s",sig="%s"`, s.cfg.ServerName, dest, s.fedKey.id, sig), nil
}

// fedRequest sends a signed federation request and decodes the JSON reply.
func (s *Server) fedRequest(ctx context.Context, method, dest, uri string, content, out any) error {
	return s.fedRequestLimit(ctx, method, dest, uri, content, out, 8<<20)
}

// fedRequestLimit is fedRequest accepting a reply of up to limit bytes.
func (s *Server) fedRequestLimit(ctx context.Context, method, dest, uri string, content, out any, limit int64) error {
	timeout := 60 * time.Second
	if limit > 8<<20 {
		timeout = 5 * time.Minute
	}
	resp, cancel, err := s.fedDo(ctx, method, dest, uri, content, timeout)
	if err != nil {
		return err
	}
	defer cancel()
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return errors.New("reply too large")
	}
	if resp.StatusCode != 200 {
		var e struct {
			Code string `json:"errcode"`
			Msg  string `json:"error"`
		}
		json.Unmarshal(raw, &e)
		return &fedError{status: resp.StatusCode, code: e.Code, msg: e.Msg}
	}
	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber() // keep event numbers exact
		return dec.Decode(out)
	}
	return nil
}

// fedDo sends a signed request and returns the raw response; the caller
// closes the body and calls cancel.
func (s *Server) fedDo(ctx context.Context, method, dest, uri string, content any, timeout time.Duration) (*http.Response, context.CancelFunc, error) {
	if dest == s.cfg.ServerName {
		return nil, nil, errors.New("federation request to ourselves")
	}
	route, err := s.resolveServer(ctx, dest)
	if err != nil {
		return nil, nil, err
	}
	auth, err := s.requestAuth(method, uri, dest, content)
	if err != nil {
		return nil, nil, err
	}
	var body io.Reader
	if content != nil {
		raw, err := json.Marshal(content)
		if err != nil {
			return nil, nil, err
		}
		body = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(route.context(ctx), timeout)
	req, err := http.NewRequestWithContext(ctx, method, route.urlBase()+uri, body)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	req.Host = route.host
	req.Header.Set("Authorization", auth)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.fedClient.Do(req)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return resp, cancel, nil
}

type fedError struct {
	status    int
	code, msg string
}

func (e *fedError) Error() string {
	return fmt.Sprintf("remote server: HTTP %d %s %s", e.status, e.code, e.msg)
}

// ---- other servers' keys ----

func (s *Server) fetchServerKeys(ctx context.Context, server string, out any) error {
	route, err := s.resolveServer(ctx, server)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(route.context(ctx), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", route.urlBase()+"/_matrix/key/v2/server", nil)
	req.Host = route.host
	resp, err := s.fedClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	v, err := decodeJSONNumbers(raw)
	if err != nil {
		return err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return errors.New("key response is not an object")
	}
	*(out.(*map[string]any)) = m
	return nil
}

// ---- inbound requests ----

type xMatrix struct{ origin, destination, key, sig string }

// parseXMatrix parses `X-Matrix origin="a",destination="b",key="k",sig="s"`.
func parseXMatrix(h string) (xMatrix, bool) {
	rest, ok := strings.CutPrefix(h, "X-Matrix ")
	if !ok {
		return xMatrix{}, false
	}
	params := map[string]string{}
	for len(rest) > 0 {
		rest = strings.TrimLeft(rest, " ,")
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			break
		}
		name := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = rest[eq+1:]
		var val strings.Builder
		if strings.HasPrefix(rest, `"`) {
			i := 1
			for ; i < len(rest) && rest[i] != '"'; i++ {
				if rest[i] == '\\' && i+1 < len(rest) {
					i++
				}
				val.WriteByte(rest[i])
			}
			if i >= len(rest) {
				return xMatrix{}, false // unterminated
			}
			rest = rest[i+1:]
		} else {
			end := strings.IndexByte(rest, ',')
			if end < 0 {
				end = len(rest)
			}
			val.WriteString(strings.TrimSpace(rest[:end]))
			rest = rest[end:]
		}
		if _, dup := params[name]; !dup {
			params[name] = val.String()
		}
	}
	x := xMatrix{origin: params["origin"], destination: params["destination"], key: params["key"], sig: params["sig"]}
	return x, x.origin != "" && x.key != "" && x.sig != ""
}

// fedAuth checks a request's X-Matrix signature and returns who sent it.
func (s *Server) fedAuth(r *http.Request) (string, []byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxFedBody))
	if err != nil {
		return "", nil, errf(413, "M_TOO_LARGE", "request too large")
	}
	var content any
	if len(bytes.TrimSpace(body)) > 0 {
		if content, err = decodeJSONNumbers(body); err != nil {
			return "", nil, errBadJSON("invalid JSON body")
		}
	}
	for _, h := range r.Header.Values("Authorization") {
		x, ok := parseXMatrix(h)
		if !ok || !validHostPort(x.origin) || x.origin == s.cfg.ServerName || !strings.HasPrefix(x.key, "ed25519:") {
			continue
		}
		if x.destination != "" && x.destination != s.cfg.ServerName {
			continue
		}
		obj := map[string]any{"method": r.Method, "uri": r.RequestURI, "origin": x.origin, "destination": s.cfg.ServerName}
		if content != nil {
			obj["content"] = content
		}
		pub, err := s.serverKey(r.Context(), x.origin, x.key)
		if err != nil {
			log.Printf("federation: request from %s: %v", x.origin, err)
			continue
		}
		sig, err := decodeB64(x.sig)
		msg, cerr := canonicalJSON(obj)
		if err == nil && cerr == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, msg, sig) {
			return x.origin, body, nil
		}
	}
	return "", nil, errf(401, "M_UNAUTHORIZED", "missing or invalid X-Matrix signature")
}

type fedHandler func(w http.ResponseWriter, r *http.Request, origin string, body []byte) (any, error)

func (s *Server) wrapFed(h fedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin, body, err := s.fedAuth(r)
		if err != nil {
			writeErr(w, err)
			return
		}
		resp, err := h(w, r, origin, body)
		if err != nil {
			writeErr(w, err)
			return
		}
		if resp != nil {
			writeJSON(w, 200, resp)
		}
	}
}

// ---- queries ----

func (s *Server) hFedQueryProfile(w http.ResponseWriter, r *http.Request, origin string, _ []byte) (any, error) {
	uid := r.URL.Query().Get("user_id")
	if !s.isLocal(uid) {
		return nil, errNotFound("not a user on this server")
	}
	p, err := s.profile(uid)
	if err != nil {
		return nil, err
	}
	if f := r.URL.Query().Get("field"); f != "" {
		if v, ok := p[f]; ok {
			return map[string]any{f: v}, nil
		}
		return map[string]any{}, nil
	}
	return p, nil
}

func (s *Server) hFedQueryDirectory(w http.ResponseWriter, r *http.Request, origin string, _ []byte) (any, error) {
	alias := r.URL.Query().Get("room_alias")
	var id string
	if !s.isLocal(alias) || s.db.QueryRow("SELECT room_id FROM aliases WHERE alias = ?", alias).Scan(&id) != nil {
		return nil, errNotFound("room alias not found")
	}
	return map[string]any{"room_id": id, "servers": []string{s.cfg.ServerName}}, nil
}

// remoteProfile asks another server for a user's profile (client API).
func (s *Server) remoteProfile(ctx context.Context, uid, field string) (map[string]any, error) {
	_, server, ok := splitID(uid)
	if !ok {
		return nil, errNotFound("profile not found")
	}
	q := url.Values{"user_id": {uid}}
	if field != "" {
		q.Set("field", field)
	}
	var out map[string]any
	if err := s.fedRequest(ctx, "GET", server, "/_matrix/federation/v1/query/profile?"+q.Encode(), nil, &out); err != nil {
		return nil, errNotFound("profile not found")
	}
	clean := map[string]any{} // keep only well-formed fields
	for _, f := range []string{"displayname", "avatar_url"} {
		if v, ok := out[f].(string); ok && len(v) <= 1024 {
			clean[f] = v
		}
	}
	return clean, nil
}

// remoteAlias resolves an alias on another server (client API).
func (s *Server) remoteAlias(ctx context.Context, alias string) (map[string]any, error) {
	_, server, ok := splitID(alias)
	if !ok {
		return nil, errNotFound("room alias not found")
	}
	var out struct {
		RoomID  string   `json:"room_id"`
		Servers []string `json:"servers"`
	}
	if err := s.fedRequest(ctx, "GET", server, "/_matrix/federation/v1/query/directory?"+url.Values{"room_alias": {alias}}.Encode(), nil, &out); err != nil || out.RoomID == "" {
		return nil, errNotFound("room alias not found")
	}
	if len(out.Servers) > 50 {
		out.Servers = out.Servers[:50]
	}
	return map[string]any{"room_id": out.RoomID, "servers": out.Servers}, nil
}

// startFederation loads the signing key and sets up the clients.
func (s *Server) startFederation() error {
	k, err := loadSigningKey(s.db)
	if err != nil {
		return err
	}
	s.fedKey = k
	s.fedTxns = txnSeen{seen: map[string]map[string]any{}}
	if s.fedOut == nil {
		s.startSender()
	}
	s.fedRoutes = map[string]fedRoute{}
	s.fedKeys = map[string]*keySet{}
	if s.fedClient == nil {
		tr := newFedTransport(s.cfg.FederationAllowPrivate, nil)
		s.fedClient = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		s.fedWellKnownClient = &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Scheme != "https" {
				return errors.New("too many or non-https redirects")
			}
			return nil
		}}
	}
	if s.fedLookupSRV == nil {
		s.fedLookupSRV = net.DefaultResolver.LookupSRV
	}
	if s.fedWellKnown == nil {
		s.fedWellKnown = s.fetchWellKnown
	}
	if s.fedGetKeys == nil {
		s.fedGetKeys = func(ctx context.Context, server string, out *map[string]any) error {
			return s.fetchServerKeys(ctx, server, out)
		}
	}
	return nil
}

var _ sync.Locker = (*sync.Mutex)(nil)
