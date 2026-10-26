package server

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// synapseVectors were produced by Synapse's own libraries (canonicaljson 2.0,
// signedjson) so renka's output must match byte for byte. The signing seed
// and the first two signatures are also the examples in the Matrix spec.
const synapseVectors = `{
 "canonical": [
  [
   "{}",
   "{}"
  ],
  [
   "{\"one\": 1, \"two\": \"Two\"}",
   "{\"one\":1,\"two\":\"Two\"}"
  ],
  [
   "{\"b\": \"2\", \"a\": \"1\"}",
   "{\"a\":\"1\",\"b\":\"2\"}"
  ],
  [
   "{\"auth\": {\"success\": true, \"mxid\": \"@john.doe:example.com\", \"profile\": {\"display_name\": \"John Doe\", \"three_pids\": [{\"medium\": \"email\",\"address\": \"john.doe@example.org\"},{\"medium\": \"msisdn\",\"address\": \"123456789\"}]}}}",
   "{\"auth\":{\"mxid\":\"@john.doe:example.com\",\"profile\":{\"display_name\":\"John Doe\",\"three_pids\":[{\"address\":\"john.doe@example.org\",\"medium\":\"email\"},{\"address\":\"123456789\",\"medium\":\"msisdn\"}]},\"success\":true}}"
  ],
  [
   "{\"a\": \"日本語\"}",
   "{\"a\":\"日本語\"}"
  ],
  [
   "{\"本\": 2, \"日\": 1}",
   "{\"日\":1,\"本\":2}"
  ],
  [
   "{\"a\": \"\\u65E5\"}",
   "{\"a\":\"日\"}"
  ],
  [
   "{\"a\": null}",
   "{\"a\":null}"
  ],
  [
   "{\"a\": true, \"b\": false}",
   "{\"a\":true,\"b\":false}"
  ],
  [
   "{\"a\": \"\\u0000\\u0001\\b\\f\\n\\r\\t\\u001f\\u0020\"}",
   "{\"a\":\"\\u0000\\u0001\\b\\f\\n\\r\\t\\u001f \"}"
  ],
  [
   "{\"a\": \"\\u007f\\u0080\\u2028\\u2029\"}",
   "{\"a\":\"  \"}"
  ],
  [
   "{\"a\": \"</script>&'\"}",
   "{\"a\":\"</script>&'\"}"
  ],
  [
   "{\"a\": \"\\\\\\\"/\"}",
   "{\"a\":\"\\\\\\\"/\"}"
  ],
  [
   "{\"😀\": \"𝄞\", \"ｚ\": \"x\", \"a\": \"y\"}",
   "{\"a\":\"y\",\"ｚ\":\"x\",\"😀\":\"𝄞\"}"
  ],
  [
   "{\"max\": 9007199254740991, \"min\": -9007199254740991, \"zero\": -0}",
   "{\"max\":9007199254740991,\"min\":-9007199254740991,\"zero\":0}"
  ],
  [
   "[1, [2, [3, {\"b\": 1, \"a\": 2}]]]",
   "[1,[2,[3,{\"a\":2,\"b\":1}]]]"
  ]
 ],
 "signatures": [
  [
   "{}",
   "K8280/U9SSy9IVtjBuVeLr+HpOB4BQFWbg+UZaADMtTdGYI7Geitb76LTrr5QV/7Xg4ahLwYGYZzuHGZKM5ZAQ"
  ],
  [
   "{\"one\": 1, \"two\": \"Two\"}",
   "KqmLSbO39/Bzb0QIYE82zqLwsA+PDzYIpIRA2sRQ4sL53+sN6/fpNSoqE7BP7vBZhG6kYdD13EIMJpvhJI+6Bw"
  ],
  [
   "{\"type\": \"m.room.message\", \"content\": {\"body\": \"hé <b>\"}, \"unsigned\": {\"age\": 5}, \"signatures\": {\"other.org\": {\"ed25519:x\": \"abc\"}}}",
   "6JuuGz7LiMmyB6UJIIm1NxXkvNABw0Ga2JsvaIW39NsfxtNy8DVfQ+oted3oLF2lxOFTAyOJLMV4+ixa4KeSDQ"
  ]
 ],
 "pub": "XGX0JRS2Af3be3knz2fBiRbApjm2Dh61gXDJA8kcJNI"
}
`

func TestCanonicalJSONMatchesSynapse(t *testing.T) {
	var v struct {
		Canonical  [][2]string `json:"canonical"`
		Signatures [][2]string `json:"signatures"`
		Pub        string      `json:"pub"`
	}
	if err := json.Unmarshal([]byte(synapseVectors), &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Canonical {
		got, err := canonicalizeRaw([]byte(c[0]))
		if err != nil || string(got) != c[1] {
			t.Errorf("canonical(%s)\n got  %q (%v)\n want %q", c[0], got, err, c[1])
		}
	}
	seed, _ := decodeB64("YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1")
	key := signingKey{id: "ed25519:1", priv: ed25519.NewKeyFromSeed(seed)}
	if b64.EncodeToString(key.public()) != v.Pub {
		t.Fatal("public key differs from Synapse's")
	}
	for _, c := range v.Signatures {
		obj, _ := decodeJSONNumbers([]byte(c[0]))
		m := obj.(map[string]any)
		if err := signJSON(m, "domain", key); err != nil {
			t.Fatal(err)
		}
		got := m["signatures"].(map[string]any)["domain"].(map[string]any)["ed25519:1"]
		if got != c[1] {
			t.Errorf("signature of %s\n got  %v\n want %s", c[0], got, c[1])
		}
		if err := verifyJSON(m, "domain", "ed25519:1", key.public()); err != nil {
			t.Errorf("own signature doesn't verify: %v", err)
		}
		if other, ok := m["signatures"].(map[string]any)["other.org"]; strings.Contains(c[0], "other.org") && !ok {
			t.Error("existing signatures were dropped")
		} else {
			_ = other
		}
		m["content"] = map[string]any{"tampered": true}
		if verifyJSON(m, "domain", "ed25519:1", key.public()) == nil {
			t.Error("tampered object still verifies")
		}
	}
}

func TestCanonicalJSONRejects(t *testing.T) {
	for _, bad := range []string{`1.5`, `{"a":1e400}`, `{"a":9007199254740992}`, `{"a":-9007199254740992}`, `{"a":0.1}`, `{} {}`,
		strings.Repeat("[", 200) + strings.Repeat("]", 200)} {
		if _, err := canonicalizeRaw([]byte(bad)); err == nil {
			t.Errorf("%.40s accepted", bad)
		}
	}
	// integral numbers in other notations are normalised
	if got, _ := canonicalizeRaw([]byte(`{"a":1e3,"b":-0,"c":5.0}`)); string(got) != `{"a":1000,"b":0,"c":5}` {
		t.Errorf("got %s", got)
	}
}

func TestParseXMatrix(t *testing.T) {
	cases := []struct {
		h  string
		ok bool
		x  xMatrix
	}{
		{`X-Matrix origin="a.org",destination="b.org",key="ed25519:1",sig="SIG"`, true, xMatrix{"a.org", "b.org", "ed25519:1", "SIG"}},
		{`X-Matrix origin=a.org,key=ed25519:1,sig=SIG`, true, xMatrix{"a.org", "", "ed25519:1", "SIG"}},
		{`X-Matrix ORIGIN="a.org", Key="ed25519:1", SIG="S\"G"`, true, xMatrix{"a.org", "", "ed25519:1", `S"G`}},
		{`X-Matrix origin="a.org",origin="evil.org",key="k",sig="s"`, true, xMatrix{"a.org", "", "k", "s"}},
		{`X-Matrix origin="a.org",key="k"`, false, xMatrix{}},
		{`X-Matrix origin="a.org,key="k",sig="s`, false, xMatrix{}},
		{`Bearer abc`, false, xMatrix{}},
		{`X-Matrix `, false, xMatrix{}},
	}
	for _, c := range cases {
		x, ok := parseXMatrix(c.h)
		if ok != c.ok || (ok && x != c.x) {
			t.Errorf("parseXMatrix(%q) = %+v %v, want %+v %v", c.h, x, ok, c.x, c.ok)
		}
	}
}

func TestServerDiscovery(t *testing.T) {
	s := newTestServer(t)
	wellKnown := map[string]string{}
	srv := map[string]*net.SRV{}
	s.fedWellKnown = func(_ context.Context, host string) (string, error) {
		if v, ok := wellKnown[host]; ok {
			return v, nil
		}
		return "", errors.New("none")
	}
	s.fedLookupSRV = func(_ context.Context, service, _, name string) (string, []*net.SRV, error) {
		if r, ok := srv[service+"/"+name]; ok {
			return "", []*net.SRV{r}, nil
		}
		return "", nil, errors.New("nxdomain")
	}
	s.fedRoutes = map[string]fedRoute{}
	wellKnown["delegated.org"] = "matrix.delegated.org:443"
	wellKnown["srvdeleg.org"] = "m.srvdeleg.org"
	srv["matrix-fed/m.srvdeleg.org"] = &net.SRV{Target: "fed1.srvdeleg.org.", Port: 8449}
	wellKnown["plaindeleg.org"] = "m.plaindeleg.org"
	wellKnown["ipdeleg.org"] = "203.0.113.7"
	wellKnown["junk.org"] = "not a host!"
	srv["matrix-fed/srvonly.org"] = &net.SRV{Target: "fed.srvonly.org.", Port: 443}
	srv["matrix/oldsrv.org"] = &net.SRV{Target: "old.oldsrv.org.", Port: 8450}
	cases := []struct{ name, addr, tlsHost, host string }{
		{"1.2.3.4", "1.2.3.4:8448", "1.2.3.4", "1.2.3.4"},
		{"1.2.3.4:9000", "1.2.3.4:9000", "1.2.3.4", "1.2.3.4:9000"},
		{"[2001:db8::1]:8443", "[2001:db8::1]:8443", "2001:db8::1", "[2001:db8::1]:8443"},
		{"example.com:1234", "example.com:1234", "example.com", "example.com:1234"},
		{"delegated.org", "matrix.delegated.org:443", "matrix.delegated.org", "matrix.delegated.org:443"},
		{"srvdeleg.org", "fed1.srvdeleg.org:8449", "m.srvdeleg.org", "m.srvdeleg.org"},
		{"plaindeleg.org", "m.plaindeleg.org:8448", "m.plaindeleg.org", "m.plaindeleg.org"},
		{"ipdeleg.org", "203.0.113.7:8448", "203.0.113.7", "203.0.113.7"},
		{"junk.org", "junk.org:8448", "junk.org", "junk.org"},
		{"srvonly.org", "fed.srvonly.org:443", "srvonly.org", "srvonly.org"},
		{"oldsrv.org", "old.oldsrv.org:8450", "oldsrv.org", "oldsrv.org"},
		{"nothing.org", "nothing.org:8448", "nothing.org", "nothing.org"},
	}
	for _, c := range cases {
		r, err := s.resolveServer(context.Background(), c.name)
		if err != nil || r.addr != c.addr || r.tlsHost != c.tlsHost || r.host != c.host {
			t.Errorf("%s -> %+v %v, want addr=%s tls=%s host=%s", c.name, r, err, c.addr, c.tlsHost, c.host)
		}
	}
	for _, bad := range []string{"", "bad name", "a/b", "::1"} {
		if _, err := s.resolveServer(context.Background(), bad); err == nil {
			t.Errorf("resolved invalid name %q", bad)
		}
	}
}

// fedPair starts two federating servers on 127.0.0.1 with TLS, named by
// their addresses (an IP literal name needs no DNS or well-known).
func fedPair(t *testing.T) (a, b *Server, ha, hb http.Handler) {
	ss, hs := fedServers(t, 2)
	return ss[0], ss[1], hs[0], hs[1]
}

// fedServers starts n federating servers on localhost TLS ports.
func fedServers(t *testing.T, n int) ([]*Server, []http.Handler) {
	t.Helper()
	pool := x509.NewCertPool()
	var servers []*Server
	var handlers []http.Handler
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		cfg := &Config{ServerName: ln.Addr().String(), PublicBaseURL: "https://" + ln.Addr().String(),
			Database: filepath.Join(dir, "t.db"), MediaDir: filepath.Join(dir, "m"), MaxUploadBytes: 1 << 20,
			Registration: true, Federation: true, FederationAllowPrivate: true}
		s, err := newServer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.db.Close() })
		h := s.routes()
		hs := httptest.NewUnstartedServer(h)
		hs.Listener.Close()
		hs.Listener = ln
		hs.StartTLS()
		t.Cleanup(hs.Close)
		pool.AddCert(hs.Certificate())
		servers = append(servers, s)
		handlers = append(handlers, h)
	}
	for _, s := range servers { // trust the test certificates
		tr := newFedTransport(true, &tls.Config{RootCAs: pool})
		s.fedClient = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return servers, handlers
}

func TestFederationQueries(t *testing.T) {
	a, b, ha, hb := fedPair(t)
	_, at := addUser(t, a, "alice")
	bob, bt := addUser(t, b, "bob")
	do(t, hb, "PUT", "/_matrix/client/v3/profile/"+bob+"/displayname", bt, map[string]any{"displayname": "Bob from B"})
	_, r := do(t, hb, "POST", "/_matrix/client/v3/createRoom", bt, map[string]any{"room_alias_name": "lobby"})

	// alice (on A) looks up bob's profile on B: A signs, B checks A's keys
	st, p := do(t, ha, "GET", "/_matrix/client/v3/profile/"+bob, at, nil)
	if st != 200 || p["displayname"] != "Bob from B" {
		t.Fatalf("remote profile: %d %v", st, p)
	}
	st, p = do(t, ha, "GET", "/_matrix/client/v3/profile/"+bob+"/displayname", at, nil)
	if st != 200 || p["displayname"] != "Bob from B" {
		t.Fatalf("remote profile field: %d %v", st, p)
	}
	alias := "#lobby:" + b.cfg.ServerName
	st, d := do(t, ha, "GET", "/_matrix/client/v3/directory/room/"+strings.ReplaceAll(alias, "#", "%23"), at, nil)
	if st != 200 || d["room_id"] != r["room_id"] {
		t.Fatalf("remote alias: %d %v", st, d)
	}
	// anonymous requests never trigger outbound calls
	if st, _ := do(t, ha, "GET", "/_matrix/client/v3/profile/"+bob, "", nil); st != 404 {
		t.Fatalf("anonymous remote lookup allowed (%d)", st)
	}
	// B's key endpoint is self-signed and verifies
	_, keys := do(t, hb, "GET", "/_matrix/key/v2/server", "", nil)
	var vk map[string]any
	for id, v := range keys["verify_keys"].(map[string]any) {
		pub, _ := decodeB64(v.(map[string]any)["key"].(string))
		raw, _ := json.Marshal(keys)
		obj, _ := decodeJSONNumbers(raw)
		if err := verifyJSON(obj.(map[string]any), b.cfg.ServerName, id, pub); err != nil {
			t.Fatalf("server keys not self-signed: %v", err)
		}
		vk = v.(map[string]any)
	}
	if vk == nil || keys["valid_until_ts"].(float64) < float64(time.Now().UnixMilli()) {
		t.Fatalf("bad key response %v", keys)
	}
}

func TestFederationRejectsBadRequests(t *testing.T) {
	a, b, _, hb := fedPair(t)
	bob, _ := addUser(t, b, "bob")
	path := "/_matrix/federation/v1/query/profile?user_id=" + strings.ReplaceAll(bob, ":", "%3A")
	call := func(auth string) int {
		req := httptest.NewRequest("GET", path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		hb.ServeHTTP(w, req)
		return w.Code
	}
	good, _ := a.requestAuth("GET", path, b.cfg.ServerName, nil)
	if c := call(good); c != 200 {
		t.Fatalf("valid signed request refused: %d", c)
	}
	wrongDest, _ := a.requestAuth("GET", path, "other.org", nil)
	wrongURI, _ := a.requestAuth("GET", path+"&x=1", b.cfg.ServerName, nil)
	wrongMethod, _ := a.requestAuth("POST", path, b.cfg.ServerName, nil)
	forged := strings.Replace(good, `origin="`+a.cfg.ServerName, `origin="`+b.cfg.ServerName, 1)
	badSig := good[:len(good)-6] + `AAAA"`
	unknownKey := strings.Replace(good, a.fedKey.id, "ed25519:nope", 1)
	for name, h := range map[string]string{"none": "", "wrong destination": wrongDest, "wrong uri": wrongURI,
		"wrong method": wrongMethod, "origin = target": forged, "bad signature": badSig, "unknown key": unknownKey,
		"bearer": "Bearer x", "garbage": "X-Matrix ,,,=="} {
		if c := call(h); c != 401 {
			t.Errorf("%s: accepted (%d)", name, c)
		}
	}
}

func TestFederationKeyChecks(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Federation = true
	if err := s.startFederation(); err != nil {
		t.Fatal(err)
	}
	other, _ := loadSigningKey(newTestServer(t).db)
	evil, _ := loadSigningKey(newTestServer(t).db)
	resp := func(name string, until time.Time, signWith signingKey, listKey signingKey) map[string]any {
		obj := map[string]any{"server_name": name, "valid_until_ts": until.UnixMilli(), "old_verify_keys": map[string]any{},
			"verify_keys": map[string]any{listKey.id: map[string]any{"key": b64.EncodeToString(listKey.public())}}}
		signJSON(obj, name, signWith)
		raw, _ := json.Marshal(obj)
		v, _ := decodeJSONNumbers(raw)
		return v.(map[string]any)
	}
	soon := time.Now().Add(time.Hour)
	cases := []struct {
		name string
		resp map[string]any
		ok   bool
	}{
		{"good", resp("o.org", soon, other, other), true},
		{"expired", resp("o.org", time.Now().Add(-time.Minute), other, other), false},
		{"other server's name", resp("x.org", soon, other, other), false},
		{"not self-signed", resp("o.org", soon, evil, other), false},
	}
	for _, c := range cases {
		s.fedKeys = map[string]*keySet{}
		r := c.resp
		s.fedGetKeys = func(context.Context, string, *map[string]any) error { return nil }
		s.fedGetKeys = func(_ context.Context, _ string, out *map[string]any) error { *out = r; return nil }
		_, err := s.serverKey(context.Background(), "o.org", other.id)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v", c.name, err)
		}
	}
}

func TestRetiredKeys(t *testing.T) {
	s := newTestServer(t)
	s.cfg.Federation = true
	s.cfg.TrustedKeyServers = nil
	if err := s.startFederation(); err != nil {
		t.Fatal(err)
	}
	cur, _ := loadSigningKey(newTestServer(t).db)
	old, _ := loadSigningKey(newTestServer(t).db)
	old.id = "ed25519:old"
	retired := time.Now().Add(-24 * time.Hour).UnixMilli()
	obj := map[string]any{"server_name": "o.org", "valid_until_ts": time.Now().Add(time.Hour).UnixMilli(),
		"verify_keys":     map[string]any{cur.id: map[string]any{"key": b64.EncodeToString(cur.public())}},
		"old_verify_keys": map[string]any{old.id: map[string]any{"key": b64.EncodeToString(old.public()), "expired_ts": retired}}}
	signJSON(obj, "o.org", cur)
	raw, _ := json.Marshal(obj)
	v, _ := decodeJSONNumbers(raw)
	fetches := 0
	s.fedGetKeys = func(_ context.Context, _ string, out *map[string]any) error {
		fetches++
		*out = v.(map[string]any)
		return nil
	}
	ctx := context.Background()
	if _, err := s.eventKey(ctx, "o.org", old.id, retired-1000); err != nil {
		t.Errorf("retired key refused for an event signed before it retired: %v", err)
	}
	if _, err := s.eventKey(ctx, "o.org", old.id, retired+1000); err == nil {
		t.Error("retired key accepted for an event signed after it retired")
	}
	if _, err := s.serverKey(ctx, "o.org", old.id); err == nil {
		t.Error("retired key accepted for a request")
	}
	if _, err := s.serverKey(ctx, "o.org", cur.id); err != nil {
		t.Errorf("current key: %v", err)
	}
	// an unknown key doesn't trigger a fetch per lookup
	for i := 0; i < 5; i++ {
		s.eventKey(ctx, "o.org", "ed25519:nope", 1)
	}
	if fetches != 1 {
		t.Errorf("%d key fetches, want 1", fetches)
	}
}

func TestFederationOffByDefault(t *testing.T) {
	s := newTestServer(t)
	h := s.routes()
	for _, p := range []string{"/_matrix/key/v2/server", "/_matrix/federation/v1/version", "/.well-known/matrix/server"} {
		if st, _ := do(t, h, "GET", p, "", nil); st != 404 {
			t.Errorf("%s served with federation off (%d)", p, st)
		}
	}
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM kv WHERE k = 'signing_key'").Scan(&n)
	if n != 0 {
		t.Error("signing key created while federation is off")
	}
}

func FuzzCanonicalJSON(f *testing.F) {
	for _, s := range []string{`{"b":1,"a":[1,2,{"c":" "}]}`, `"\u0000"`, `1e3`, `{"😀":1,"ｚ":2}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, err := canonicalizeRaw([]byte(s))
		if err != nil {
			return
		}
		if !json.Valid(out) {
			t.Fatalf("invalid JSON from %q: %q", s, out)
		}
		again, err := canonicalizeRaw(out)
		if err != nil || string(again) != string(out) {
			t.Fatalf("not idempotent: %q -> %q -> %q (%v)", s, out, again, err)
		}
	})
}

func FuzzParseXMatrix(f *testing.F) {
	f.Add(`X-Matrix origin="a",key="b",sig="c"`)
	f.Fuzz(func(t *testing.T, h string) { parseXMatrix(h) })
}
