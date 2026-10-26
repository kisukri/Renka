package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- helpers ----

// newTestServer starts a Server on a throwaway database.
func newTestServer(t testing.TB) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{
		ServerName: "test.local", PublicBaseURL: "https://test.local", Listen: "127.0.0.1:0",
		Database: filepath.Join(dir, "t.db"), MediaDir: filepath.Join(dir, "media"),
		Registration: true, MaxUploadBytes: 1 << 20,
	}
	s, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	return s
}

// addUser creates a user and returns an access token for a new device.
func addUser(t testing.TB, s *Server, name string) (uid, token string) {
	t.Helper()
	if err := s.createUser(name, "password123", false); err != nil {
		t.Fatal(err)
	}
	uid = "@" + name + ":" + s.cfg.ServerName
	err := s.write(func(tx *sql.Tx) error {
		var err error
		_, token, err = s.createDevice(tx, uid, "", "", "127.0.0.1")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return uid, token
}

func do(t testing.TB, h http.Handler, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// ---- pure functions ----

func TestToInt(t *testing.T) {
	cases := []struct {
		in   any
		want int64
	}{
		{float64(50), 50}, {float64(-5), -5}, {float64(1.5), 7}, {float64(1e20), 7}, {float64(-1e20), 7},
		{math.Inf(1), 7}, {float64(maxSafeInt), maxSafeInt}, {float64(maxSafeInt + 2), 7},
		{json.Number("100"), 100}, {json.Number("1e2"), 7}, {json.Number("9007199254740993"), 7},
		{json.Number("-9007199254740991"), -maxSafeInt}, {"42", 42}, {" 42 ", 42}, {"4x", 7},
		{"99999999999999999999", 7}, {nil, 7}, {true, 7}, {map[string]any{}, 7}, {int64(3), 3}, {int(9), 9},
	}
	for _, c := range cases {
		if got := toInt(c.in, 7); got != c.want {
			t.Errorf("toInt(%#v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestValidatePowerLevels(t *testing.T) {
	ok := []string{
		`{}`,
		`{"ban":50,"users":{"@a:x":100},"events":{"m.room.name":50},"notifications":{"room":50}}`,
		`{"users_default":-10,"state_default":9007199254740991}`,
	}
	bad := []string{
		`null`, `[]`, `"x"`, `{"ban":"50"}`, `{"ban":50.5}`, `{"ban":1e20}`, `{"kick":true}`,
		`{"users":[]}`, `{"users":{"@a:x":"100"}}`, `{"users":{"not-a-user":1}}`, `{"events":{"x":null}}`,
		`{"state_default":9007199254740992}`, `{"notifications":{"room":1.0e1}}`,
	}
	for _, c := range ok {
		if err := validatePowerLevels(json.RawMessage(c)); err != nil {
			t.Errorf("valid %s rejected: %v", c, err)
		}
	}
	for _, c := range bad {
		if err := validatePowerLevels(json.RawMessage(c)); err == nil {
			t.Errorf("invalid %s accepted", c)
		}
	}
}

func TestCheckPowerLevelChange(t *testing.T) {
	oldPL := `{"users":{"@admin:x":100,"@mod:x":50},"ban":50,"events":{"m.room.power_levels":50}}`
	auth := authState{
		createTuple: {EventID: "$c", Type: "m.room.create", StateKey: sp(""), Sender: "@admin:x", RoomID: "!r:x",
			Content: json.RawMessage(`{"creator":"@admin:x","room_version":"10"}`)},
		plTuple: {EventID: "$p", Type: "m.room.power_levels", StateKey: sp(""), Sender: "@admin:x", RoomID: "!r:x",
			Content: json.RawMessage(oldPL)},
		{"m.room.member", "@mod:x"}:   {Type: "m.room.member", StateKey: sp("@mod:x"), Content: json.RawMessage(`{"membership":"join"}`)},
		{"m.room.member", "@admin:x"}: {Type: "m.room.member", StateKey: sp("@admin:x"), Content: json.RawMessage(`{"membership":"join"}`)},
	}
	try := func(sender, nw string) error {
		ev := &Event{Type: "m.room.power_levels", StateKey: sp(""), Sender: sender, RoomID: "!r:x", Content: json.RawMessage(nw)}
		return checkAuth("10", ev, []string{"$p"}, auth)
	}
	if try("@mod:x", `{"users":{"@admin:x":100,"@mod:x":100},"ban":50,"events":{"m.room.power_levels":50}}`) == nil {
		t.Error("mod promoted themselves above their level")
	}
	if try("@mod:x", `{"users":{"@admin:x":0,"@mod:x":50},"ban":50,"events":{"m.room.power_levels":50}}`) == nil {
		t.Error("mod demoted the admin")
	}
	if try("@mod:x", `{"users":{"@admin:x":100,"@mod:x":50},"ban":60,"events":{"m.room.power_levels":50}}`) == nil {
		t.Error("mod raised ban above their level")
	}
	if try("@mod:x", `{"users":{"@admin:x":100,"@mod:x":50},"ban":50,"events":{"m.room.power_levels":50},"notifications":{"room":60}}`) == nil {
		t.Error("mod set a notification level above their own")
	}
	if try("@mod:x", `{"users":{"@admin:x":100,"@mod:x":50,"@new:x":50},"ban":50,"events":{"m.room.power_levels":50}}`) != nil {
		t.Error("mod could not grant their own level to a new user")
	}
	if try("@admin:x", `{"users":{"@admin:x":100,"@mod:x":0},"ban":50,"events":{"m.room.power_levels":50}}`) != nil {
		t.Error("admin could not demote mod")
	}
}

func TestParseTokenAndIDs(t *testing.T) {
	for in, want := range map[string]bool{"s0": true, "s123": true, "123": true, "s": false, "": false, "s-1": false,
		"sx": false, "s9223372036854775807": true, "s9223372036854775808": false} {
		if _, ok := parseToken(in); ok != want {
			t.Errorf("parseToken(%q) ok=%v want %v", in, ok, want)
		}
	}
	for in, want := range map[string]bool{"@a:b": true, "@:b": false, "@a:": false, "@ab": false, "": false,
		"!r:host:8008": true, "#x:y": true, "@abc": false} {
		if _, _, ok := splitID(in); ok != want {
			t.Errorf("splitID(%q) ok=%v want %v", in, ok, want)
		}
	}
	for in, want := range map[string]bool{"alice": true, "a.b_c=d-e/f+g": true, "Alice": false, "": false,
		"al ice": false, "ålice": false, "a:b": false} {
		if validLocalpart(in) != want {
			t.Errorf("validLocalpart(%q) want %v", in, want)
		}
	}
}

func TestValidHostPort(t *testing.T) {
	for in, want := range map[string]bool{
		"example.com": true, "matrix.example.com:8448": true, "localhost:8008": true, "1.2.3.4": true,
		"[::1]:8008": true, "[::1]": true, "::1": false, "example.com:0": false, "example.com:70000": false,
		"exa mple.com": false, "exa/mple": false, "a@b": false, "": false, "host:port": false, "ex_ample.com": false,
	} {
		if validHostPort(in) != want {
			t.Errorf("validHostPort(%q) want %v", in, want)
		}
	}
}

func TestLoadConfigRejectsBadValues(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "c.conf")
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	good := "server_name = example.com\n"
	if _, err := loadConfig(write(good + "registration = True\nmax_upload_mb = 5\n")); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	for _, extra := range []string{
		"max_upload_mb = 5O\n", "max_upload_mb = 0\n", "max_upload_mb = -1\n", "max_upload_mb = 99999999999999\n",
		"registration = maybe\n", "trust_proxy = 2\n", "memory_limit_mb = x\n", "nope = 1\n", "garbage line\n",
		"public_base_url = ftp://x\n", "registration_token = short\n",
		"media_quota_mb = -1\n", "media_quota_mb = lots\n", "search_all_users = maybe\n",
	} {
		if _, err := loadConfig(write(good + extra)); err == nil {
			t.Errorf("bad config line %q accepted", extra)
		}
	}
	if _, err := loadConfig(write("server_name = bad name\n")); err == nil {
		t.Error("server_name with a space accepted")
	}
	if _, err := loadConfig(write("listen = 1\n")); err == nil {
		t.Error("missing server_name accepted")
	}
}

func TestPickThumbSize(t *testing.T) {
	cases := []struct {
		w, h   int
		crop   bool
		ww, wh int
	}{
		{1, 1, true, 32, 32}, {64, 64, true, 96, 96}, {5000, 5000, true, 320, 320},
		{64, 64, false, 96, 96}, {300, 200, false, 320, 240}, {99999, 1, false, 1280, 960}, {-5, -5, false, 96, 96},
	}
	for _, c := range cases {
		if w, h := pickThumbSize(c.w, c.h, c.crop); w != c.ww || h != c.wh {
			t.Errorf("pickThumbSize(%d,%d,%v) = %dx%d, want %dx%d", c.w, c.h, c.crop, w, h, c.ww, c.wh)
		}
	}
}

func TestPasswords(t *testing.T) {
	h := hashPassword("correct horse")
	if !checkPassword(h, "correct horse") || checkPassword(h, "wrong") {
		t.Fatal("password round trip failed")
	}
	for _, bad := range []string{"", "x", "pbkdf2-sha256$abc$AA$AA", "pbkdf2-sha256$0$AA$AA",
		"pbkdf2-sha256$999999999$AA$AA", "pbkdf2-sha256$1$!!$AA", "pbkdf2-sha256$1$AA$", "md5$1$a$b"} {
		if checkPassword(bad, "x") {
			t.Errorf("malformed hash %q accepted", bad)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(3, time.Hour)
	for i := 0; i < 3; i++ {
		if l.check("k") != nil {
			t.Fatal("blocked too early")
		}
		l.record("k")
	}
	if l.check("k") == nil {
		t.Fatal("not blocked after max")
	}
	if l.check("other") != nil {
		t.Fatal("other key blocked")
	}
	for i := 0; i < maxLimiterKeys*2; i++ {
		l.record(fmt.Sprint("ip", i))
	}
	if len(l.m) > maxLimiterKeys {
		t.Fatalf("limiter grew to %d keys", len(l.m))
	}
	short := newLimiter(1, time.Millisecond)
	short.record("k")
	time.Sleep(5 * time.Millisecond)
	if short.check("k") != nil {
		t.Fatal("window did not expire")
	}
}

func TestClientIP(t *testing.T) {
	s := &Server{cfg: &Config{TrustProxy: true}}
	req := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct{ remote, xff, want string }{
		{"127.0.0.1:5000", "203.0.113.9", "203.0.113.9"},
		{"127.0.0.1:5000", "6.6.6.6, 203.0.113.9", "203.0.113.9"}, // forged first hop ignored
		{"10.0.0.2:5000", "203.0.113.9", "203.0.113.9"},           // proxy container
		{"198.51.100.7:5000", "1.2.3.4", "198.51.100.7"},          // public peer: header not trusted
		{"127.0.0.1:5000", "not-an-ip", "127.0.0.1"},
		{"[::1]:5000", "2001:db8::1", "2001:db8::1"},
	}
	for _, c := range cases {
		if got := s.clientIP(req(c.remote, c.xff)); got != c.want {
			t.Errorf("clientIP(%s, %q) = %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
	s.cfg.TrustProxy = false
	if got := s.clientIP(req("127.0.0.1:5000", "203.0.113.9")); got != "127.0.0.1" {
		t.Errorf("trust_proxy off still used XFF: %s", got)
	}
}

func TestSignatureHelpers(t *testing.T) {
	stored := `{"keys":{"ed25519:K":"K"},"signatures":{"@alice:x":{"ed25519:K":"REAL"}}}`
	// bob adds his own signature; alice's must survive untouched
	merged, ok := mergeSignatures(stored, "@bob:x", map[string]any{"ed25519:B": "BOBSIG"})
	if !ok || !strings.Contains(merged, `"REAL"`) || !strings.Contains(merged, `"BOBSIG"`) {
		t.Fatalf("merge lost signatures: %s", merged)
	}
	// ownSignatures only returns the named signer's entries
	obj := map[string]any{"signatures": map[string]any{
		"@alice:x": map[string]any{"ed25519:K": "FORGED"},
		"@bob:x":   map[string]any{"ed25519:B": "OK", "bad": 5},
	}}
	if got := ownSignatures(obj, "@bob:x"); len(got) != 1 || got["ed25519:B"] != "OK" {
		t.Fatalf("ownSignatures = %v", got)
	}
	if ownSignatures(obj, "@carol:x") != nil || ownSignatures(map[string]any{}, "@bob:x") != nil {
		t.Fatal("expected no signatures")
	}
	f := filterSignatures(json.RawMessage(merged), "@alice:x")
	if strings.Contains(string(f), "BOBSIG") || !strings.Contains(string(f), "REAL") {
		t.Fatalf("filter kept wrong signers: %s", f)
	}
	if _, ok := mergeSignatures("null", "@b:x", nil); ok {
		t.Fatal("merge into null should fail")
	}
}

func TestPruneContent(t *testing.T) {
	got := string(pruneContent("m.room.member", json.RawMessage(`{"membership":"join","displayname":"x"}`), "10"))
	if got != `{"membership":"join"}` {
		t.Errorf("member prune = %s", got)
	}
	if got := string(pruneContent("m.room.message", json.RawMessage(`{"body":"secret"}`), "11")); got != `{}` {
		t.Errorf("message prune = %s", got)
	}
	for _, in := range []string{`null`, `[]`, `"s"`, ``, `{`} {
		if !json.Valid(pruneContent("m.room.message", json.RawMessage(in), "10")) {
			t.Errorf("prune of %q produced invalid JSON", in)
		}
	}
}

func TestRandString(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		r := randString(20)
		if len(r) != 20 || strings.Trim(r, alnum) != "" || seen[r] {
			t.Fatalf("bad random string %q", r)
		}
		seen[r] = true
	}
}

// ---- handlers ----

func TestLandingPageIsPlainText(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, req)
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") ||
		strings.Contains(w.Body.String(), "<") || !strings.Contains(w.Body.String(), "https://test.local") {
		t.Fatalf("landing page: %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}

// TestWritePanicReleasesConnection checks that a panic inside write() rolls
// back and frees its DB connection (the pool has only 4).
func TestWritePanicReleasesConnection(t *testing.T) {
	s := newTestServer(t)
	for i := 0; i < 10; i++ {
		func() {
			defer func() { recover() }()
			s.write(func(tx *sql.Tx) error {
				s.next()
				panic("boom")
			})
		}()
	}
	done := make(chan error, 1)
	go func() { done <- s.write(func(tx *sql.Tx) error { _, err := tx.Exec("SELECT 1"); return err }) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("write blocked: connections leaked by panics")
	}
	if s.pos.Load() != s.committed.Load() {
		t.Fatalf("stream position not restored after panic: pos=%d committed=%d", s.pos.Load(), s.committed.Load())
	}
}

func TestSignatureUploadRules(t *testing.T) {
	s := newTestServer(t)
	h := s.routes()
	alice, at := addUser(t, s, "alice")
	bob, bt := addUser(t, s, "bob")
	// alice's device keys and master key
	var adev string
	s.db.QueryRow("SELECT device_id FROM devices WHERE user_id = ?", alice).Scan(&adev)
	do(t, h, "POST", "/_matrix/client/v3/keys/upload", at, map[string]any{"device_keys": map[string]any{
		"user_id": alice, "device_id": adev, "keys": map[string]any{"ed25519:" + adev: "DK"},
		"signatures": map[string]any{alice: map[string]any{"ed25519:" + adev: "REAL"}}}})
	do(t, h, "POST", "/_matrix/client/v3/keys/device_signing/upload", at, map[string]any{
		"master_key": map[string]any{"user_id": alice, "usage": []string{"master"}, "keys": map[string]any{"ed25519:AMK": "AMK"}}})

	// bob tries to overwrite alice's device self-signature under alice's name
	_, b := do(t, h, "POST", "/_matrix/client/v3/keys/signatures/upload", bt, map[string]any{
		alice: map[string]any{adev: map[string]any{"signatures": map[string]any{alice: map[string]any{"ed25519:" + adev: "FORGED"}}}}})
	if b["failures"].(map[string]any)[alice] == nil {
		t.Fatalf("forged signature not reported as failure: %v", b)
	}
	// bob signs alice's device with his own key: not allowed (only master keys)
	_, b = do(t, h, "POST", "/_matrix/client/v3/keys/signatures/upload", bt, map[string]any{
		alice: map[string]any{adev: map[string]any{"signatures": map[string]any{bob: map[string]any{"ed25519:B": "S"}}}}})
	if b["failures"].(map[string]any)[alice] == nil {
		t.Fatalf("signing another user's device was allowed: %v", b)
	}
	// bob verifies alice: signs her master key with his user-signing key -> allowed
	_, b = do(t, h, "POST", "/_matrix/client/v3/keys/signatures/upload", bt, map[string]any{
		alice: map[string]any{"AMK": map[string]any{"signatures": map[string]any{bob: map[string]any{"ed25519:BUSK": "BOBSIG"}}}}})
	if len(b["failures"].(map[string]any)) != 0 {
		t.Fatalf("cross-user master signature refused: %v", b)
	}
	var keys string
	s.db.QueryRow("SELECT keys FROM device_keys WHERE user_id = ?", alice).Scan(&keys)
	if !strings.Contains(keys, "REAL") || strings.Contains(keys, "FORGED") {
		t.Fatalf("alice's device signature was changed: %s", keys)
	}
	// bob sees his signature on alice's master key; carol does not
	_, ct := addUser(t, s, "carol")
	query := func(tok string) string {
		_, b := do(t, h, "POST", "/_matrix/client/v3/keys/query", tok, map[string]any{"device_keys": map[string]any{alice: []any{}}})
		j, _ := json.Marshal(b["master_keys"])
		return string(j)
	}
	if !strings.Contains(query(bt), "BOBSIG") {
		t.Error("bob can't see his own signature on alice's master key")
	}
	if strings.Contains(query(ct), "BOBSIG") {
		t.Error("carol can see bob's private verification of alice")
	}
}

// fuzzRoutes are hit with random bodies by FuzzEndpoints.
var fuzzRoutes = []struct{ method, path string }{
	{"POST", "/_matrix/client/v3/createRoom"},
	{"POST", slidingSyncPath},
	{"PUT", "/_matrix/client/v3/rooms/ROOM/send/m.room.message/TXN"},
	{"PUT", "/_matrix/client/v3/rooms/ROOM/send/m.room.member/TXN"},
	{"PUT", "/_matrix/client/v3/rooms/ROOM/send/m.room.power_levels/TXN"},
	{"PUT", "/_matrix/client/v3/rooms/ROOM/send/m.room.redaction/TXN"},
	{"PUT", "/_matrix/client/v3/rooms/ROOM/state/m.room.power_levels"},
	{"PUT", "/_matrix/client/v3/rooms/ROOM/state/m.room.member/@u0:test.local"},
	{"PUT", "/_matrix/client/v3/rooms/ROOM/state/m.room.canonical_alias"},
	{"PUT", "/_matrix/client/v3/rooms/ROOM/state/m.room.name"},
	{"PUT", "/_matrix/client/v3/rooms/ROOM/redact/$x/TXN"},
	{"POST", "/_matrix/client/v3/rooms/ROOM/invite"},
	{"POST", "/_matrix/client/v3/rooms/ROOM/kick"},
	{"POST", "/_matrix/client/v3/rooms/ROOM/ban"},
	{"POST", "/_matrix/client/v3/rooms/ROOM/unban"},
	{"POST", "/_matrix/client/v3/rooms/ROOM/read_markers"},
	{"PUT", "/_matrix/client/v3/rooms/ROOM/typing/@u0:test.local"},
	{"POST", "/_matrix/client/v3/login"},
	{"POST", "/_matrix/client/v3/register"},
	{"POST", "/_matrix/client/v3/keys/upload"},
	{"POST", "/_matrix/client/v3/keys/query"},
	{"POST", "/_matrix/client/v3/keys/claim"},
	{"POST", "/_matrix/client/v3/keys/device_signing/upload"},
	{"POST", "/_matrix/client/v3/keys/signatures/upload"},
	{"PUT", "/_matrix/client/v3/sendToDevice/m.x/TXN"},
	{"POST", "/_matrix/client/v3/room_keys/version"},
	{"PUT", "/_matrix/client/v3/room_keys/keys?version=1"},
	{"PUT", "/_matrix/client/v3/pushrules/global/override/myrule"},
	{"PUT", "/_matrix/client/v3/pushrules/global/override/.m.rule.master/actions"},
	{"PUT", "/_matrix/client/v3/pushrules/global/override/.m.rule.master/enabled"},
	{"PUT", "/_matrix/client/v3/user/@u0:test.local/account_data/x.y"},
	{"PUT", "/_matrix/client/v3/profile/@u0:test.local/displayname"},
	{"POST", "/_matrix/client/v3/user/@u0:test.local/filter"},
	{"POST", "/_matrix/client/v3/user_directory/search"},
	{"POST", "/_matrix/client/v3/publicRooms"},
	{"POST", "/_matrix/client/v3/delete_devices"},
	{"POST", "/_matrix/client/v3/account/password"},
	{"PUT", "/_matrix/client/v3/directory/room/%23a:test.local"},
	{"GET", "/_matrix/client/v3/sync?timeout=0&since=QUERY"},
	{"GET", "/_matrix/client/v3/rooms/ROOM/messages?from=QUERY&limit=QUERY&dir=f"},
	{"GET", "/_matrix/client/v1/rooms/ROOM/relations/$x?from=QUERY&dir=f"},
	{"GET", "/_matrix/client/v3/publicRooms?since=QUERY&limit=QUERY"},
	{"GET", "/_matrix/media/v3/thumbnail/test.local/QUERY?width=QUERY&height=QUERY"},
	{"POST", "/_matrix/client/v3/pushers/set"},
	{"GET", "/_matrix/client/v3/pushers"},
	{"GET", "/_matrix/client/v3/profile/QUERY"},
	{"GET", "/_matrix/client/v3/directory/room/QUERY"},
}

// FuzzEndpoints sends arbitrary bodies and query strings to many endpoints as a
// logged-in room member and requires that nothing returns 5xx or panics.
func FuzzEndpoints(f *testing.F) {
	for i := range fuzzRoutes {
		for _, seed := range []string{`{}`, `null`, `[]`, `{"membership":"join"}`, `{"users":{"@u0:test.local":1e20}}`,
			`{"alias":"#a:test.local","alt_aliases":[1]}`, `{"global":null}`, `{"enabled":"yes"}`, `"x"`, `{"a":` + strings.Repeat("[", 200)} {
			f.Add(uint8(i), seed, "-1")
		}
	}
	s := newTestServer(f)
	h := s.routes()
	_, tok := addUser(f, s, "u0")
	_, room := do(f, h, "POST", "/_matrix/client/v3/createRoom", tok, map[string]any{"room_alias_name": "seed"})
	roomID, _ := room["room_id"].(string)
	n := 0
	f.Fuzz(func(t *testing.T, idx uint8, body, q string) {
		rt := fuzzRoutes[int(idx)%len(fuzzRoutes)]
		n++
		path := strings.ReplaceAll(rt.path, "ROOM", roomID)
		path = strings.ReplaceAll(path, "TXN", fmt.Sprint("t", n))
		path = strings.ReplaceAll(path, "QUERY", urlQueryEscape(q))
		req := httptest.NewRequest(rt.method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("%s %s with body %q panicked: %v", rt.method, path, body, p)
				}
			}()
			h.ServeHTTP(w, req)
		}()
		if w.Code >= 500 {
			t.Fatalf("%s %s with body %q -> %d %s", rt.method, path, body, w.Code, w.Body.String())
		}
	})
}

func urlQueryEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func FuzzToInt(f *testing.F) {
	for _, s := range []string{"1", "-1", "1e400", "1.5", "9007199254740993", "abc", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, v := range []any{json.Number(s), s} {
			if n := toInt(v, 0); n > maxSafeInt || n < -maxSafeInt {
				t.Fatalf("toInt(%q) = %d out of range", s, n)
			}
		}
	})
}

func FuzzValidatePowerLevels(f *testing.F) {
	f.Add(`{"users":{"@a:b":100},"ban":50}`)
	f.Add(`{"ban":1e400}`)
	f.Fuzz(func(t *testing.T, s string) {
		if validatePowerLevels(json.RawMessage(s)) == nil {
			// anything accepted must parse to in-range values on every platform
			pl := parsePowerLevels(json.RawMessage(s))
			for _, v := range append([]int64{pl.ban, pl.kick, pl.redact, pl.invite, pl.usersDefault}, mapVals(pl.users)...) {
				if v > maxSafeInt || v < -maxSafeInt {
					t.Fatalf("accepted out-of-range power level in %s", s)
				}
			}
		}
	})
}

func mapVals(m map[string]int64) []int64 {
	var out []int64
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func FuzzPickThumbSize(f *testing.F) {
	f.Add(64, 64, true)
	f.Fuzz(func(t *testing.T, w, h int, crop bool) {
		gw, gh := pickThumbSize(w, h, crop)
		for _, s := range thumbSizes {
			if s.w == gw && s.h == gh && s.crop == crop {
				return
			}
		}
		t.Fatalf("pickThumbSize(%d,%d,%v) = %dx%d, not a standard size", w, h, crop, gw, gh)
	})
}

func TestChangeLog(t *testing.T) {
	s := newTestServer(t)
	base := s.committed.Load()
	add := func(c change) int64 {
		var p int64
		if err := s.write(func(tx *sql.Tx) error { p = s.nextFor(c); return nil }); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rooms := map[string]bool{"!mine:x": true}
	shared := map[string]bool{"@me:x": true, "@friend:x": true}
	cur := func() int64 { return s.committed.Load() }

	add(change{room: "!other:x"})
	add(change{user: "@someone:x"})
	add(change{dev: "@stranger:x"})
	if s.touches("@me:x", rooms, shared, base, cur()) {
		t.Fatal("unrelated changes reported as relevant")
	}
	for name, c := range map[string]change{
		"my room": {room: "!mine:x"}, "aimed at me": {user: "@me:x"},
		"friend's devices": {dev: "@friend:x"}, "my devices": {dev: "@me:x"},
	} {
		before := cur()
		add(c)
		if !s.touches("@me:x", rooms, shared, before, cur()) {
			t.Errorf("%s not reported", name)
		}
		if s.touches("@me:x", rooms, shared, cur(), cur()) {
			t.Errorf("%s reported for an empty window", name)
		}
	}

	// a rolled-back write must not leave entries behind
	before := cur()
	s.write(func(tx *sql.Tx) error { s.nextFor(change{room: "!mine:x"}); return fmt.Errorf("nope") })
	add(change{room: "!other:x"})
	if s.touches("@me:x", rooms, shared, before, cur()) {
		t.Fatal("rolled-back change was published")
	}

	// once old entries are dropped, asking about that range must fall back to "yes"
	old := cur()
	for i := 0; i < 2*changeLogSize+10; i++ {
		add(change{room: "!other:x"})
	}
	if !s.touches("@me:x", rooms, shared, old, cur()) {
		t.Fatal("range older than the log did not fall back to rebuilding")
	}
	if s.touches("@me:x", rooms, shared, cur()-5, cur()) {
		t.Fatal("recent unrelated range reported as relevant")
	}
	if len(s.clog) > 2*changeLogSize {
		t.Fatalf("log grew to %d", len(s.clog))
	}
}

// TestSyncWakesForRelevantChanges runs real long-polls and checks that they
// return promptly for changes they can see and keep waiting otherwise.
func TestSyncWakesForRelevantChanges(t *testing.T) {
	s := newTestServer(t)
	h := s.routes()
	alice, at := addUser(t, s, "alice")
	_, bt := addUser(t, s, "bob")
	_, ct := addUser(t, s, "carol")
	_, r := do(t, h, "POST", "/_matrix/client/v3/createRoom", at, map[string]any{"preset": "public_chat"})
	room := r["room_id"].(string)
	do(t, h, "POST", "/_matrix/client/v3/join/"+room, bt, map[string]any{})
	_, other := do(t, h, "POST", "/_matrix/client/v3/createRoom", ct, map[string]any{})
	otherRoom := other["room_id"].(string)

	poll := func(tok string, since string, ms int) chan time.Duration {
		out := make(chan time.Duration, 1)
		go func() {
			t0 := time.Now()
			do(t, h, "GET", "/_matrix/client/v3/sync?timeout="+fmt.Sprint(ms)+"&since="+since, tok, nil)
			out <- time.Since(t0)
		}()
		return out
	}
	_, sb := do(t, h, "GET", "/_matrix/client/v3/sync?timeout=0", bt, nil)
	since := sb["next_batch"].(string)

	// unrelated: carol talks in her own room -> bob's poll keeps waiting
	done := poll(bt, since, 700)
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 5; i++ {
		do(t, h, "PUT", fmt.Sprintf("/_matrix/client/v3/rooms/%s/send/m.room.message/c%d", otherRoom, i), ct, map[string]any{"body": "x"})
	}
	if d := <-done; d < 600*time.Millisecond {
		t.Fatalf("bob's sync returned after %v for changes he can't see", d)
	}
	// related: alice talks in the shared room -> returns at once
	done = poll(bt, since, 5000)
	time.Sleep(100 * time.Millisecond)
	do(t, h, "PUT", "/_matrix/client/v3/rooms/"+room+"/send/m.room.message/a1", at, map[string]any{"body": "hi"})
	if d := <-done; d > 2*time.Second {
		t.Fatalf("bob's sync took %v to see a message in his room", d)
	}
	// being invited to a room bob isn't in yet must also wake him
	_, sb = do(t, h, "GET", "/_matrix/client/v3/sync?timeout=0&since="+since, bt, nil)
	since = sb["next_batch"].(string)
	done = poll(bt, since, 5000)
	time.Sleep(100 * time.Millisecond)
	do(t, h, "POST", "/_matrix/client/v3/rooms/"+otherRoom+"/invite", ct, map[string]any{"user_id": "@bob:test.local"})
	if d := <-done; d > 2*time.Second {
		t.Fatalf("bob's sync took %v to see an invite", d)
	}
	_ = alice
}

func TestMediaQuota(t *testing.T) {
	s := newTestServer(t)
	s.cfg.MediaQuotaBytes = 1 << 20 // 1 MB
	h := s.routes()
	_, tok := addUser(t, s, "uploader")
	upload := func(n int, declare bool) int {
		req := httptest.NewRequest("POST", "/_matrix/media/v3/upload", bytes.NewReader(make([]byte, n)))
		if !declare {
			req.ContentLength = -1 // unknown length: only the exact check can catch it
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if c := upload(600<<10, true); c != 200 {
		t.Fatalf("first upload: %d", c)
	}
	if c := upload(600<<10, true); c != 413 {
		t.Fatalf("over quota (declared length) allowed: %d", c)
	}
	if c := upload(600<<10, false); c != 413 {
		t.Fatalf("over quota (no length) allowed: %d", c)
	}
	files, _ := os.ReadDir(s.cfg.MediaDir)
	n := 0
	for _, f := range files {
		if !f.IsDir() {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("rejected uploads left %d files on disk (want 1)", n)
	}
	if c := upload(300<<10, true); c != 200 {
		t.Fatalf("upload that fits refused: %d", c)
	}
	// concurrent uploads can't jointly exceed the quota
	s2 := newTestServer(t)
	s2.cfg.MediaQuotaBytes = 1 << 20
	h2 := s2.routes()
	_, tok2 := addUser(t, s2, "racer")
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		go func() {
			req := httptest.NewRequest("POST", "/_matrix/media/v3/upload", bytes.NewReader(make([]byte, 300<<10)))
			req.ContentLength = -1
			req.Header.Set("Authorization", "Bearer "+tok2)
			w := httptest.NewRecorder()
			h2.ServeHTTP(w, req)
			codes <- w.Code
		}()
	}
	ok := 0
	for i := 0; i < 8; i++ {
		if <-codes == 200 {
			ok++
		}
	}
	if ok != 3 { // 3 x 300 KB fit in 1 MB, a 4th doesn't
		t.Fatalf("%d concurrent 300KB uploads accepted under a 1MB quota (want 3)", ok)
	}
}

func TestUserSearchPrivacy(t *testing.T) {
	s := newTestServer(t)
	h := s.routes()
	_, at := addUser(t, s, "alice")
	addUser(t, s, "bobby")          // shares nothing with alice
	_, ct := addUser(t, s, "carla") // will share a room
	_, dt := addUser(t, s, "dana")  // will be in a public room
	_, r := do(t, h, "POST", "/_matrix/client/v3/createRoom", at, map[string]any{"invite": []string{"@carla:test.local"}})
	do(t, h, "POST", "/_matrix/client/v3/join/"+r["room_id"].(string), ct, map[string]any{})
	do(t, h, "POST", "/_matrix/client/v3/createRoom", dt, map[string]any{"preset": "public_chat"})
	found := func() map[string]bool {
		out := map[string]bool{}
		for _, term := range []string{"b", "c", "d"} {
			_, b := do(t, h, "POST", "/_matrix/client/v3/user_directory/search", at, map[string]any{"search_term": term})
			for _, x := range b["results"].([]any) {
				out[x.(map[string]any)["user_id"].(string)] = true
			}
		}
		return out
	}
	got := found()
	if got["@bobby:test.local"] || !got["@carla:test.local"] || !got["@dana:test.local"] {
		t.Fatalf("default search found %v: want carla (shared room) and dana (public room), not bobby", got)
	}
	s.cfg.SearchAllUsers = true
	if !found()["@bobby:test.local"] {
		t.Fatal("search_all_users = true still hides bobby")
	}
}

func TestLegacyR0Paths(t *testing.T) {
	s := newTestServer(t)
	h := s.routes()
	_, tok := addUser(t, s, "alice")
	if code, out := do(t, h, "GET", "/_matrix/client/r0/login", "", nil); code != 200 || out["flows"] == nil {
		t.Fatalf("r0 login flows: %d %v", code, out)
	}
	code, out := do(t, h, "POST", "/_matrix/client/r0/login", "", map[string]any{
		"type": "m.login.password", "identifier": map[string]any{"type": "m.id.user", "user": "alice"}, "password": "password123"})
	if code != 200 || out["access_token"] == nil {
		t.Fatalf("r0 login: %d %v", code, out)
	}
	code, out = do(t, h, "POST", "/_matrix/client/r0/createRoom", tok, map[string]any{})
	if code != 200 {
		t.Fatalf("r0 createRoom: %d %v", code, out)
	}
	room := out["room_id"].(string)
	// escaped room ID in the path
	if code, out := do(t, h, "GET", "/_matrix/client/r0/rooms/"+url.PathEscape(room)+"/state", tok, nil); code != 200 {
		t.Fatalf("r0 state: %d %v", code, out)
	}
	if code, out := do(t, h, "GET", "/_matrix/client/r0/sync?timeout=0", tok, nil); code != 200 || out["next_batch"] == nil {
		t.Fatalf("r0 sync: %d %v", code, out)
	}
	if code, _ := do(t, h, "GET", "/_matrix/media/r0/config", tok, nil); code != 200 {
		t.Fatalf("r0 media config: %d", code)
	}
	if code, out := do(t, h, "GET", "/_matrix/client/unstable/room_keys/version", tok, nil); code != 404 || out["errcode"] != "M_NOT_FOUND" {
		t.Fatalf("unstable room_keys: %d %v", code, out)
	}
	if code, out := do(t, h, "GET", "/_matrix/client/unstable/org.matrix.msc9999/thing", tok, nil); code != 404 || out["errcode"] != "M_UNRECOGNIZED" {
		t.Fatalf("unknown unstable: %d %v", code, out)
	}
	if code, out := do(t, h, "GET", "/_matrix/client/r9/login", "", nil); code != 404 || out["errcode"] != "M_UNRECOGNIZED" {
		t.Fatalf("unknown version: %d %v", code, out)
	}
}
