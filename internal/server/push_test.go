package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func defaultRulesFor(uid string) *pushRuleSet {
	var rs pushRuleSet
	json.Unmarshal([]byte(strings.ReplaceAll(defaultPushRules, "@USER@", uid)), &rs)
	return &rs
}

func evFor(typ string, content string) map[string]any {
	var c map[string]any
	dec := json.NewDecoder(strings.NewReader(content))
	dec.UseNumber()
	dec.Decode(&c)
	return map[string]any{"type": typ, "sender": "@bob:x", "room_id": "!r:x", "content": c}
}

func TestPushRules(t *testing.T) {
	alice := "@alice:x"
	cases := []struct {
		name      string
		event     map[string]any
		members   int
		senderPL  int64
		notify    bool
		highlight bool
		sound     bool
	}{
		{"DM message", evFor("m.room.message", `{"msgtype":"m.text","body":"hi"}`), 2, 0, true, false, true},
		{"group message", evFor("m.room.message", `{"msgtype":"m.text","body":"hi"}`), 5, 0, true, false, false},
		{"encrypted DM", evFor("m.room.encrypted", `{"algorithm":"m.megolm.v1.aes-sha2","ciphertext":"x"}`), 2, 0, true, false, true},
		{"encrypted group", evFor("m.room.encrypted", `{"ciphertext":"x"}`), 5, 0, true, false, false},
		{"notice", evFor("m.room.message", `{"msgtype":"m.notice","body":"bot"}`), 2, 0, false, false, false},
		{"reaction", evFor("m.reaction", `{"m.relates_to":{"rel_type":"m.annotation","event_id":"$e","key":"👍"}}`), 2, 0, false, false, false},
		{"edit", evFor("m.room.message", `{"body":"* x","m.relates_to":{"rel_type":"m.replace","event_id":"$e"}}`), 2, 0, false, false, false},
		{"user mention", evFor("m.room.message", `{"body":"hey","m.mentions":{"user_ids":["@alice:x"]}}`), 9, 0, true, true, true},
		{"other user's mention", evFor("m.room.message", `{"body":"hey","m.mentions":{"user_ids":["@carol:x"]}}`), 9, 0, true, false, false},
		{"@room by a mod", evFor("m.room.message", `{"body":"all","m.mentions":{"room":true}}`), 9, 50, true, true, false},
		{"@room by a nobody", evFor("m.room.message", `{"body":"all","m.mentions":{"room":true}}`), 9, 0, true, false, false},
		{"other member change", func() map[string]any {
			e := evFor("m.room.member", `{"membership":"join"}`)
			e["state_key"] = "@bob:x"
			return e
		}(), 5, 0, false, false, false},
		{"invite for me", func() map[string]any {
			e := evFor("m.room.member", `{"membership":"invite"}`)
			e["state_key"] = alice
			return e
		}(), 5, 0, true, false, true},
		{"unknown event", evFor("org.example.x", `{}`), 2, 0, false, false, false},
	}
	for _, c := range cases {
		env := &pushEnv{event: c.event, uid: alice, displayName: "Alice", memberCount: c.members,
			senderLevel: c.senderPL, notifLevels: map[string]int64{"room": 50}}
		notify, tweaks := notifyTweaks(pushActions(defaultRulesFor(alice), env))
		hl, _ := tweaks["highlight"].(bool)
		_, sound := tweaks["sound"]
		if notify != c.notify || hl != c.highlight || sound != c.sound {
			t.Errorf("%s: notify=%v highlight=%v sound=%v, want %v %v %v", c.name, notify, hl, sound, c.notify, c.highlight, c.sound)
		}
	}

	// user-defined rules
	msg := evFor("m.room.message", `{"msgtype":"m.text","body":"I like cake!"}`)
	env := &pushEnv{event: msg, uid: alice, memberCount: 5}
	try := func(kind string, rule map[string]any) bool {
		rs := defaultRulesFor(alice)
		rs.Global[kind] = append([]map[string]any{rule}, rs.Global[kind]...)
		n, _ := notifyTweaks(pushActions(rs, env))
		return n
	}
	if try("override", map[string]any{"rule_id": "mute", "enabled": true, "actions": []any{},
		"conditions": []any{map[string]any{"kind": "event_match", "key": "room_id", "pattern": "!r:x"}}}) {
		t.Error("muted room still notifies")
	}
	if try("room", map[string]any{"rule_id": "!r:x", "enabled": true, "actions": []any{}}) {
		t.Error("room rule with no actions still notifies")
	}
	if try("sender", map[string]any{"rule_id": "@bob:x", "enabled": true, "actions": []any{"dont_notify"}}) {
		t.Error("sender rule ignored")
	}
	rs := defaultRulesFor(alice)
	rs.Global["content"] = []map[string]any{{"rule_id": "cake", "enabled": true, "pattern": "cake",
		"actions": []any{"notify", map[string]any{"set_tweak": "highlight"}}}}
	if _, tw := notifyTweaks(pushActions(rs, env)); tw["highlight"] != true {
		t.Error("content keyword rule did not highlight")
	}
	env.event = evFor("m.room.message", `{"msgtype":"m.text","body":"pancakes"}`)
	if _, tw := notifyTweaks(pushActions(rs, env)); tw["highlight"] == true {
		t.Error("keyword matched inside another word")
	}
	rs = defaultRulesFor(alice)
	rs.Global["override"][0]["enabled"] = true // .m.rule.master: mute everything
	env.event = msg
	if n, _ := notifyTweaks(pushActions(rs, env)); n {
		t.Error("master rule did not silence notifications")
	}
	// display name mentions
	env = &pushEnv{event: evFor("m.room.message", `{"body":"thanks alice!"}`), displayName: "Alice"}
	if !condMatches(map[string]any{"kind": "contains_display_name"}, env) {
		t.Error("display name mention missed")
	}
	env.event = evFor("m.room.message", `{"body":"malice"}`)
	if condMatches(map[string]any{"kind": "contains_display_name"}, env) {
		t.Error("display name matched inside a word")
	}
	env.displayName = "a.*b"
	env.event = evFor("m.room.message", `{"body":"axxb"}`)
	if condMatches(map[string]any{"kind": "contains_display_name"}, env) {
		t.Error("display name was treated as a pattern")
	}
}

func TestPushHelpers(t *testing.T) {
	for key, want := range map[string][]string{
		"content.body": {"content", "body"}, `content.m\.relates_to.rel_type`: {"content", "m.relates_to", "rel_type"},
		`a\\.b`: {`a\`, "b"}, "x": {"x"},
	} {
		if got := splitPath(key); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("splitPath(%q) = %q, want %q", key, got, want)
		}
	}
	for _, c := range []struct {
		pat, val   string
		body, want bool
	}{
		{"foo*", "foobar", false, true}, {"foo*", "xfoobar", false, false}, {"f?o", "FOO", false, true},
		{"cake", "I like Cake.", true, true}, {"cake", "cakes", true, false}, {"c*e", "a cake here", true, true},
		{"m.notice", "m.notice", false, true}, {"m.notice", "mxnotice", false, false}, // dots are literal
	} {
		if got := globMatch(c.pat, c.val, c.body); got != c.want {
			t.Errorf("globMatch(%q, %q, %v) = %v", c.pat, c.val, c.body, got)
		}
	}
	for is, want := range map[string]bool{"2": true, "==2": true, ">1": true, "<2": false, ">=2": true, "<=1": false, "x": false, "": false} {
		if memberCountMatches(is, 2) != want {
			t.Errorf("memberCountMatches(%q, 2) want %v", is, want)
		}
	}
	if !jsonEqual(json.Number("5"), float64(5)) || jsonEqual("5", float64(5)) || !jsonEqual(true, true) || !jsonEqual(nil, nil) {
		t.Error("jsonEqual")
	}
	for ip, pub := range map[string]bool{"8.8.8.8": true, "127.0.0.1": false, "10.1.2.3": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false, "fd00::1": false,
		"2001:4860:4860::8888": true, "fe80::1": false, "::ffff:127.0.0.1": false, "255.255.255.255": false} {
		if publicIP(parseIP(ip)) != pub {
			t.Errorf("publicIP(%s) want %v", ip, pub)
		}
	}
}

func TestPusherAPI(t *testing.T) {
	s := newTestServer(t)
	h := s.routes()
	alice, at := addUser(t, s, "alice")
	_, bt := addUser(t, s, "bob")
	good := map[string]any{"pushkey": "pk1", "kind": "http", "app_id": "im.vector.app", "app_display_name": "Element",
		"device_display_name": "Phone", "lang": "en", "data": map[string]any{"url": "https://push.example.org" + pushGatewayPath, "format": "event_id_only"}}
	set := func(tok string, body map[string]any) int {
		st, _ := do(t, h, "POST", "/_matrix/client/v3/pushers/set", tok, body)
		return st
	}
	with := func(k string, v any) map[string]any {
		b := map[string]any{}
		for kk, vv := range good {
			b[kk] = vv
		}
		b[k] = v
		return b
	}
	for name, body := range map[string]map[string]any{
		"http url":   with("data", map[string]any{"url": "http://push.example.org" + pushGatewayPath}),
		"wrong path": with("data", map[string]any{"url": "https://push.example.org/notify"}),
		"no url":     with("data", map[string]any{}),
		"userinfo":   with("data", map[string]any{"url": "https://u:p@push.example.org" + pushGatewayPath}),
		"email kind": with("kind", "email"),
		"no pushkey": with("pushkey", ""),
		"long key":   with("pushkey", strings.Repeat("k", 513)),
		"long app":   with("app_id", strings.Repeat("a", 65)),
	} {
		if st := set(at, body); st != 400 {
			t.Errorf("%s: accepted (%d)", name, st)
		}
	}
	if st := set(at, good); st != 200 {
		t.Fatalf("valid pusher refused: %d", st)
	}
	_, b := do(t, h, "GET", "/_matrix/client/v3/pushers", at, nil)
	ps := b["pushers"].([]any)
	if len(ps) != 1 || ps[0].(map[string]any)["pushkey"] != "pk1" {
		t.Fatalf("pushers = %v", b)
	}
	// the same phone now logs into bob's account: alice's pusher goes away
	if st := set(bt, good); st != 200 {
		t.Fatal(st)
	}
	_, b = do(t, h, "GET", "/_matrix/client/v3/pushers", at, nil)
	if len(b["pushers"].([]any)) != 0 {
		t.Fatal("pushkey still registered to the previous account")
	}
	// kind: null deletes
	set(bt, with("kind", nil))
	_, b = do(t, h, "GET", "/_matrix/client/v3/pushers", bt, nil)
	if len(b["pushers"].([]any)) != 0 {
		t.Fatal("kind null did not delete")
	}
	// limit
	for i := 0; i < maxPushersPerUser; i++ {
		if st := set(at, with("pushkey", "k"+string(rune('a'+i)))); st != 200 {
			t.Fatalf("pusher %d refused", i)
		}
	}
	if st := set(at, with("pushkey", "one-too-many")); st != 400 {
		t.Fatal("pusher limit not enforced")
	}
	// logging out the device removes its pushers
	do(t, h, "POST", "/_matrix/client/v3/logout", at, map[string]any{})
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM pushers WHERE user_id = ?", alice).Scan(&n)
	if n != 0 {
		t.Fatalf("%d pushers left after logout", n)
	}
}

// fakeGateway records notifications sent to it.
type fakeGateway struct {
	mu       sync.Mutex
	got      []map[string]any
	rejected []string
}

func (g *fakeGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var m map[string]any
	json.Unmarshal(body, &m)
	g.mu.Lock()
	g.got = append(g.got, m)
	rej := g.rejected
	g.mu.Unlock()
	if r.URL.Path != pushGatewayPath {
		w.WriteHeader(404)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"rejected": rej})
}

func (g *fakeGateway) wait(t *testing.T, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		if len(g.got) >= n {
			out := append([]map[string]any(nil), g.got...)
			g.mu.Unlock()
			return out
		}
		g.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	t.Fatalf("gateway got %d notifications, want %d", len(g.got), n)
	return nil
}

func (g *fakeGateway) count() int {
	time.Sleep(300 * time.Millisecond) // give the worker time to (wrongly) send
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.got)
}

func TestPushDelivery(t *testing.T) {
	gw := &fakeGateway{}
	srv := httptest.NewTLSServer(gw)
	defer srv.Close()
	s := newTestServer(t)
	s.pushClient = srv.Client() // trusts the test certificate; the SSRF guard is tested separately
	s.startPusher()
	h := s.routes()
	alice, at := addUser(t, s, "alice")
	_, bt := addUser(t, s, "bob")
	_, r := do(t, h, "POST", "/_matrix/client/v3/createRoom", at, map[string]any{"invite": []string{"@bob:test.local"}, "is_direct": true})
	room := r["room_id"].(string)
	do(t, h, "POST", "/_matrix/client/v3/join/"+room, bt, map[string]any{})
	st, _ := do(t, h, "POST", "/_matrix/client/v3/pushers/set", at, map[string]any{"pushkey": "pk1", "kind": "http",
		"app_id": "im.vector.app", "data": map[string]any{"url": srv.URL + pushGatewayPath, "format": "full", "extra": "x"}})
	if st != 200 {
		t.Fatal(st)
	}
	send := func(tok, txn string, content map[string]any) string {
		_, b := do(t, h, "PUT", "/_matrix/client/v3/rooms/"+room+"/send/m.room.message/"+txn, tok, content)
		return b["event_id"].(string)
	}

	eid := send(bt, "1", map[string]any{"msgtype": "m.text", "body": "secret words"})
	n := gw.wait(t, 1)[0]["notification"].(map[string]any)
	for k := range n {
		switch k {
		case "event_id", "room_id", "counts", "devices", "prio":
		default:
			t.Errorf("notification leaks %q (only IDs and counts may leave the server)", k)
		}
	}
	raw, _ := json.Marshal(n)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "@bob") {
		t.Fatalf("message content or sender sent to the gateway: %s", raw)
	}
	if n["event_id"] != eid || n["room_id"] != room || n["counts"].(map[string]any)["unread"] != float64(1) {
		t.Fatalf("notification = %s", raw)
	}
	dev := n["devices"].([]any)[0].(map[string]any)
	if dev["pushkey"] != "pk1" || dev["app_id"] != "im.vector.app" || dev["data"].(map[string]any)["url"] != nil ||
		dev["data"].(map[string]any)["extra"] != "x" || dev["tweaks"].(map[string]any)["sound"] != "default" {
		t.Fatalf("device entry = %v", dev)
	}

	// no push for: alice's own message, a notice
	send(at, "2", map[string]any{"msgtype": "m.text", "body": "mine"})
	send(bt, "3", map[string]any{"msgtype": "m.notice", "body": "bot"})
	if c := gw.count(); c != 1 {
		t.Fatalf("got %d notifications, want still 1", c)
	}
	// reading clears the badge on other devices: one counts-only update
	do(t, h, "POST", "/_matrix/client/v3/rooms/"+room+"/receipt/m.read/"+eid, at, map[string]any{})
	all := gw.wait(t, 2)
	badge := all[1]["notification"].(map[string]any)
	if badge["event_id"] != nil || badge["counts"].(map[string]any)["unread"] != float64(0) {
		t.Fatalf("badge update = %v", badge)
	}
	do(t, h, "POST", "/_matrix/client/v3/rooms/"+room+"/receipt/m.read/"+eid, at, map[string]any{})
	if c := gw.count(); c != 2 {
		t.Fatalf("unchanged badge sent again (%d)", c)
	}
	// the gateway says the pushkey is dead: the pusher is removed
	gw.mu.Lock()
	gw.rejected = []string{"pk1"}
	gw.mu.Unlock()
	send(bt, "4", map[string]any{"msgtype": "m.text", "body": "again"})
	gw.wait(t, 3)
	deadline := time.Now().Add(3 * time.Second)
	for {
		var left int
		s.db.QueryRow("SELECT COUNT(*) FROM pushers WHERE user_id = ?", alice).Scan(&left)
		if left == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rejected pusher not removed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPushClientRefusesInternalAddresses(t *testing.T) {
	hit := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	c := newPushClient(false)
	c.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	_, err := c.Post(srv.URL+pushGatewayPath, "application/json", bytes.NewReader([]byte("{}")))
	if err == nil || hit || !errors.Is(err, errPushAddress) {
		t.Fatalf("request to 127.0.0.1 not refused: err=%v hit=%v", err, hit)
	}
	// and the same client may reach it when private addresses are allowed (tests only)
	c = newPushClient(true)
	c.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	if resp, err := c.Post(srv.URL+pushGatewayPath, "application/json", bytes.NewReader([]byte("{}"))); err != nil || !hit {
		t.Fatalf("allowPrivate client failed: %v", err)
	} else {
		resp.Body.Close()
	}
	// redirects are not followed
	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer redir.Close()
	c.Transport.(*http.Transport).TLSClientConfig = redir.Client().Transport.(*http.Transport).TLSClientConfig
	resp, err := c.Post(redir.URL+pushGatewayPath, "application/json", bytes.NewReader([]byte("{}")))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect was followed: %v %v", resp, err)
	}
	resp.Body.Close()
}

// FuzzPushRules feeds random events and rules to the evaluator; it must never
// panic and must only ever return what a rule said.
func FuzzPushRules(f *testing.F) {
	f.Add(`{"body":"hi","m.mentions":{"user_ids":["@a:x"]}}`, `{"kind":"event_match","key":"content.body","pattern":"h*"}`)
	f.Add(`{"a":{"b":[1,2,{"c":null}]}}`, `{"kind":"event_property_contains","key":"content.a.b","value":2}`)
	f.Add(`[]`, `{"kind":"room_member_count","is":">=999999999999"}`)
	f.Fuzz(func(t *testing.T, content, cond string) {
		var c map[string]any
		dec := json.NewDecoder(strings.NewReader(content))
		dec.UseNumber()
		dec.Decode(&c)
		var cm map[string]any
		json.Unmarshal([]byte(cond), &cm)
		ev := map[string]any{"type": "m.room.message", "sender": "@b:x", "room_id": "!r:x", "content": c}
		env := &pushEnv{event: ev, uid: "@a:x", displayName: cond, memberCount: 3}
		rs := defaultRulesFor("@a:x")
		rs.Global["override"] = append([]map[string]any{{"rule_id": "f", "conditions": []any{cm}, "actions": []any{"notify"}}}, rs.Global["override"]...)
		pushActions(rs, env)
		condMatches(cm, env)
	})
}

var _ = sql.ErrNoRows

func parseIP(s string) net.IP { return net.ParseIP(s) }
