package server

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func hasEvent(s *Server, id string) bool {
	h, _, ok := haveEvent(s.db, id)
	return ok && h == evVisible
}

func topicOf(s *Server, room string) string {
	return stateString(s.db, room, "m.room.topic", "", "topic")
}

type fedUser struct {
	s     *Server
	h     http.Handler
	id    string
	token string
}

func (u fedUser) do(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	return do(t, u.h, method, path, u.token, body)
}

func (u fedUser) send(t *testing.T, room, body string) string {
	t.Helper()
	code, res := u.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/send/m.room.message/"+randString(8), map[string]any{"msgtype": "m.text", "body": body})
	if code != 200 {
		t.Fatalf("%s send: %d %v", u.id, code, res)
	}
	return res["event_id"].(string)
}

func TestRoomAcrossServers(t *testing.T) {
	a, b, ha, hb := fedPair(t)
	aid, at := addUser(t, a, "alice")
	bid, bt := addUser(t, b, "bob")
	alice, bob := fedUser{a, ha, aid, at}, fedUser{b, hb, bid, bt}

	code, res := alice.do(t, "POST", "/_matrix/client/v3/createRoom", map[string]any{"preset": "private_chat", "name": "across"})
	if code != 200 {
		t.Fatal(code, res)
	}
	room := res["room_id"].(string)

	// invite across servers
	if code, res := alice.do(t, "POST", "/_matrix/client/v3/rooms/"+room+"/invite", map[string]any{"user_id": bid}); code != 200 {
		t.Fatalf("remote invite: %d %v", code, res)
	}
	if m, _ := getMembership(b.db, room, bid); m != "invite" {
		t.Fatalf("bob's server has membership %q", m)
	}
	_, sync := bob.do(t, "GET", "/_matrix/client/v3/sync", nil)
	inv, _ := sync["rooms"].(map[string]any)["invite"].(map[string]any)
	if _, ok := inv[room]; !ok {
		t.Fatalf("invite not in bob's sync: %v", sync["rooms"])
	}

	// join across servers
	if code, res := bob.do(t, "POST", "/_matrix/client/v3/join/"+room, map[string]any{}); code != 200 {
		t.Fatalf("remote join: %d %v", code, res)
	}
	if m, _ := getMembership(a.db, room, bid); m != "join" {
		t.Fatalf("alice's server sees bob as %q", m)
	}
	if got := stateString(b.db, room, "m.room.name", "", "name"); got != "across" {
		t.Errorf("bob's server has room name %q", got)
	}

	// messages both ways
	m1 := bob.send(t, room, "hi from b")
	waitFor(t, "bob's message on A", func() bool { return hasEvent(a, m1) })
	m2 := alice.send(t, room, "hi from a")
	waitFor(t, "alice's message on B", func() bool { return hasEvent(b, m2) })
	_, sync = bob.do(t, "GET", "/_matrix/client/v3/sync", nil)
	join, _ := sync["rooms"].(map[string]any)["join"].(map[string]any)
	if _, ok := join[room]; !ok {
		t.Fatalf("room not joined in bob's sync")
	}

	// state changes reach the other side
	if code, _ := alice.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/state/m.room.topic/", map[string]any{"topic": "t1"}); code != 200 {
		t.Fatal("topic")
	}
	waitFor(t, "topic on B", func() bool { return topicOf(b, room) == "t1" })

	// both servers agree on the whole state
	assertSameState(t, a, b, room)
	checkGraph(t, a, room)
	checkGraph(t, b, room)

	// bob can't change the topic (power level 0): his server refuses, and
	// a forged one sent straight to A would be rejected there too
	if code, _ := bob.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/state/m.room.topic/", map[string]any{"topic": "bob"}); code != 403 {
		t.Errorf("bob set the topic: %d", code)
	}

	// kick across servers
	if code, res := alice.do(t, "POST", "/_matrix/client/v3/rooms/"+room+"/kick", map[string]any{"user_id": bid}); code != 200 {
		t.Fatalf("kick: %d %v", code, res)
	}
	waitFor(t, "kick on B", func() bool { m, _ := getMembership(b.db, room, bid); return m == "leave" })
}

// assertSameState checks both servers have the same current state.
func assertSameState(t *testing.T, a, b *Server, room string) {
	t.Helper()
	sa, _ := loadStateGroup(a.db, currentStateGroup(a.db, room))
	sb, _ := loadStateGroup(b.db, currentStateGroup(b.db, room))
	if len(sa) != len(sb) {
		t.Errorf("state sizes differ: %d vs %d", len(sa), len(sb))
	}
	for k, v := range sa {
		if sb[k] != v {
			t.Errorf("state %v: %s vs %s", k, v, sb[k])
		}
	}
	// room_state mirrors the current state group
	rows, _ := a.db.Query("SELECT type, state_key, event_id FROM room_state WHERE room_id = ?", room)
	n := 0
	for rows.Next() {
		var k stateTuple
		var id string
		rows.Scan(&k.typ, &k.key, &id)
		if sa[k] != id {
			t.Errorf("room_state %v = %s, state group has %s", k, id, sa[k])
		}
		n++
	}
	rows.Close()
	if n != len(sa) {
		t.Errorf("room_state has %d rows, state group %d", n, len(sa))
	}
}

// checkGraph re-checks each visible event against its own auth events.
func checkGraph(t *testing.T, s *Server, room string) {
	t.Helper()
	ri, _ := getRoomInfo(s.db, room)
	rows, _ := s.db.Query("SELECT event_id FROM events WHERE room_id = ? AND hidden = 0", room)
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	get := pduGetter(s.db, nil)
	for _, id := range ids {
		ev := get(id)
		if ev == nil {
			t.Fatalf("event %s unreadable", id)
		}
		if err := checkAgainstAuthEvents(ri.version, ev, get); err != nil {
			t.Errorf("%s (%s) fails its auth events: %v", id, ev.Type, err)
		}
	}
}

func pauseTo(s *Server, dest string) {
	s.destState(dest)
	s.db.Exec("UPDATE fed_destinations SET retry_at = ? WHERE server = ?", time.Now().Add(time.Hour).UnixMilli(), dest)
}

func resumeTo(s *Server, dest string) {
	s.db.Exec("UPDATE fed_destinations SET retry_at = 0, backoff = 0 WHERE server = ?", dest)
	s.kickSender()
}

// sharedRoom makes a room on A that bob (on B) has joined, with bob at power 50.
func sharedRoom(t *testing.T, alice, bob fedUser, preset string) string {
	t.Helper()
	code, res := alice.do(t, "POST", "/_matrix/client/v3/createRoom", map[string]any{"preset": preset,
		"power_level_content_override": map[string]any{"users": map[string]any{alice.id: 100, bob.id: 50}}})
	if code != 200 {
		t.Fatal(code, res)
	}
	room := res["room_id"].(string)
	if preset != "public_chat" {
		if code, res := alice.do(t, "POST", "/_matrix/client/v3/rooms/"+room+"/invite", map[string]any{"user_id": bob.id}); code != 200 {
			t.Fatal(code, res)
		}
	}
	if code, res := bob.do(t, "POST", "/_matrix/client/v3/join/"+room, map[string]any{}); code != 200 {
		t.Fatalf("join: %d %v", code, res)
	}
	return room
}

func TestConcurrentChangesConverge(t *testing.T) {
	a, b, ha, hb := fedPair(t)
	aid, at := addUser(t, a, "alice")
	bid, bt := addUser(t, b, "bob")
	alice, bob := fedUser{a, ha, aid, at}, fedUser{b, hb, bid, bt}
	room := sharedRoom(t, alice, bob, "private_chat")
	A, B := a.cfg.ServerName, b.cfg.ServerName

	// Both sides change things without hearing from each other: the graph forks.
	pauseTo(a, B)
	pauseTo(b, A)
	alice.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/state/m.room.name/", map[string]any{"name": "from alice"})
	// alice demotes bob ...
	if code, res := alice.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/state/m.room.power_levels/", map[string]any{
		"users": map[string]any{aid: 100}, "state_default": 50, "events": map[string]any{"m.room.topic": 50}}); code != 200 {
		t.Fatal(code, res)
	}
	// ... while bob, still at 50 on his side, changes the topic
	if code, res := bob.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/state/m.room.topic/", map[string]any{"topic": "from bob"}); code != 200 {
		t.Fatal(code, res)
	}
	mb := bob.send(t, room, "concurrent b")
	ma := alice.send(t, room, "concurrent a")
	resumeTo(a, B)
	resumeTo(b, A)
	waitFor(t, "exchange", func() bool {
		_, _, okA := haveEvent(a.db, mb)
		_, _, okB := haveEvent(b.db, ma)
		return okA && okB
	})
	waitFor(t, "convergence", func() bool { return topicOf(a, room) == topicOf(b, room) })
	// state resolution applies alice's demotion first; bob's topic then fails
	if got := topicOf(b, room); got == "from bob" {
		t.Errorf("bob's topic survived his demotion")
	}
	if got := stateString(b.db, room, "m.room.name", "", "name"); got != "from alice" {
		t.Errorf("name on B: %q", got)
	}
	// a later event from each side merges the branches
	m3 := alice.send(t, room, "after")
	waitFor(t, "merge event on B", func() bool { return hasEvent(b, m3) })
	m4 := bob.send(t, room, "after b")
	waitFor(t, "merge event on A", func() bool { return hasEvent(a, m4) })
	assertSameState(t, a, b, room)
	checkGraph(t, a, room)
	checkGraph(t, b, room)
}

func TestMissingEventsAreFetched(t *testing.T) {
	a, b, ha, hb := fedPair(t)
	aid, at := addUser(t, a, "alice")
	bid, bt := addUser(t, b, "bob")
	alice, bob := fedUser{a, ha, aid, at}, fedUser{b, hb, bid, bt}
	room := sharedRoom(t, alice, bob, "public_chat")
	B := b.cfg.ServerName
	pauseTo(a, B)
	m1 := alice.send(t, room, "one")
	alice.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/state/m.room.topic/", map[string]any{"topic": "gap"})
	m3 := alice.send(t, room, "three")
	// B never gets the first two: skip them in A's queue
	var st int64
	a.db.QueryRow("SELECT stream FROM events WHERE event_id = ?", m3).Scan(&st)
	a.db.Exec("UPDATE fed_destinations SET last_stream = ? WHERE server = ?", st-1, B)
	resumeTo(a, B)
	waitFor(t, "m3 on B", func() bool { return hasEvent(b, m3) })
	if !hasEvent(b, m1) {
		t.Error("B didn't fetch the missing events before m3")
	}
	if topicOf(b, room) != "gap" {
		t.Errorf("topic from the gap: %q", topicOf(b, room))
	}
	assertSameState(t, a, b, room)
	_ = bob
}

func TestFederationRejectsForgeries(t *testing.T) {
	a, b, ha, hb := fedPair(t)
	aid, at := addUser(t, a, "alice")
	bid, bt := addUser(t, b, "bob")
	alice, bob := fedUser{a, ha, aid, at}, fedUser{b, hb, bid, bt}
	room := sharedRoom(t, alice, bob, "public_chat")
	ri, _ := getRoomInfo(b.db, room)
	r, _ := rulesFor(ri.version)
	A := a.cfg.ServerName

	// build an event on B the normal way, without storing it
	build := func(sender string, content map[string]any) (map[string]any, string) {
		var pdu map[string]any
		var id string
		b.write(func(tx *sql.Tx) error {
			ev := b.newEvent(room, sender, "m.room.message", nil, content)
			if err := b.storeEvent(tx, ev); err != nil {
				t.Fatal(err)
			}
			var raw string
			tx.QueryRow("SELECT pdu FROM events WHERE event_id = ?", ev.EventID).Scan(&raw)
			v, _ := decodeJSONNumbers([]byte(raw))
			pdu, id = v.(map[string]any), ev.EventID
			return errBuildOnly
		})
		return pdu, id
	}
	sendTxn := func(pdus ...map[string]any) map[string]any {
		var res map[string]any
		body := map[string]any{"origin": b.cfg.ServerName, "origin_server_ts": nowMS(), "pdus": pdus, "edus": []any{}}
		if err := b.fedRequest(context.Background(), "PUT", A, "/_matrix/federation/v1/send/"+randString(8), body, &res); err != nil {
			t.Fatal(err)
		}
		return res["pdus"].(map[string]any)
	}

	// 1. content changed after signing: kept, but only in redacted form
	pdu, id := build(bid, map[string]any{"msgtype": "m.text", "body": "original"})
	pdu["content"] = map[string]any{"msgtype": "m.text", "body": "tampered"}
	sendTxn(pdu)
	if e, _ := getEvent(a.db, id); e == nil || strings.Contains(string(e.Content), "tampered") {
		t.Errorf("tampered event: %v", e)
	}

	// 2. signature from the wrong key: refused
	pdu, id = build(bid, map[string]any{"msgtype": "m.text", "body": "forged"})
	evil, _ := loadSigningKey(newTestServer(t).db)
	evil.id = b.fedKey.id
	red := without(redactPDU(r, pdu), "signatures", "unsigned")
	signJSON(red, b.cfg.ServerName, evil)
	pdu["signatures"] = red["signatures"]
	res := sendTxn(pdu)
	if _, _, ok := haveEvent(a.db, id); ok {
		t.Error("event with a forged signature was stored")
	}
	if e, _ := res[id].(map[string]any); e["error"] == nil {
		t.Errorf("no error reported for the forged event: %v", res)
	}

	// 3. B speaking for a user of A: signed by B, but A's user must be signed by A
	pdu, id = build(aid, map[string]any{"msgtype": "m.text", "body": "impostor"})
	sendTxn(pdu)
	if _, _, ok := haveEvent(a.db, id); ok {
		t.Error("B could send as alice")
	}

	// 4. a send_join for a user of another server is refused
	var tmpl map[string]any
	err := b.fedRequest(context.Background(), "GET", A, "/_matrix/federation/v1/make_join/"+pathEscape(room)+"/"+pathEscape("@x:"+A)+"?ver=10&ver=11", nil, &tmpl)
	var fe *fedError
	if !errors.As(err, &fe) || fe.status != 403 {
		t.Errorf("make_join for another server's user: %v", err)
	}

	// 5. events of a room the sender isn't allowed in (ACL) are refused
	alice.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/state/m.room.server_acl/", map[string]any{"allow": []any{"*"}, "deny": []any{"127.0.0.1"}})
	pdu, id = build(bid, map[string]any{"msgtype": "m.text", "body": "after acl"})
	sendTxn(pdu)
	if _, _, ok := haveEvent(a.db, id); ok {
		t.Error("event from an ACL-banned server was stored")
	}
}

func TestJoinPublicRoomByAlias(t *testing.T) {
	a, b, ha, hb := fedPair(t)
	aid, at := addUser(t, a, "alice")
	bid, bt := addUser(t, b, "bob")
	alice, bob := fedUser{a, ha, aid, at}, fedUser{b, hb, bid, bt}
	code, res := alice.do(t, "POST", "/_matrix/client/v3/createRoom", map[string]any{"preset": "public_chat", "room_alias_name": "lobby"})
	if code != 200 {
		t.Fatal(code, res)
	}
	room := res["room_id"].(string)
	m0 := alice.send(t, room, "before bob")
	code, res = bob.do(t, "POST", "/_matrix/client/v3/join/"+pathEscape("#lobby:"+a.cfg.ServerName), map[string]any{})
	if code != 200 || res["room_id"] != room {
		t.Fatalf("join by alias: %d %v", code, res)
	}
	// history from before the join is fetched from A when bob scrolls up
	code, hist := bob.do(t, "GET", "/_matrix/client/v3/rooms/"+room+"/messages?dir=b&limit=30", nil)
	found := false
	for _, e := range hist["chunk"].([]any) {
		if e.(map[string]any)["event_id"] == m0 {
			found = true
		}
	}
	if code != 200 || !found {
		t.Fatalf("history from before the join not backfilled: %d %v", code, hist)
	}
	var st int64
	b.db.QueryRow("SELECT stream FROM events WHERE event_id = ?", m0).Scan(&st)
	if st >= 0 {
		t.Errorf("backfilled event at stream %d, want below 0", st)
	}
	// paging further back ends at the room's creation without errors
	end, _ := hist["end"].(string)
	for i := 0; end != "" && i < 5; i++ {
		code, more := bob.do(t, "GET", "/_matrix/client/v3/rooms/"+room+"/messages?dir=b&limit=30&from="+end, nil)
		if code != 200 {
			t.Fatalf("paging back: %d %v", code, more)
		}
		end, _ = more["end"].(string)
	}
	// backfilled history isn't news: an incremental sync doesn't show it
	_, sync := bob.do(t, "GET", "/_matrix/client/v3/sync", nil)
	_, sync = bob.do(t, "GET", "/_matrix/client/v3/sync?timeout=0&since="+sync["next_batch"].(string), nil)
	if strings.Contains(mustJSON(sync), m0) {
		t.Error("backfilled event showed up in sync")
	}
	m1 := alice.send(t, room, "welcome")
	waitFor(t, "message after join", func() bool { return hasEvent(b, m1) })
	// bob leaves: alice's server sees it
	if code, _ := bob.do(t, "POST", "/_matrix/client/v3/rooms/"+room+"/leave", map[string]any{}); code != 200 {
		t.Fatal("leave")
	}
	waitFor(t, "leave on A", func() bool { m, _ := getMembership(a.db, room, bid); return m == "leave" })
	// and can join again
	if code, res := bob.do(t, "POST", "/_matrix/client/v3/join/"+room, map[string]any{}); code != 200 {
		t.Fatalf("rejoin: %d %v", code, res)
	}
	assertSameState(t, a, b, room)
}

func TestDeclineRemoteInvite(t *testing.T) {
	a, b, ha, hb := fedPair(t)
	aid, at := addUser(t, a, "alice")
	bid, bt := addUser(t, b, "bob")
	alice, bob := fedUser{a, ha, aid, at}, fedUser{b, hb, bid, bt}
	_, res := alice.do(t, "POST", "/_matrix/client/v3/createRoom", map[string]any{"invite": []string{bid}, "is_direct": true})
	room := res["room_id"].(string)
	if m, _ := getMembership(b.db, room, bid); m != "invite" {
		t.Fatalf("createRoom didn't invite bob remotely: %q", m)
	}
	if code, res := bob.do(t, "POST", "/_matrix/client/v3/rooms/"+room+"/leave", map[string]any{}); code != 200 {
		t.Fatalf("decline: %d %v", code, res)
	}
	if m, _ := getMembership(b.db, room, bid); m != "leave" {
		t.Errorf("bob's server: %q", m)
	}
	waitFor(t, "decline on A", func() bool { m, _ := getMembership(a.db, room, bid); return m == "leave" })
}

func TestThreeServers(t *testing.T) {
	ss, hs := fedServers(t, 3)
	var u []fedUser
	for i, name := range []string{"alice", "bob", "carol"} {
		id, tok := addUser(t, ss[i], name)
		u = append(u, fedUser{ss[i], hs[i], id, tok})
	}
	alice, bob, carol := u[0], u[1], u[2]
	code, res := alice.do(t, "POST", "/_matrix/client/v3/createRoom", map[string]any{"preset": "public_chat"})
	if code != 200 {
		t.Fatal(code, res)
	}
	room := res["room_id"].(string)
	for _, x := range []fedUser{bob, carol} {
		if code, res := x.do(t, "POST", "/_matrix/client/v3/join/"+room, map[string]any{}); code != 200 {
			t.Fatalf("%s join: %d %v", x.id, code, res)
		}
	}
	// carol joined through A: A passes her join on to B
	waitFor(t, "carol's join on B", func() bool { m, _ := getMembership(bob.s.db, room, carol.id); return m == "join" })
	// C talks to B directly
	mc := carol.send(t, room, "from C")
	waitFor(t, "C's message on A and B", func() bool { return hasEvent(alice.s, mc) && hasEvent(bob.s, mc) })
	mb := bob.send(t, room, "from B")
	waitFor(t, "B's message on C", func() bool { return hasEvent(carol.s, mb) })
	// typing and read receipts travel as EDUs
	bob.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/typing/"+bob.id, map[string]any{"typing": true, "timeout": 30000})
	waitFor(t, "typing on C", func() bool {
		carol.s.tmu.Lock()
		defer carol.s.tmu.Unlock()
		_, ok := carol.s.typing[room][bob.id]
		return ok
	})
	carol.do(t, "POST", "/_matrix/client/v3/rooms/"+room+"/receipt/m.read/"+mb, map[string]any{})
	waitFor(t, "receipt on B", func() bool {
		var e string
		bob.s.db.QueryRow("SELECT event_id FROM receipts WHERE room_id = ? AND user_id = ?", room, carol.id).Scan(&e)
		return e == mb
	})
	waitFor(t, "same state everywhere", func() bool {
		ga, _ := loadStateGroup(alice.s.db, currentStateGroup(alice.s.db, room))
		gb, _ := loadStateGroup(bob.s.db, currentStateGroup(bob.s.db, room))
		gc, _ := loadStateGroup(carol.s.db, currentStateGroup(carol.s.db, room))
		return len(ga) == len(gb) && len(gb) == len(gc) && len(ga) > 0
	})
	assertSameState(t, alice.s, bob.s, room)
	assertSameState(t, bob.s, carol.s, room)
}

func TestHistoryHiddenFromLaterServers(t *testing.T) {
	a, b, ha, hb := fedPair(t)
	aid, at := addUser(t, a, "alice")
	bid, bt := addUser(t, b, "bob")
	alice, bob := fedUser{a, ha, aid, at}, fedUser{b, hb, bid, bt}
	_, res := alice.do(t, "POST", "/_matrix/client/v3/createRoom", map[string]any{"preset": "public_chat"})
	room := res["room_id"].(string)
	alice.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/state/m.room.history_visibility/", map[string]any{"history_visibility": "joined"})
	secret := alice.send(t, room, "before bob arrived")
	if code, res := bob.do(t, "POST", "/_matrix/client/v3/join/"+room, map[string]any{}); code != 200 {
		t.Fatal(code, res)
	}
	var got struct {
		PDUs []map[string]any `json:"pdus"`
	}
	if err := b.fedRequest(context.Background(), "GET", a.cfg.ServerName, "/_matrix/federation/v1/event/"+pathEscape(secret), nil, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.PDUs) != 1 || len(got.PDUs[0]["content"].(map[string]any)) != 0 {
		t.Errorf("message from before bob's server joined was served unredacted: %v", got.PDUs)
	}
	after := alice.send(t, room, "after")
	waitFor(t, "new message", func() bool { return hasEvent(b, after) })
	if e, _ := getEvent(b.db, after); e == nil || !strings.Contains(string(e.Content), "after") {
		t.Error("new message should arrive in full")
	}
}
