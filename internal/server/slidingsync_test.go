package server

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func ssDo(t *testing.T, h http.Handler, token, pos string, timeout int, body map[string]any) (int, map[string]any) {
	t.Helper()
	q := url.Values{"timeout": {fmt.Sprint(timeout)}}
	if pos != "" {
		q.Set("pos", pos)
	}
	return do(t, h, "POST", slidingSyncPath+"?"+q.Encode(), token, body)
}

func ssRooms(out map[string]any) map[string]any {
	r, _ := out["rooms"].(map[string]any)
	return r
}

func ssTimeline(room any) []any {
	tl, _ := room.(map[string]any)["timeline"].([]any)
	return tl
}

func send(t *testing.T, h http.Handler, token, room, txn, body string) string {
	t.Helper()
	code, out := do(t, h, "PUT", "/_matrix/client/v3/rooms/"+room+"/send/m.room.message/"+txn, token,
		map[string]any{"msgtype": "m.text", "body": body})
	if code != 200 {
		t.Fatalf("send: %d %v", code, out)
	}
	return out["event_id"].(string)
}

var roomListReq = map[string]any{
	"conn_id": "room-list",
	"lists": map[string]any{"all": map[string]any{
		"ranges":         [][]int{{0, 1}},
		"timeline_limit": 2,
		"required_state": [][]string{{"m.room.name", ""}, {"m.room.member", "$LAZY"}, {"m.room.create", ""}},
	}},
	"extensions": map[string]any{
		"account_data": map[string]any{"enabled": true},
		"receipts":     map[string]any{"enabled": true},
		"typing":       map[string]any{"enabled": true},
	},
}

func TestSlidingSync(t *testing.T) {
	s := newTestServer(t)
	h := s.routes()
	_, at := addUser(t, s, "alice")
	_, bt := addUser(t, s, "bob")

	if _, v := do(t, h, "GET", "/_matrix/client/versions", "", nil); v["unstable_features"].(map[string]any)["org.matrix.simplified_msc3575"] != true {
		t.Fatal("versions doesn't announce sliding sync")
	}

	// three rooms; the one with the newest message comes first
	var rooms []string
	for i := range 3 {
		_, r := do(t, h, "POST", "/_matrix/client/v3/createRoom", at, map[string]any{"name": fmt.Sprintf("room %d", i)})
		rooms = append(rooms, r["room_id"].(string))
	}
	do(t, h, "POST", "/_matrix/client/v3/rooms/"+rooms[0]+"/invite", at, map[string]any{"user_id": "@bob:test.local"})
	do(t, h, "POST", "/_matrix/client/v3/join/"+rooms[0], bt, map[string]any{})
	send(t, h, bt, rooms[0], "b1", "hello alice")
	send(t, h, at, rooms[1], "a1", "note to self")
	do(t, h, "PUT", "/_matrix/client/v3/user/@alice:test.local/account_data/x.global", at, map[string]any{"a": 1})

	code, out := ssDo(t, h, at, "", 0, roomListReq)
	if code != 200 {
		t.Fatalf("first sync: %d %v", code, out)
	}
	pos := out["pos"].(string)
	if n := out["lists"].(map[string]any)["all"].(map[string]any)["count"]; n != float64(3) {
		t.Fatalf("count = %v", n)
	}
	got := ssRooms(out)
	if len(got) != 2 || got[rooms[1]] == nil || got[rooms[0]] == nil {
		t.Fatalf("want the two most recent rooms, got %v", got)
	}
	r0 := got[rooms[0]].(map[string]any)
	if r0["initial"] != true || r0["name"] != "room 0" || r0["limited"] != true || len(ssTimeline(r0)) != 2 {
		t.Fatalf("room 0: %v", r0)
	}
	if r0["notification_count"] != float64(1) || r0["joined_count"] != float64(2) {
		t.Fatalf("room 0 counts: %v", r0)
	}
	if got[rooms[1]].(map[string]any)["bump_stamp"].(float64) <= r0["bump_stamp"].(float64) {
		t.Fatal("bump_stamp order")
	}
	// required_state: name, create, and the members who sent timeline events
	types := map[string]bool{}
	for _, e := range r0["required_state"].([]any) {
		ev := e.(map[string]any)
		types[ev["type"].(string)+"|"+ev["state_key"].(string)] = true
	}
	if !types["m.room.name|"] || !types["m.room.create|"] || !types["m.room.member|@bob:test.local"] || types["m.room.power_levels|"] {
		t.Fatalf("required_state: %v", types)
	}
	ext := out["extensions"].(map[string]any)
	if g := ext["account_data"].(map[string]any)["global"].([]any); len(g) == 0 {
		t.Fatal("global account data missing on the first sync")
	}

	// nothing new: a long poll times out with no rooms
	start := time.Now()
	_, out = ssDo(t, h, at, pos, 200, roomListReq)
	if len(ssRooms(out)) != 0 || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("expected an empty long poll, got %v", out)
	}
	pos = out["pos"].(string)

	// a new message wakes the long poll and only that room comes back
	done := make(chan map[string]any)
	go func() {
		_, out := ssDo(t, h, at, pos, 5000, roomListReq)
		done <- out
	}()
	time.Sleep(100 * time.Millisecond)
	ev := send(t, h, bt, rooms[0], "b2", "again")
	select {
	case out = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("long poll didn't wake up")
	}
	got = ssRooms(out)
	r0 = got[rooms[0]].(map[string]any)
	if len(got) != 1 || r0["initial"] != nil || len(ssTimeline(r0)) != 1 || r0["num_live"] != float64(1) ||
		r0["notification_count"] != float64(2) {
		t.Fatalf("incremental: %v", got)
	}
	pos2 := out["pos"].(string)

	// retrying the same pos gives the same rooms again
	_, again := ssDo(t, h, at, pos, 0, roomListReq)
	if len(ssRooms(again)) != 1 {
		t.Fatalf("retry: %v", again)
	}

	// reading the room: count goes to 0, receipt shows up
	do(t, h, "POST", "/_matrix/client/v3/rooms/"+rooms[0]+"/receipt/m.read/"+url.PathEscape(ev), at, map[string]any{})
	_, out = ssDo(t, h, at, pos2, 1000, roomListReq)
	r0, _ = ssRooms(out)[rooms[0]].(map[string]any)
	if r0 == nil || r0["notification_count"] != float64(0) {
		t.Fatalf("after reading: %v", out)
	}
	if rc := out["extensions"].(map[string]any)["receipts"].(map[string]any)["rooms"].(map[string]any); rc[rooms[0]] == nil {
		t.Fatalf("receipt missing: %v", out["extensions"])
	}
	pos = out["pos"].(string)

	// typing
	do(t, h, "PUT", "/_matrix/client/v3/rooms/"+rooms[0]+"/typing/@bob:test.local", bt, map[string]any{"typing": true, "timeout": 10000})
	_, out = ssDo(t, h, at, pos, 1000, roomListReq)
	ty := out["extensions"].(map[string]any)["typing"].(map[string]any)["rooms"].(map[string]any)
	if ty[rooms[0]] == nil {
		t.Fatalf("typing missing: %v", out["extensions"])
	}
	pos = out["pos"].(string)

	// an invite shows up with its preview
	_, dm := do(t, h, "POST", "/_matrix/client/v3/createRoom", bt, map[string]any{"invite": []string{"@alice:test.local"}, "is_direct": true})
	dmRoom := dm["room_id"].(string)
	_, out = ssDo(t, h, at, pos, 1000, roomListReq)
	inv, _ := ssRooms(out)[dmRoom].(map[string]any)
	if inv == nil || inv["invite_state"] == nil || inv["timeline"] != nil {
		t.Fatalf("invite: %v", ssRooms(out))
	}
	// stripped events only (no event_id), and the invite says it's a DM
	direct := false
	for _, e := range inv["invite_state"].([]any) {
		ev := e.(map[string]any)
		if ev["event_id"] != nil {
			t.Fatalf("invite_state event with an event_id: %v", ev)
		}
		if ev["state_key"] == "@alice:test.local" && ev["content"].(map[string]any)["is_direct"] == true {
			direct = true
		}
	}
	if !direct {
		t.Fatal("invite isn't marked as direct")
	}
	pos = out["pos"].(string)

	// list filters: invites only
	req := map[string]any{"conn_id": "invites", "lists": map[string]any{"inv": map[string]any{
		"ranges": [][]int{{0, 9}}, "timeline_limit": 1, "filters": map[string]any{"is_invite": true}}}}
	_, out = ssDo(t, h, at, "", 0, req)
	if n := out["lists"].(map[string]any)["inv"].(map[string]any)["count"]; n != float64(1) {
		t.Fatalf("invite filter count: %v", n)
	}

	// leaving: the room comes back once with the leave, then drops out
	_, out = ssDo(t, h, at, pos, 0, map[string]any{"conn_id": "room-list", "room_subscriptions": map[string]any{
		rooms[2]: map[string]any{"timeline_limit": 1, "required_state": [][]string{{"m.room.member", "$ME"}}}}})
	pos = out["pos"].(string)
	do(t, h, "POST", "/_matrix/client/v3/rooms/"+rooms[2]+"/leave", at, map[string]any{})
	_, out = ssDo(t, h, at, pos, 1000, roomListReq)
	left, _ := ssRooms(out)[rooms[2]].(map[string]any)
	if left == nil || len(ssTimeline(left)) != 1 {
		t.Fatalf("leave: %v", ssRooms(out))
	}
	if c := ssTimeline(left)[0].(map[string]any)["content"].(map[string]any)["membership"]; c != "leave" {
		t.Fatalf("leave event: %v", left)
	}
	if left["name"] != nil || left["joined_count"] != nil || left["heroes"] != nil {
		t.Fatalf("left room shows how it is now: %v", left)
	}
	_, out = ssDo(t, h, at, out["pos"].(string), 0, roomListReq)
	if n := out["lists"].(map[string]any)["all"].(map[string]any)["count"]; n != float64(3) { // 2 joined + the invite
		t.Fatalf("count after leave: %v", n)
	}

	// subscriptions to rooms you're not in are ignored
	_, other := do(t, h, "POST", "/_matrix/client/v3/createRoom", bt, map[string]any{})
	_, out = ssDo(t, h, at, "", 0, map[string]any{"conn_id": "x", "room_subscriptions": map[string]any{
		other["room_id"].(string): map[string]any{"timeline_limit": 10}}})
	if len(ssRooms(out)) != 0 {
		t.Fatalf("got a room alice isn't in: %v", ssRooms(out))
	}

	// unknown pos
	if code, out := ssDo(t, h, at, "nope", 0, roomListReq); code != 400 || out["errcode"] != "M_UNKNOWN_POS" {
		t.Fatalf("unknown pos: %d %v", code, out)
	}
	// someone else's pos is unknown too
	if code, _ := ssDo(t, h, bt, pos2, 0, roomListReq); code != 400 {
		t.Fatalf("bob used alice's pos: %d", code)
	}
}

func TestSlidingSyncEncryption(t *testing.T) {
	s := newTestServer(t)
	h := s.routes()
	_, at := addUser(t, s, "alice")
	_, bt := addUser(t, s, "bob")
	var dev string
	s.db.QueryRow("SELECT device_id FROM devices WHERE access_token = ?", at).Scan(&dev)

	req := map[string]any{"conn_id": "encryption", "extensions": map[string]any{
		"to_device": map[string]any{"enabled": true}, "e2ee": map[string]any{"enabled": true}}}
	_, out := ssDo(t, h, at, "", 0, req)
	pos := out["pos"].(string)
	td := out["extensions"].(map[string]any)["to_device"].(map[string]any)
	since := td["next_batch"].(string)

	do(t, h, "PUT", "/_matrix/client/v3/sendToDevice/m.test/t1", bt, map[string]any{
		"messages": map[string]any{"@alice:test.local": map[string]any{dev: map[string]any{"n": 1}}}})
	req["extensions"].(map[string]any)["to_device"] = map[string]any{"enabled": true, "since": since}
	_, out = ssDo(t, h, at, pos, 1000, req)
	td = out["extensions"].(map[string]any)["to_device"].(map[string]any)
	if evs := td["events"].([]any); len(evs) != 1 {
		t.Fatalf("to-device: %v", td)
	}
	since, pos = td["next_batch"].(string), out["pos"].(string)

	// acknowledged with since: gone
	req["extensions"].(map[string]any)["to_device"] = map[string]any{"enabled": true, "since": since}
	_, out = ssDo(t, h, at, pos, 0, req)
	if evs := out["extensions"].(map[string]any)["to_device"].(map[string]any)["events"].([]any); len(evs) != 0 {
		t.Fatalf("to-device redelivered: %v", evs)
	}
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM to_device WHERE user_id = '@alice:test.local'").Scan(&n)
	if n != 0 {
		t.Fatalf("%d to-device messages left", n)
	}

	// one-time key counts
	do(t, h, "POST", "/_matrix/client/v3/keys/upload", at, map[string]any{"one_time_keys": map[string]any{
		"signed_curve25519:AAAA": map[string]any{"key": "x"}}})
	_, out = ssDo(t, h, at, out["pos"].(string), 1000, req)
	e2ee := out["extensions"].(map[string]any)["e2ee"].(map[string]any)
	if c := e2ee["device_one_time_keys_count"].(map[string]any)["signed_curve25519"]; c != float64(1) {
		t.Fatalf("otk count: %v", e2ee)
	}
}

func TestSlidingSyncConnLimits(t *testing.T) {
	var st ssStore
	for i := range ssMaxPerUser + 5 {
		st.add(fmt.Sprintf("@a:x\x00DEV\x00c%d", i), &ssSnap{}, false)
	}
	st.add("@b:x\x00DEV\x00c", &ssSnap{}, false)
	mine := 0
	for k := range st.conns {
		if k[:4] == "@a:x" {
			mine++
		}
	}
	if mine != ssMaxPerUser || st.conns["@b:x\x00DEV\x00c"] == nil {
		t.Fatalf("alice has %d connections, bob's: %v", mine, st.conns["@b:x\x00DEV\x00c"] != nil)
	}
	// the newest ones are kept
	if st.conns[fmt.Sprintf("@a:x\x00DEV\x00c%d", ssMaxPerUser+4)] == nil || st.conns["@a:x\x00DEV\x00c0"] != nil {
		t.Fatal("evicted the wrong connection")
	}
}

func TestSlidingSyncNewConnectionDeviceLists(t *testing.T) {
	s := newTestServer(t)
	h := s.routes()
	_, at := addUser(t, s, "alice")
	_, bt := addUser(t, s, "bob")
	_, r := do(t, h, "POST", "/_matrix/client/v3/createRoom", at, map[string]any{"invite": []string{"@bob:test.local"}})
	do(t, h, "POST", "/_matrix/client/v3/join/"+r["room_id"].(string), bt, map[string]any{})
	_, out := ssDo(t, h, at, "", 0, map[string]any{"conn_id": "encryption", "extensions": map[string]any{"e2ee": map[string]any{"enabled": true}}})
	changed := out["extensions"].(map[string]any)["e2ee"].(map[string]any)["device_lists"].(map[string]any)["changed"].([]any)
	if len(changed) != 2 {
		t.Fatalf("a new connection should re-check everyone's devices: %v", changed)
	}
}
