package server

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestMigrateOldDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	// tables as the first release created them
	for _, q := range []string{
		`CREATE TABLE users (user_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL, displayname TEXT, avatar_url TEXT,
			is_admin INTEGER NOT NULL DEFAULT 0, created_ts INTEGER NOT NULL)`,
		`CREATE TABLE rooms (room_id TEXT PRIMARY KEY, version TEXT NOT NULL, creator TEXT NOT NULL,
			published INTEGER NOT NULL DEFAULT 0, created_ts INTEGER NOT NULL)`,
		`INSERT INTO users VALUES ('@old:test.local', 'x', 'Old', NULL, 0, 1)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s, err := newServer(&Config{ServerName: "test.local", Database: path, MediaDir: filepath.Join(dir, "m"), MaxUploadBytes: 1 << 20})
	if err != nil {
		t.Fatalf("server on old database: %v", err)
	}
	defer s.db.Close()
	var deact, blocked int
	if err := s.db.QueryRow("SELECT deactivated FROM users WHERE user_id = '@old:test.local'").Scan(&deact); err != nil {
		t.Fatalf("users.deactivated missing: %v", err)
	}
	if err := s.db.QueryRow("SELECT COUNT(blocked) FROM rooms").Scan(&blocked); err != nil {
		t.Fatalf("rooms.blocked missing: %v", err)
	}
	// running again is a no-op
	if err := migrate(s.db); err != nil {
		t.Fatal(err)
	}
}

func adminServer(t *testing.T) *Server {
	s := newTestServer(t)
	s.passwordRedactDelay = 150 * time.Millisecond
	s.startAdminBot()
	if err := s.ensureAdminRoom(); err != nil {
		t.Fatal(err)
	}
	return s
}

func mustAdmin(t *testing.T, s *Server, actor string, cmd string) string {
	t.Helper()
	out, err := s.runAdmin(actor, strings.Fields(cmd))
	if err != nil {
		t.Fatalf("%q: %v", cmd, err)
	}
	return out
}

func TestAdminUserCommands(t *testing.T) {
	s := adminServer(t)
	h := s.routes()
	_, at := addUser(t, s, "alice")
	bob, bt := addUser(t, s, "bob")
	_, r := do(t, h, "POST", "/_matrix/client/v3/createRoom", at, map[string]any{"preset": "public_chat"})
	room := r["room_id"].(string)
	do(t, h, "POST", "/_matrix/client/v3/join/"+room, bt, map[string]any{})

	if out := mustAdmin(t, s, "cli", "users list"); !strings.Contains(out, bob) || strings.Contains(out, s.botID()) {
		t.Fatalf("users list:\n%s", out)
	}
	if out := mustAdmin(t, s, "cli", "users info bob"); !strings.Contains(out, "joined rooms: 1") {
		t.Fatalf("users info:\n%s", out)
	}
	if _, err := s.runAdmin("cli", strings.Fields("users info nobody")); err == nil {
		t.Fatal("info on a missing user succeeded")
	}
	if _, err := s.runAdmin("cli", strings.Fields("users frobnicate")); err == nil {
		t.Fatal("unknown command succeeded")
	}
	if out := mustAdmin(t, s, "cli", "help"); !strings.Contains(out, "users deactivate") {
		t.Fatal("help incomplete")
	}

	// create prints a working password
	out := mustAdmin(t, s, "cli", "users create carol")
	pw := strings.TrimSpace(strings.SplitN(strings.SplitN(out, "password: ", 2)[1], "\n", 2)[0])
	st, _ := do(t, h, "POST", "/_matrix/client/v3/login", "", map[string]any{"type": "m.login.password",
		"identifier": map[string]any{"type": "m.id.user", "user": "carol"}, "password": pw})
	if st != 200 {
		t.Fatalf("created user can't log in (%d)", st)
	}
	if _, err := s.runAdmin("cli", strings.Fields("users create renka")); err == nil {
		t.Fatal("the bot's name could be taken")
	}

	// reset-password logs everyone out
	out = mustAdmin(t, s, "cli", "users reset-password bob")
	if st, _ := do(t, h, "GET", "/_matrix/client/v3/account/whoami", bt, nil); st != 401 {
		t.Fatalf("old session survived a password reset (%d)", st)
	}
	pw = strings.TrimSpace(strings.SplitN(strings.SplitN(out, ": ", 2)[1], "\n", 2)[0])
	_, b := do(t, h, "POST", "/_matrix/client/v3/login", "", map[string]any{"type": "m.login.password",
		"identifier": map[string]any{"type": "m.id.user", "user": "bob"}, "password": pw})
	bt, _ = b["access_token"].(string)
	if bt == "" {
		t.Fatal("reset password doesn't work")
	}

	// deactivate: out of everything, for good
	out = mustAdmin(t, s, "cli", "users deactivate bob")
	if !strings.Contains(out, "left 1 room") {
		t.Fatalf("deactivate:\n%s", out)
	}
	if st, _ := do(t, h, "GET", "/_matrix/client/v3/account/whoami", bt, nil); st != 401 {
		t.Fatal("deactivated user's token still works")
	}
	if st, _ := do(t, h, "POST", "/_matrix/client/v3/login", "", map[string]any{"type": "m.login.password",
		"identifier": map[string]any{"type": "m.id.user", "user": "bob"}, "password": pw}); st != 403 {
		t.Fatal("deactivated user can log in")
	}
	if m, _ := getMembership(s.db, room, bob); m != "leave" {
		t.Fatalf("deactivated user still %s in room", m)
	}
	if st, _ := do(t, h, "POST", "/_matrix/client/v3/rooms/"+room+"/invite", at, map[string]any{"user_id": bob}); st != 404 {
		t.Fatalf("deactivated user can be invited (%d)", st)
	}
	s.cfg.SearchAllUsers = true
	_, b = do(t, h, "POST", "/_matrix/client/v3/user_directory/search", at, map[string]any{"search_term": "bob"})
	if len(b["results"].([]any)) != 0 {
		t.Fatal("deactivated user still in search")
	}
	if err := s.createUser("bob", "password123", false); err == nil {
		t.Fatal("deactivated name could be registered again")
	}
	if _, err := s.runAdmin("@alice:test.local", strings.Fields("users deactivate alice")); err == nil {
		t.Fatal("admin deactivated themselves")
	}
}

func TestAdminRoomCommands(t *testing.T) {
	s := adminServer(t)
	h := s.routes()
	_, at := addUser(t, s, "alice")
	_, bt := addUser(t, s, "bob")
	_, r := do(t, h, "POST", "/_matrix/client/v3/createRoom", at, map[string]any{"preset": "public_chat", "room_alias_name": "town"})
	room := r["room_id"].(string)
	do(t, h, "POST", "/_matrix/client/v3/join/"+room, bt, map[string]any{})

	if out := mustAdmin(t, s, "cli", "rooms list"); !strings.Contains(out, room) || !strings.Contains(out, "admin room") {
		t.Fatalf("rooms list:\n%s", out)
	}
	if out := mustAdmin(t, s, "cli", "rooms info #town:test.local"); !strings.Contains(out, "@bob:test.local") {
		t.Fatalf("rooms info:\n%s", out)
	}
	if _, err := s.runAdmin("cli", []string{"rooms", "shutdown", s.adminRoom()}); err == nil {
		t.Fatal("admin room could be shut down")
	}
	mustAdmin(t, s, "cli", "rooms shutdown "+room)
	if m, _ := getMembership(s.db, room, "@bob:test.local"); m != "leave" {
		t.Fatal("member still in a shut-down room")
	}
	if st, _ := do(t, h, "POST", "/_matrix/client/v3/join/"+room, bt, map[string]any{}); st != 403 {
		t.Fatalf("could rejoin a shut-down room (%d)", st)
	}
	if st, _ := do(t, h, "GET", "/_matrix/client/v3/directory/room/%23town:test.local", "", nil); st != 404 {
		t.Fatal("alias of a shut-down room still resolves")
	}
	_, b := do(t, h, "GET", "/_matrix/client/v3/publicRooms", "", nil)
	if len(b["chunk"].([]any)) != 0 {
		t.Fatal("shut-down room still listed")
	}

	// media
	up := func(tok string) string {
		_, b := do(t, h, "POST", "/_matrix/media/v3/upload", tok, []byte("hello"))
		return b["content_uri"].(string)
	}
	mxc := up(at)
	if out := mustAdmin(t, s, "cli", "media usage alice"); !strings.Contains(out, "1 file(s)") {
		t.Fatalf("media usage:\n%s", out)
	}
	mustAdmin(t, s, "cli", "media delete "+mxc)
	if st, _ := do(t, h, "GET", "/_matrix/media/v3/download/"+strings.TrimPrefix(mxc, "mxc://"), "", nil); st != 404 {
		t.Fatal("deleted media still downloadable")
	}
	if _, err := s.runAdmin("cli", strings.Fields("media delete mxc://other.org/abc")); err == nil {
		t.Fatal("deleted remote media")
	}
	if out := mustAdmin(t, s, "cli", "server stats"); !strings.Contains(out, "accounts: 2") {
		t.Fatalf("stats:\n%s", out)
	}
}

func waitBotReply(t *testing.T, s *Server, room, after string) *Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		evs, _ := queryEvents(s.db, "SELECT "+evCols+" FROM events WHERE room_id = ? AND sender = ? AND type = 'm.room.message' ORDER BY stream DESC LIMIT 1", room, s.botID())
		if len(evs) > 0 && strings.Contains(string(evs[0].Content), after) {
			return evs[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no bot reply mentioning %q", after)
	return nil
}

func TestAdminRoom(t *testing.T) {
	s := adminServer(t)
	h := s.routes()
	_, at := addUser(t, s, "alice")
	_, bt := addUser(t, s, "bob")
	room := s.adminRoom()
	if room == "" {
		t.Fatal("no admin room")
	}
	if m, _ := getMembership(s.db, room, "@alice:test.local"); m != "" {
		t.Fatal("non-admin invited")
	}
	mustAdmin(t, s, "cli", "users make-admin alice")
	if m, _ := getMembership(s.db, room, "@alice:test.local"); m != "invite" {
		t.Fatalf("new admin not invited (%q)", m)
	}
	if st, _ := do(t, h, "POST", "/_matrix/client/v3/join/"+room, bt, map[string]any{}); st != 403 {
		t.Fatal("non-admin joined the admin room")
	}
	if st, _ := do(t, h, "POST", "/_matrix/client/v3/join/"+room, at, map[string]any{}); st != 200 {
		t.Fatal("admin can't join the admin room")
	}
	say := func(txn, body string) {
		st, b := do(t, h, "PUT", "/_matrix/client/v3/rooms/"+room+"/send/m.room.message/"+txn, at, map[string]any{"msgtype": "m.text", "body": body})
		if st != 200 {
			t.Fatalf("send %q: %d %v", body, st, b)
		}
	}
	say("1", "users list")
	reply := waitBotReply(t, s, room, "@bob:test.local")
	var c map[string]any
	json.Unmarshal(reply.Content, &c)
	if c["msgtype"] != "m.notice" || !strings.Contains(c["formatted_body"].(string), "<pre><code>") {
		t.Fatalf("reply = %v", c)
	}
	say("2", "!admin server stats")
	waitBotReply(t, s, room, "accounts:")
	say("3", "nonsense command")
	waitBotReply(t, s, room, "unknown command")

	// a reply with a password is redacted soon after
	say("4", "users reset-password bob")
	pwReply := waitBotReply(t, s, room, "new password for @bob")
	deadline := time.Now().Add(5 * time.Second)
	for {
		e, _ := getEvent(s.db, pwReply.EventID)
		if e.RedactedBecause != nil && !strings.Contains(string(e.Content), "password") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("password reply not redacted")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// admins can't turn on encryption (the bot couldn't read commands) or invite others
	if st, _ := do(t, h, "PUT", "/_matrix/client/v3/rooms/"+room+"/state/m.room.encryption", at, map[string]any{"algorithm": "m.megolm.v1.aes-sha2"}); st != 403 {
		t.Fatal("admin enabled encryption in the admin room")
	}
	if st, _ := do(t, h, "POST", "/_matrix/client/v3/rooms/"+room+"/invite", at, map[string]any{"user_id": "@bob:test.local"}); st != 403 {
		t.Fatal("admin invited a non-admin")
	}

	// revoked admins are removed and can't post any more (bob was logged out
	// by the reset above, so use a fresh account)
	_, ct := addUser(t, s, "carol")
	mustAdmin(t, s, "cli", "users make-admin carol")
	if st, _ := do(t, h, "POST", "/_matrix/client/v3/join/"+room, ct, map[string]any{}); st != 200 {
		t.Fatal("carol can't join")
	}
	mustAdmin(t, s, "cli", "users revoke-admin carol")
	if m, _ := getMembership(s.db, room, "@carol:test.local"); m != "leave" {
		t.Fatalf("revoked admin still %s", m)
	}
	if st, b := do(t, h, "PUT", "/_matrix/client/v3/rooms/"+room+"/send/m.room.message/c1", ct, map[string]any{"msgtype": "m.text", "body": "users list"}); st != 403 {
		t.Fatalf("removed admin can still post: %d %v", st, b)
	}
	_ = bt
}

func TestAdminSocket(t *testing.T) {
	s := adminServer(t)
	addUser(t, s, "alice")
	if err := s.startAdminSocket(); err != nil {
		t.Fatal(err)
	}
	defer s.stopAdminSocket()
	st, err := os.Stat(adminSocketPath(s.cfg))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v err %v", st.Mode(), err)
	}
	// capture stdout of the client
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	code := cmdAdmin(s.cfg, []string{"users", "list"})
	w.Close()
	os.Stdout = old
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	if code != 0 || !strings.Contains(string(buf[:n]), "@alice:test.local") {
		t.Fatalf("cmdAdmin = %d, output %q", code, buf[:n])
	}
	devnull, _ := os.Open(os.DevNull)
	os.Stderr, devnull = devnull, os.Stderr
	code = cmdAdmin(s.cfg, []string{"users", "info", "ghost"})
	os.Stderr = devnull
	if code != 1 {
		t.Fatal("failing command exited 0")
	}
}
