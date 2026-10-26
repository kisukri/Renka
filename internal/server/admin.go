package server

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// Admin commands, from `renka admin` (unix socket, the server runs the
// command since it owns the stream counter) or from the admin room
// (bot @renka, admins only).

const (
	botLocalpart  = "renka"
	adminPrefix   = "!admin"
	maxReplyBytes = 30000
)

func (s *Server) botID() string { return "@" + botLocalpart + ":" + s.cfg.ServerName }

// adminSocketPath lives next to the database: only the renka user can reach it.
func adminSocketPath(cfg *Config) string {
	return filepath.Join(filepath.Dir(cfg.Database), "admin.sock")
}

type adminCommand struct {
	name, args, help string
	run              func(s *Server, actor string, args []string) (string, error)
}

func adminCommands() []adminCommand {
	return []adminCommand{
		{"users list", "[--admins|--deactivated]", "list accounts", cmdUsersList},
		{"users info", "USER", "show an account: devices, rooms, storage", cmdUsersInfo},
		{"users create", "NAME [--admin]", "create an account with a random password", cmdUsersCreate},
		{"users reset-password", "USER", "set a random password and log out every session", cmdUsersResetPassword},
		{"users logout", "USER", "log out every session of an account", cmdUsersLogout},
		{"users deactivate", "USER", "lock an account for good: logs out, leaves all rooms, clears the profile", cmdUsersDeactivate},
		{"users make-admin", "USER", "make an account a server admin", cmdUsersSetAdmin(true)},
		{"users revoke-admin", "USER", "remove admin rights", cmdUsersSetAdmin(false)},
		{"rooms list", "", "list rooms", cmdRoomsList},
		{"rooms info", "ROOM", "show a room's details and members", cmdRoomsInfo},
		{"rooms shutdown", "ROOM", "close a room: everyone leaves, nobody can join again, aliases removed", cmdRoomsShutdown},
		{"media usage", "[USER]", "storage used per user", cmdMediaUsage},
		{"media delete", "mxc://SERVER/ID", "delete an uploaded file and its thumbnails", cmdMediaDelete},
		{"server stats", "", "users, rooms, storage, uptime", cmdServerStats},
	}
}

func adminHelp() string {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Commands:")
	for _, c := range adminCommands() {
		fmt.Fprintf(w, "  %s %s\t%s\n", c.name, c.args, c.help)
	}
	w.Flush()
	b.WriteString("\nUSER is @name:server or just name. ROOM is a room ID or #alias.")
	return b.String()
}

// runAdmin runs one command. actor is "cli" or the admin's user ID (logged).
func (s *Server) runAdmin(actor string, args []string) (string, error) {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		return adminHelp(), nil
	}
	for _, c := range adminCommands() {
		words := strings.Fields(c.name)
		if len(args) >= len(words) && strings.EqualFold(strings.Join(args[:len(words)], " "), c.name) {
			log.Printf("admin: %s ran %q", actor, strings.Join(args, " "))
			return c.run(s, actor, args[len(words):])
		}
	}
	return "", fmt.Errorf("unknown command %q\n\n%s", strings.Join(args, " "), adminHelp())
}

// ---- argument helpers ----

func (s *Server) userArg(args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("which user? give @name:server or name")
	}
	uid := strings.ToLower(args[0])
	if !strings.HasPrefix(uid, "@") {
		uid = "@" + uid + ":" + s.cfg.ServerName
	}
	var x int
	if s.db.QueryRow("SELECT 1 FROM users WHERE user_id = ?", uid).Scan(&x) != nil {
		return "", fmt.Errorf("no such user %s", uid)
	}
	return uid, nil
}

func (s *Server) roomArg(args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("which room? give a room ID or #alias")
	}
	id, err := s.resolveRoom(s.db, args[0])
	if err != nil {
		return "", fmt.Errorf("no such room %s", args[0])
	}
	return id, nil
}

func hasFlag(args []string, f string) bool {
	for _, a := range args {
		if a == f {
			return true
		}
	}
	return false
}

func table(header []string, rows [][]string) string {
	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(header, "\t"))
	for _, r := range rows {
		fmt.Fprintln(w, strings.Join(r, "\t"))
	}
	w.Flush()
	return strings.TrimRight(b.String(), "\n")
}

func ago(ms int64) string {
	if ms == 0 {
		return "-"
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02 15:04")
}

func mb(n int64) string { return fmt.Sprintf("%.1f MB", float64(n)/(1<<20)) }

// ---- users ----

func cmdUsersList(s *Server, _ string, args []string) (string, error) {
	q := "SELECT user_id, COALESCE(displayname,''), is_admin, deactivated, created_ts FROM users WHERE user_id != ?"
	switch {
	case hasFlag(args, "--admins"):
		q += " AND is_admin = 1"
	case hasFlag(args, "--deactivated"):
		q += " AND deactivated = 1"
	}
	rows, err := s.db.Query(q+" ORDER BY created_ts", s.botID())
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var out [][]string
	for rows.Next() {
		var id, dn string
		var admin, deact int
		var created int64
		rows.Scan(&id, &dn, &admin, &deact, &created)
		flags := []string{}
		if admin == 1 {
			flags = append(flags, "admin")
		}
		if deact == 1 {
			flags = append(flags, "deactivated")
		}
		out = append(out, []string{id, dn, strings.Join(flags, ","), ago(created)})
	}
	return table([]string{"USER", "NAME", "FLAGS", "CREATED"}, out) + fmt.Sprintf("\n%d account(s)", len(out)), nil
}

func cmdUsersInfo(s *Server, _ string, args []string) (string, error) {
	uid, err := s.userArg(args)
	if err != nil {
		return "", err
	}
	var dn sql.NullString
	var admin, deact int
	var created int64
	s.db.QueryRow("SELECT displayname, is_admin, deactivated, created_ts FROM users WHERE user_id = ?", uid).Scan(&dn, &admin, &deact, &created)
	var rooms, pushers int
	s.db.QueryRow("SELECT COUNT(*) FROM memberships WHERE user_id = ? AND membership = 'join'", uid).Scan(&rooms)
	s.db.QueryRow("SELECT COUNT(*) FROM pushers WHERE user_id = ?", uid).Scan(&pushers)
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n  name: %s\n  admin: %v   deactivated: %v\n  created: %s\n  joined rooms: %d   pushers: %d\n  media: %s\n",
		uid, dn.String, admin == 1, deact == 1, ago(created), rooms, pushers, mb(s.mediaUsed(s.db, uid)))
	devs, _ := s.listDevices(uid, "")
	var rows [][]string
	for _, d := range devs {
		name, _ := d["display_name"].(string)
		ip, _ := d["last_seen_ip"].(string)
		ts, _ := d["last_seen_ts"].(int64)
		rows = append(rows, []string{d["device_id"].(string), name, ip, ago(ts)})
	}
	b.WriteString(table([]string{"DEVICE", "NAME", "LAST IP", "LAST SEEN"}, rows))
	return b.String(), nil
}

// newPassword is shown once to the admin, who passes it on.
func newPassword() string { return randString(20) }

func cmdUsersCreate(s *Server, actor string, args []string) (string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", errors.New("usage: users create NAME [--admin]")
	}
	name := strings.ToLower(strings.TrimPrefix(args[0], "@"))
	name, _, _ = strings.Cut(name, ":")
	pw := newPassword()
	if err := s.createUser(name, pw, hasFlag(args, "--admin")); err != nil {
		return "", err
	}
	uid := "@" + name + ":" + s.cfg.ServerName
	if hasFlag(args, "--admin") {
		s.syncAdminRoom()
	}
	return fmt.Sprintf("created %s\npassword: %s\n%s", uid, pw, passwordNote(actor)), nil
}

func passwordNote(actor string) string {
	if actor == "cli" {
		return "Ask them to change it after logging in."
	}
	return "Ask them to change it after logging in. This message will be redacted in 10 minutes."
}

func cmdUsersResetPassword(s *Server, actor string, args []string) (string, error) {
	uid, err := s.userArg(args)
	if err != nil {
		return "", err
	}
	if uid == s.botID() {
		return "", errors.New("the bot has no password")
	}
	pw := newPassword()
	n := 0
	err = s.write(func(tx *sql.Tx) error {
		if _, err := tx.Exec("UPDATE users SET password_hash = ? WHERE user_id = ? AND deactivated = 0", hashPassword(pw), uid); err != nil {
			return err
		}
		tx.QueryRow("SELECT COUNT(*) FROM devices WHERE user_id = ?", uid).Scan(&n)
		return s.deleteAllDevices(tx, uid, "")
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("new password for %s: %s\n%d session(s) logged out.\n%s", uid, pw, n, passwordNote(actor)), nil
}

func cmdUsersLogout(s *Server, _ string, args []string) (string, error) {
	uid, err := s.userArg(args)
	if err != nil {
		return "", err
	}
	n := 0
	err = s.write(func(tx *sql.Tx) error {
		tx.QueryRow("SELECT COUNT(*) FROM devices WHERE user_id = ?", uid).Scan(&n)
		return s.deleteAllDevices(tx, uid, "")
	})
	return fmt.Sprintf("%d session(s) of %s logged out", n, uid), err
}

func cmdUsersDeactivate(s *Server, actor string, args []string) (string, error) {
	uid, err := s.userArg(args)
	if err != nil {
		return "", err
	}
	if uid == s.botID() {
		return "", errors.New("the bot can't be deactivated")
	}
	if uid == actor {
		return "", errors.New("you can't deactivate your own account from here")
	}
	left, err := s.deactivateUser(uid)
	if err != nil {
		return "", err
	}
	s.syncAdminRoom()
	return fmt.Sprintf("%s deactivated: logged out, left %d room(s), profile cleared. The name can't be registered again.", uid, left), nil
}

// deactivateUser locks an account for good.
func (s *Server) deactivateUser(uid string) (int, error) {
	left := 0
	err := s.write(func(tx *sql.Tx) error {
		rooms, err := userRooms(tx, uid, "'join', 'invite'")
		if err != nil {
			return err
		}
		for _, room := range rooms {
			ev := s.newEvent(room, uid, "m.room.member", sp(uid), map[string]any{"membership": "leave", "reason": "account deactivated"})
			if err := s.storeEvent(tx, ev); err != nil {
				return err
			}
			left++
		}
		if err := s.deleteAllDevices(tx, uid, ""); err != nil {
			return err
		}
		for _, q := range []string{"DELETE FROM cross_signing WHERE user_id = ?", "DELETE FROM pushers WHERE user_id = ?",
			"UPDATE users SET deactivated = 1, password_hash = '!', displayname = NULL, avatar_url = NULL WHERE user_id = ?"} {
			if _, err := tx.Exec(q, uid); err != nil {
				return err
			}
		}
		return nil
	})
	return left, err
}

func userRooms(q querier, uid, memberships string) ([]string, error) {
	rows, err := q.Query("SELECT room_id FROM memberships WHERE user_id = ? AND membership IN ("+memberships+")", uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if rows.Scan(&r) == nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

func cmdUsersSetAdmin(admin bool) func(*Server, string, []string) (string, error) {
	return func(s *Server, actor string, args []string) (string, error) {
		uid, err := s.userArg(args)
		if err != nil {
			return "", err
		}
		if uid == s.botID() {
			return "", errors.New("the bot isn't an account")
		}
		if !admin && uid == actor {
			return "", errors.New("you can't remove your own admin rights from here")
		}
		v := 0
		if admin {
			v = 1
		}
		res, err := s.db.Exec("UPDATE users SET is_admin = ? WHERE user_id = ? AND deactivated = 0", v, uid)
		if err != nil {
			return "", err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return "", fmt.Errorf("%s is deactivated", uid)
		}
		s.syncAdminRoom()
		if admin {
			return uid + " is now a server admin (invited to the admin room)", nil
		}
		return uid + " is no longer a server admin", nil
	}
}

// ---- rooms ----

func cmdRoomsList(s *Server, _ string, _ []string) (string, error) {
	rows, err := s.db.Query(`SELECT r.room_id, r.published, r.blocked, r.created_ts,
		(SELECT COUNT(*) FROM memberships m WHERE m.room_id = r.room_id AND m.membership = 'join')
		FROM rooms r ORDER BY r.created_ts`)
	if err != nil {
		return "", err
	}
	type row struct {
		id              string
		pub, blocked    int
		created, joined int64
	}
	var rs []row
	for rows.Next() {
		var r row
		rows.Scan(&r.id, &r.pub, &r.blocked, &r.created, &r.joined)
		rs = append(rs, r)
	}
	rows.Close()
	var out [][]string
	for _, r := range rs {
		flags := []string{}
		if r.pub == 1 {
			flags = append(flags, "public")
		}
		if r.blocked == 1 {
			flags = append(flags, "shut down")
		}
		if r.id == s.adminRoom() {
			flags = append(flags, "admin room")
		}
		name := stateString(s.db, r.id, "m.room.name", "", "name")
		out = append(out, []string{r.id, name, fmt.Sprint(r.joined), strings.Join(flags, ","), ago(r.created)})
	}
	return table([]string{"ROOM", "NAME", "MEMBERS", "FLAGS", "CREATED"}, out) + fmt.Sprintf("\n%d room(s)", len(out)), nil
}

func cmdRoomsInfo(s *Server, _ string, args []string) (string, error) {
	room, err := s.roomArg(args)
	if err != nil {
		return "", err
	}
	var creator string
	var pub, blocked int
	var created, events int64
	s.db.QueryRow("SELECT creator, published, blocked, created_ts FROM rooms WHERE room_id = ?", room).Scan(&creator, &pub, &blocked, &created)
	s.db.QueryRow("SELECT COUNT(*) FROM events WHERE room_id = ?", room).Scan(&events)
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n  name: %s\n  topic: %s\n  alias: %s\n  creator: %s   created: %s\n  public: %v   shut down: %v   events: %d\n  encrypted: %v\n",
		room, stateString(s.db, room, "m.room.name", "", "name"), stateString(s.db, room, "m.room.topic", "", "topic"),
		stateString(s.db, room, "m.room.canonical_alias", "", "alias"), creator, ago(created), pub == 1, blocked == 1, events,
		stateString(s.db, room, "m.room.encryption", "", "algorithm") != "")
	rows, _ := s.db.Query("SELECT user_id, membership FROM memberships WHERE room_id = ? AND membership IN ('join','invite','ban') ORDER BY membership, user_id", room)
	var out [][]string
	if rows != nil {
		for rows.Next() {
			var u, m string
			rows.Scan(&u, &m)
			out = append(out, []string{u, m})
		}
		rows.Close()
	}
	b.WriteString(table([]string{"MEMBER", "STATE"}, out))
	return b.String(), nil
}

func cmdRoomsShutdown(s *Server, _ string, args []string) (string, error) {
	room, err := s.roomArg(args)
	if err != nil {
		return "", err
	}
	if room == s.adminRoom() {
		return "", errors.New("that's the admin room")
	}
	left := 0
	err = s.write(func(tx *sql.Tx) error {
		if _, err := tx.Exec("UPDATE rooms SET blocked = 1, published = 0 WHERE room_id = ?", room); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM aliases WHERE room_id = ?", room); err != nil {
			return err
		}
		rows, err := tx.Query("SELECT user_id FROM memberships WHERE room_id = ? AND membership IN ('join', 'invite')", room)
		if err != nil {
			return err
		}
		var members []string
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				members = append(members, u)
			}
		}
		rows.Close()
		for _, u := range members {
			ev := s.newEvent(room, u, "m.room.member", sp(u), map[string]any{"membership": "leave", "reason": "room shut down by the server admin"})
			if err := s.storeEvent(tx, ev); err != nil {
				return err
			}
			left++
		}
		return nil
	})
	return fmt.Sprintf("%s shut down: %d member(s) removed, aliases deleted, no one can join again", room, left), err
}

// ---- media ----

func cmdMediaUsage(s *Server, _ string, args []string) (string, error) {
	if len(args) > 0 {
		uid, err := s.userArg(args)
		if err != nil {
			return "", err
		}
		var n int
		s.db.QueryRow("SELECT COUNT(*) FROM media WHERE uploader = ?", uid).Scan(&n)
		quota := "unlimited"
		if s.cfg.MediaQuotaBytes > 0 {
			quota = mb(s.cfg.MediaQuotaBytes)
		}
		return fmt.Sprintf("%s: %d file(s), %s (quota %s)", uid, n, mb(s.mediaUsed(s.db, uid)), quota), nil
	}
	rows, err := s.db.Query("SELECT uploader, COUNT(*), SUM(size) FROM media GROUP BY uploader ORDER BY SUM(size) DESC LIMIT 50")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var out [][]string
	var total int64
	for rows.Next() {
		var u string
		var n int
		var size int64
		rows.Scan(&u, &n, &size)
		total += size
		out = append(out, []string{u, fmt.Sprint(n), mb(size)})
	}
	return table([]string{"USER", "FILES", "SIZE"}, out) + "\ntotal: " + mb(total), nil
}

func cmdMediaDelete(s *Server, _ string, args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("usage: media delete mxc://SERVER/ID")
	}
	rest, ok := strings.CutPrefix(args[0], "mxc://")
	server, id, ok2 := strings.Cut(rest, "/")
	if !ok || !ok2 || server != s.cfg.ServerName || !mediaIDRe.MatchString(id) {
		return "", errors.New("give a local media URI like mxc://" + s.cfg.ServerName + "/abc")
	}
	var size int64
	if s.db.QueryRow("SELECT size FROM media WHERE media_id = ?", id).Scan(&size) != nil {
		return "", errors.New("no such media")
	}
	if _, err := s.db.Exec("DELETE FROM media WHERE media_id = ?", id); err != nil {
		return "", err
	}
	os.Remove(filepath.Join(s.cfg.MediaDir, id))
	thumbs, _ := filepath.Glob(filepath.Join(s.cfg.MediaDir, "thumbs", id+"-*"))
	for _, t := range thumbs {
		os.Remove(t)
	}
	return fmt.Sprintf("deleted %s (%s, %d thumbnail(s))", args[0], mb(size), len(thumbs)), nil
}

// ---- server ----

func cmdServerStats(s *Server, _ string, _ []string) (string, error) {
	var users, admins, deact, rooms, events, files, pushers, devices int64
	var media int64
	s.db.QueryRow("SELECT COUNT(*), COALESCE(SUM(is_admin),0), COALESCE(SUM(deactivated),0) FROM users WHERE user_id != ?", s.botID()).Scan(&users, &admins, &deact)
	s.db.QueryRow("SELECT COUNT(*) FROM rooms").Scan(&rooms)
	s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&events)
	s.db.QueryRow("SELECT COUNT(*), COALESCE(SUM(size),0) FROM media").Scan(&files, &media)
	s.db.QueryRow("SELECT COUNT(*) FROM pushers").Scan(&pushers)
	s.db.QueryRow("SELECT COUNT(*) FROM devices").Scan(&devices)
	var dbSize int64
	for _, suffix := range []string{"", "-wal"} {
		if st, err := os.Stat(s.cfg.Database + suffix); err == nil {
			dbSize += st.Size()
		}
	}
	return fmt.Sprintf("renka %s on %s, up %s\n  accounts: %d (%d admin, %d deactivated)   sessions: %d   pushers: %d\n  rooms: %d   events: %d\n  database: %s   media: %d file(s), %s",
		version, s.cfg.ServerName, time.Since(s.started).Round(time.Second), users, admins, deact, devices, pushers,
		rooms, events, mb(dbSize), files, mb(media)), nil
}

// ---- unix socket for `renka admin` ----

type adminRequest struct {
	Args []string `json:"args"`
}
type adminResponse struct {
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

// startAdminSocket: socket is 0600, and we check the peer uid too.
func (s *Server) startAdminSocket() error {
	path := adminSocketPath(s.cfg)
	os.Remove(path) // left over from an unclean stop
	old := umask(0o177)
	ln, err := net.Listen("unix", path)
	umask(old)
	if err != nil {
		return err
	}
	os.Chmod(path, 0o600)
	s.adminLn = ln
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveAdminConn(conn)
		}
	}()
	return nil
}

func (s *Server) stopAdminSocket() {
	if s.adminLn != nil {
		s.adminLn.Close()
		os.Remove(adminSocketPath(s.cfg))
	}
}

func (s *Server) serveAdminConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Minute))
	enc := json.NewEncoder(conn)
	if !peerAllowed(conn) {
		enc.Encode(adminResponse{Error: "permission denied: run this as the user renka runs as, or root"})
		return
	}
	var req adminRequest
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		enc.Encode(adminResponse{Error: "bad request"})
		return
	}
	out, err := s.runAdmin("cli", req.Args)
	resp := adminResponse{Output: out}
	if err != nil {
		resp.Error = err.Error()
	}
	enc.Encode(resp)
}

// cmdAdmin is `renka admin [-config f] COMMAND...`.
func cmdAdmin(cfg *Config, args []string) int {
	conn, err := net.DialTimeout("unix", adminSocketPath(cfg), 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't reach the running server at %s: %v\n(is renka running, and are you its user or root?)\n", adminSocketPath(cfg), err)
		return 1
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Minute))
	if err := json.NewEncoder(conn).Encode(adminRequest{Args: args}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var resp adminResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		fmt.Fprintln(os.Stderr, "no answer from the server:", err)
		return 1
	}
	if resp.Output != "" {
		fmt.Println(resp.Output)
	}
	if resp.Error != "" {
		fmt.Fprintln(os.Stderr, resp.Error)
		return 1
	}
	return 0
}

// ---- admin room ----

func (s *Server) adminRoom() string {
	v, _ := s.adminRoomID.Load().(string)
	return v
}

// ensureAdminRoom creates the bot and the admin room on first start.
func (s *Server) ensureAdminRoom() error {
	bot := s.botID()
	var hash string
	switch err := s.db.QueryRow("SELECT password_hash FROM users WHERE user_id = ?", bot).Scan(&hash); {
	case err == sql.ErrNoRows:
		if _, err := s.db.Exec(`INSERT INTO users (user_id, password_hash, displayname, is_admin, created_ts)
			VALUES (?, '!', 'Renka', 0, ?)`, bot, nowMS()); err != nil {
			return err
		}
	case err != nil:
		return err
	case hash != "!":
		log.Printf("admin room disabled: %s is a normal account; rename it to use the admin room", bot)
		return nil
	}
	var room string
	s.db.QueryRow("SELECT v FROM kv WHERE k = 'admin_room'").Scan(&room)
	if room == "" {
		room = "!" + randString(18) + ":" + s.cfg.ServerName
		err := s.write(func(tx *sql.Tx) error {
			if _, err := tx.Exec("INSERT INTO rooms (room_id, version, creator, published, created_ts) VALUES (?,?,?,0,?)",
				room, defaultRoomVersion, bot, nowMS()); err != nil {
				return err
			}
			store := func(typ string, content any) error {
				return s.storeEvent(tx, s.newEvent(room, bot, typ, sp(""), content))
			}
			steps := []struct {
				typ     string
				content any
			}{
				{"m.room.create", map[string]any{"creator": bot, "room_version": defaultRoomVersion, "m.federate": false}},
			}
			for _, st := range steps {
				if err := store(st.typ, st.content); err != nil {
					return err
				}
			}
			if err := s.storeEvent(tx, s.newEvent(room, bot, "m.room.member", sp(bot), map[string]any{"membership": "join", "displayname": "Renka"})); err != nil {
				return err
			}
			// admins can talk, nothing else (no encryption: the bot must read)
			for _, st := range []struct {
				typ     string
				content any
			}{
				{"m.room.power_levels", map[string]any{"users": map[string]any{bot: 100}, "users_default": 0,
					"events_default": 0, "state_default": 100, "ban": 100, "kick": 100, "redact": 100, "invite": 100,
					"events": map[string]any{"m.room.encryption": 100, "m.room.power_levels": 100, "m.room.name": 100}}},
				{"m.room.join_rules", map[string]any{"join_rule": "invite"}},
				{"m.room.history_visibility", map[string]any{"history_visibility": "joined"}},
				{"m.room.guest_access", map[string]any{"guest_access": "forbidden"}},
				{"m.room.name", map[string]any{"name": "Renka admin"}},
				{"m.room.topic", map[string]any{"topic": "Server admin commands. Type: help"}},
			} {
				if err := store(st.typ, st.content); err != nil {
					return err
				}
			}
			_, err := tx.Exec("INSERT OR REPLACE INTO kv (k, v) VALUES ('admin_room', ?)", room)
			return err
		})
		if err != nil {
			return err
		}
	}
	s.adminRoomID.Store(room)
	s.syncAdminRoom()
	return nil
}

// syncAdminRoom invites current admins and removes anyone who isn't one.
func (s *Server) syncAdminRoom() {
	room := s.adminRoom()
	if room == "" {
		return
	}
	bot := s.botID()
	err := s.write(func(tx *sql.Tx) error {
		admins := map[string]bool{}
		rows, err := tx.Query("SELECT user_id FROM users WHERE is_admin = 1 AND deactivated = 0")
		if err != nil {
			return err
		}
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				admins[u] = true
			}
		}
		rows.Close()
		current := map[string]string{}
		rows, err = tx.Query("SELECT user_id, membership FROM memberships WHERE room_id = ?", room)
		if err != nil {
			return err
		}
		for rows.Next() {
			var u, m string
			if rows.Scan(&u, &m) == nil {
				current[u] = m
			}
		}
		rows.Close()
		ids := make([]string, 0, len(admins))
		for u := range admins {
			ids = append(ids, u)
		}
		sort.Strings(ids)
		for _, u := range ids {
			if m := current[u]; m != "join" && m != "invite" {
				ev := s.newEvent(room, bot, "m.room.member", sp(u), s.memberContent(tx, u, "invite", nil))
				if err := s.storeEvent(tx, ev); err != nil {
					return err
				}
			}
		}
		for u, m := range current {
			if u != bot && !admins[u] && (m == "join" || m == "invite") {
				ev := s.newEvent(room, bot, "m.room.member", sp(u), map[string]any{"membership": "leave", "reason": "no longer a server admin"})
				if err := s.storeEvent(tx, ev); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("admin room: %v", err)
	}
}

// adminRoomJobs feeds committed admin-room messages to the bot.
func (s *Server) enqueueAdmin(evs []*Event) {
	room := s.adminRoom()
	if room == "" || s.adminQ == nil {
		return
	}
	for _, e := range evs {
		if e.RoomID == room && e.Type == "m.room.message" && e.Sender != s.botID() {
			select {
			case s.adminQ <- e:
			default:
				log.Printf("admin room: busy, dropped a command")
			}
		}
	}
}

func (s *Server) startAdminBot() {
	s.adminQ = make(chan *Event, 64)
	go func() {
		for ev := range s.adminQ {
			s.handleAdminMessage(ev)
		}
	}()
}

func (s *Server) handleAdminMessage(ev *Event) {
	var c struct {
		MsgType string `json:"msgtype"`
		Body    string `json:"body"`
		Rel     struct {
			RelType string `json:"rel_type"`
		} `json:"m.relates_to"`
	}
	json.Unmarshal(ev.Content, &c)
	if c.MsgType != "m.text" || c.Rel.RelType == "m.replace" {
		return // only plain messages are commands (not edits, notices, files)
	}
	// Obey only someone who is an admin right now and is in the room.
	var admin int
	s.db.QueryRow("SELECT is_admin FROM users WHERE user_id = ? AND deactivated = 0", ev.Sender).Scan(&admin)
	if m, _ := getMembership(s.db, ev.RoomID, ev.Sender); admin != 1 || m != "join" {
		return
	}
	line := strings.TrimSpace(c.Body)
	if rest, ok := strings.CutPrefix(line, adminPrefix); ok {
		line = strings.TrimSpace(rest)
	}
	out, err := s.runAdmin(ev.Sender, strings.Fields(line))
	if err != nil {
		out = "error: " + err.Error()
	}
	if len(out) > maxReplyBytes {
		out = out[:maxReplyBytes] + "\n... (truncated)"
	}
	reply := map[string]any{
		"msgtype": "m.notice", "body": out,
		"format": "org.matrix.custom.html", "formatted_body": "<pre><code>" + html.EscapeString(out) + "</code></pre>",
		"m.relates_to": map[string]any{"m.in_reply_to": map[string]any{"event_id": ev.EventID}},
	}
	var replyEv *Event
	err = s.write(func(tx *sql.Tx) error {
		replyEv = s.newEvent(ev.RoomID, s.botID(), "m.room.message", nil, reply)
		return s.storeEvent(tx, replyEv)
	})
	if err != nil {
		log.Printf("admin room: reply failed: %v", err)
		return
	}
	// A reply carrying a password shouldn't stay in the room history.
	if strings.Contains(out, "password") && strings.Contains(out, "redacted in 10 minutes") {
		time.AfterFunc(s.passwordRedactDelay, func() { s.redactBotMessage(replyEv) })
	}
}

func (s *Server) redactBotMessage(ev *Event) {
	s.write(func(tx *sql.Tx) error {
		_, err := s.redact(tx, ev.RoomID, s.botID(), ev.EventID, map[string]any{"reason": "contained a password"},
			&Session{UserID: s.botID(), DeviceID: "renka"}, "")
		return err
	})
}

// migrate adds columns missing from older databases.
func migrate(db *sql.DB) error {
	for _, c := range []struct{ table, col, def string }{
		{"users", "deactivated", "INTEGER NOT NULL DEFAULT 0"},
		{"rooms", "blocked", "INTEGER NOT NULL DEFAULT 0"},
		{"rooms", "federated", "INTEGER NOT NULL DEFAULT 0"}, // events are signed PDUs (pdu.go)
		{"events", "pdu", "TEXT"},
		{"events", "state_group", "INTEGER"},               // federated rooms: state after the event (fedstate.go)
		{"events", "hidden", "INTEGER NOT NULL DEFAULT 0"}, // outlier, soft-failed or rejected remote events
		{"rooms", "state_group", "INTEGER"},                // federated rooms: current state
		{"events", "relay", "INTEGER NOT NULL DEFAULT 0"},  // passed on to other servers for a remote user
	} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?", c.table, c.col).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := db.Exec("ALTER TABLE " + c.table + " ADD COLUMN " + c.col + " " + c.def); err != nil {
				return fmt.Errorf("migrate %s.%s: %w", c.table, c.col, err)
			}
		}
	}
	return nil
}
