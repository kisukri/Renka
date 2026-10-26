package server

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---- passwords ----

const (
	pbkdf2Iter    = 310000
	maxPbkdf2Iter = 10_000_000 // refuse absurd counts from a tampered hash
)

// hashSem limits concurrent PBKDF2 runs (~100ms each), so a login flood
// can't starve the rest of a small box.
var hashSem = make(chan struct{}, max(1, runtime.NumCPU()/2))

func pbkdf2Key(pw string, salt []byte, iter, n int) ([]byte, error) {
	hashSem <- struct{}{}
	defer func() { <-hashSem }()
	return pbkdf2.Key(sha256.New, pw, salt, iter, n)
}

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	dk, _ := pbkdf2Key(pw, salt, pbkdf2Iter, 32)
	b := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter, b.EncodeToString(salt), b.EncodeToString(dk))
}

func checkPassword(hash, pw string) bool {
	p := strings.Split(hash, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(p[1])
	if err != nil || iter < 1 || iter > maxPbkdf2Iter {
		return false
	}
	b := base64.RawStdEncoding
	salt, err1 := b.DecodeString(p[2])
	want, err2 := b.DecodeString(p[3])
	if err1 != nil || err2 != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2Key(pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash makes unknown users take as long as wrong passwords.
var dummyHash = sync.OnceValue(func() string { return hashPassword("renka-no-such-user") })

// ---- rate limiting (brute force, registration spam) ----

// limiter: max hits per key per window.
type limiter struct {
	mu     sync.Mutex
	m      map[string]*limitEntry
	max    int
	window time.Duration
}
type limitEntry struct {
	count int
	since time.Time
}

const maxLimiterKeys = 10000

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{m: map[string]*limitEntry{}, max: max, window: window}
}

func (l *limiter) check(key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[key]
	if e == nil || time.Since(e.since) > l.window {
		return nil
	}
	if e.count >= l.max {
		wait := l.window - time.Since(e.since)
		return &apiError{Status: 429, Code: "M_LIMIT_EXCEEDED", Msg: "too many attempts, try again later",
			Extra: map[string]any{"retry_after_ms": wait.Milliseconds()}}
	}
	return nil
}

func (l *limiter) record(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) >= maxLimiterKeys { // keep memory bounded
		for k, e := range l.m {
			if time.Since(e.since) > l.window {
				delete(l.m, k)
			}
		}
		// still full (many distinct keys inside one window): evict arbitrary ones
		for k := range l.m {
			if len(l.m) < maxLimiterKeys {
				break
			}
			delete(l.m, k)
		}
	}
	e := l.m[key]
	if e == nil || time.Since(e.since) > l.window {
		e = &limitEntry{since: time.Now()}
		l.m[key] = e
	}
	e.count++
}

// ---- users & devices ----

func (s *Server) createUser(localpart, password string, admin bool) error {
	if !validLocalpart(localpart) {
		return errf(400, "M_INVALID_USERNAME", "username may only contain a-z, 0-9 and ._=-/+")
	}
	uid := "@" + localpart + ":" + s.cfg.ServerName
	if len(uid) > 255 {
		return errf(400, "M_INVALID_USERNAME", "username too long")
	}
	if localpart == botLocalpart {
		return errf(400, "M_USER_IN_USE", "this name is reserved for the server")
	}
	ad := 0
	if admin {
		ad = 1
	}
	res, err := s.db.Exec(`INSERT OR IGNORE INTO users (user_id, password_hash, displayname, is_admin, created_ts)
		VALUES (?, ?, ?, ?, ?)`, uid, hashPassword(password), localpart, ad, nowMS())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errf(400, "M_USER_IN_USE", "user ID already taken")
	}
	return nil
}

// createDevice creates (or re-uses) a device and returns a fresh access token.
func (s *Server) createDevice(tx *sql.Tx, userID, deviceID, name, ip string) (string, string, error) {
	if deviceID == "" {
		deviceID = strings.ToUpper(randString(10))
	}
	token := "renka_" + randString(40)
	_, err := tx.Exec(`INSERT INTO devices (user_id, device_id, display_name, access_token, last_seen_ts, last_seen_ip)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id, device_id) DO UPDATE SET access_token = excluded.access_token,
		  last_seen_ts = excluded.last_seen_ts, last_seen_ip = excluded.last_seen_ip,
		  display_name = COALESCE(excluded.display_name, devices.display_name)`,
		userID, deviceID, nullStr(name), token, nowMS(), ip)
	if err != nil {
		return "", "", err
	}
	if err := s.markDeviceListChange(tx, userID); err != nil {
		return "", "", err
	}
	return deviceID, token, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Server) deleteDevice(tx *sql.Tx, userID, deviceID string) error {
	for _, t := range []string{"devices", "device_keys", "one_time_keys", "fallback_keys", "to_device", "pushers"} {
		if _, err := tx.Exec("DELETE FROM "+t+" WHERE user_id = ? AND device_id = ?", userID, deviceID); err != nil {
			return err
		}
	}
	return s.markDeviceListChange(tx, userID)
}

func (s *Server) markDeviceListChange(tx *sql.Tx, userID string) error {
	st := s.nextFor(change{dev: userID})
	if _, err := tx.Exec("INSERT INTO device_list_changes (stream, user_id) VALUES (?, ?)", st, userID); err != nil {
		return err
	}
	return s.announceDeviceChange(tx, userID, st)
}

// ---- user-interactive auth (password re-check for sensitive actions) ----

type uiaAuth struct {
	Type       string `json:"type"`
	Session    string `json:"session"`
	Password   string `json:"password"`
	Token      string `json:"token"`
	User       string `json:"user"`
	Identifier struct {
		Type string `json:"type"`
		User string `json:"user"`
	} `json:"identifier"`
}

func uiaChallenge(stage string, failed string) error {
	e := &apiError{Status: 401, Code: "", Msg: "", Extra: map[string]any{
		"flows":   []any{map[string]any{"stages": []string{stage}}},
		"params":  map[string]any{},
		"session": randString(24),
	}}
	if failed != "" {
		e.Code, e.Msg = "M_FORBIDDEN", failed
	} else {
		e.Code, e.Msg = "M_UNAUTHORIZED", "authentication required"
	}
	return e
}

func (s *Server) requirePassword(r *http.Request, userID string, auth *uiaAuth) error {
	if auth == nil || auth.Type != "m.login.password" {
		return uiaChallenge("m.login.password", "")
	}
	ip := s.clientIP(r)
	if err := s.limiter.check(ip); err != nil {
		return err
	}
	var hash string
	if err := s.db.QueryRow("SELECT password_hash FROM users WHERE user_id = ?", userID).Scan(&hash); err != nil {
		s.limiter.record(ip)
		return uiaChallenge("m.login.password", "invalid password")
	}
	if !checkPassword(hash, auth.Password) {
		s.limiter.record(ip)
		return uiaChallenge("m.login.password", "invalid password")
	}
	return nil
}

// maxDeviceIDLen bounds client-chosen device IDs (they are stored and echoed).
const maxDeviceIDLen = 255

// ---- handlers ----

func (s *Server) hWellKnown(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	return map[string]any{"m.homeserver": map[string]any{"base_url": s.cfg.PublicBaseURL}}, nil
}

func (s *Server) hVersions(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	return map[string]any{
		"versions": []string{"r0.6.1", "v1.1", "v1.2", "v1.3", "v1.4", "v1.5", "v1.6", "v1.7",
			"v1.8", "v1.9", "v1.10", "v1.11"},
		"unstable_features": map[string]any{"org.matrix.simplified_msc3575": true},
	}, nil
}

func (s *Server) hLoginFlows(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	return map[string]any{"flows": []any{map[string]any{"type": "m.login.password"}}}, nil
}

// localpartFrom accepts "alice" or "@alice:server".
func (s *Server) localpartFrom(user string) (string, bool) {
	user = strings.ToLower(strings.TrimSpace(user))
	if strings.HasPrefix(user, "@") {
		l, srv, ok := splitID(user)
		if !ok || srv != strings.ToLower(s.cfg.ServerName) {
			return "", false
		}
		return l, true
	}
	return user, user != ""
}

func (s *Server) hLogin(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	var req struct {
		uiaAuth
		DeviceID    string `json:"device_id"`
		DisplayName string `json:"initial_device_display_name"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if req.Type != "m.login.password" {
		return nil, errf(400, "M_UNKNOWN", "unsupported login type")
	}
	if len(req.DeviceID) > maxDeviceIDLen {
		return nil, errInvalidParam("device_id too long")
	}
	ip := s.clientIP(r)
	if err := s.limiter.check(ip); err != nil {
		return nil, err
	}
	user := req.Identifier.User
	if user == "" {
		user = req.User
	}
	local, ok := s.localpartFrom(user)
	if !ok {
		return nil, errForbidden("invalid username or password")
	}
	uid := "@" + local + ":" + s.cfg.ServerName
	// Per-account limit too, so many IPs can't brute-force one account.
	if err := s.acctLimiter.check(uid); err != nil {
		return nil, err
	}
	var hash string
	if err := s.db.QueryRow("SELECT password_hash FROM users WHERE user_id = ?", uid).Scan(&hash); err != nil {
		checkPassword(dummyHash(), req.Password) // same cost as a real check: don't leak which users exist
		s.limiter.record(ip)
		return nil, errForbidden("invalid username or password")
	}
	if !checkPassword(hash, req.Password) {
		s.limiter.record(ip)
		s.acctLimiter.record(uid) // only real accounts get entries, so attackers can't grow this map
		return nil, errForbidden("invalid username or password")
	}
	var deviceID, token string
	err := s.write(func(tx *sql.Tx) error {
		var err error
		deviceID, token, err = s.createDevice(tx, uid, req.DeviceID, req.DisplayName, ip)
		return err
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"user_id": uid, "access_token": token, "device_id": deviceID, "home_server": s.cfg.ServerName,
		"well_known": map[string]any{"m.homeserver": map[string]any{"base_url": s.cfg.PublicBaseURL}},
	}, nil
}

func (s *Server) hRegister(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	if r.URL.Query().Get("kind") == "guest" {
		return nil, errf(403, "M_GUEST_ACCESS_FORBIDDEN", "guest access is disabled")
	}
	if !s.cfg.Registration {
		return nil, errForbidden("registration is disabled on this server")
	}
	var req struct {
		Username     string   `json:"username"`
		Password     string   `json:"password"`
		DeviceID     string   `json:"device_id"`
		DisplayName  string   `json:"initial_device_display_name"`
		InhibitLogin bool     `json:"inhibit_login"`
		Auth         *uiaAuth `json:"auth"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if len(req.DeviceID) > maxDeviceIDLen {
		return nil, errInvalidParam("device_id too long")
	}
	ip := s.clientIP(r)
	// Cap new accounts per IP: each costs a PBKDF2 run and a DB row.
	if err := s.regLimiter.check(ip); err != nil {
		return nil, err
	}
	stage := "m.login.dummy"
	if s.cfg.RegistrationToken != "" {
		stage = "m.login.registration_token"
	}
	if req.Auth == nil || req.Auth.Type != stage {
		return nil, uiaChallenge(stage, "")
	}
	if stage == "m.login.registration_token" {
		if err := s.limiter.check(ip); err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare([]byte(req.Auth.Token), []byte(s.cfg.RegistrationToken)) != 1 {
			s.limiter.record(ip)
			return nil, uiaChallenge(stage, "invalid registration token")
		}
	}
	local := strings.ToLower(req.Username)
	if local == "" {
		local = strings.ToLower(randString(12))
	}
	if len(req.Password) < 8 {
		return nil, errf(400, "M_WEAK_PASSWORD", "password must be at least 8 characters")
	}
	if err := s.createUser(local, req.Password, false); err != nil {
		return nil, err
	}
	s.regLimiter.record(ip)
	uid := "@" + local + ":" + s.cfg.ServerName
	if req.InhibitLogin {
		return map[string]any{"user_id": uid}, nil
	}
	var deviceID, token string
	err := s.write(func(tx *sql.Tx) error {
		var err error
		deviceID, token, err = s.createDevice(tx, uid, req.DeviceID, req.DisplayName, s.clientIP(r))
		return err
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"user_id": uid, "access_token": token, "device_id": deviceID, "home_server": s.cfg.ServerName}, nil
}

func (s *Server) hRegisterAvailable(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	local := strings.ToLower(r.URL.Query().Get("username"))
	if !validLocalpart(local) {
		return nil, errf(400, "M_INVALID_USERNAME", "invalid username")
	}
	if local == botLocalpart {
		return nil, errf(400, "M_USER_IN_USE", "this name is reserved for the server")
	}
	var x int
	if s.db.QueryRow("SELECT 1 FROM users WHERE user_id = ?", "@"+local+":"+s.cfg.ServerName).Scan(&x) == nil {
		return nil, errf(400, "M_USER_IN_USE", "user ID already taken")
	}
	return map[string]any{"available": true}, nil
}

func (s *Server) hTokenValidity(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	// rate limited, or it'd be a free token-guessing oracle
	if !s.cfg.Registration || s.cfg.RegistrationToken == "" {
		return map[string]any{"valid": false}, nil
	}
	ip := s.clientIP(r)
	if err := s.limiter.check(ip); err != nil {
		return nil, err
	}
	t := r.URL.Query().Get("token")
	ok := subtle.ConstantTimeCompare([]byte(t), []byte(s.cfg.RegistrationToken)) == 1
	if !ok {
		s.limiter.record(ip)
	}
	return map[string]any{"valid": ok}, nil
}

func (s *Server) hLogout(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	return map[string]any{}, s.write(func(tx *sql.Tx) error { return s.deleteDevice(tx, sess.UserID, sess.DeviceID) })
}

func (s *Server) hLogoutAll(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	return map[string]any{}, s.write(func(tx *sql.Tx) error { return s.deleteAllDevices(tx, sess.UserID, "") })
}

// deleteAllDevices removes every device of a user except `keep`.
func (s *Server) deleteAllDevices(tx *sql.Tx, userID, keep string) error {
	rows, err := tx.Query("SELECT device_id FROM devices WHERE user_id = ? AND device_id != ?", userID, keep)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if err := s.deleteDevice(tx, userID, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) hWhoami(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	return map[string]any{"user_id": sess.UserID, "device_id": sess.DeviceID, "is_guest": false}, nil
}

func (s *Server) hChangePassword(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		NewPassword   string   `json:"new_password"`
		LogoutDevices *bool    `json:"logout_devices"`
		Auth          *uiaAuth `json:"auth"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if err := s.requirePassword(r, sess.UserID, req.Auth); err != nil {
		return nil, err
	}
	if len(req.NewPassword) < 8 {
		return nil, errf(400, "M_WEAK_PASSWORD", "password must be at least 8 characters")
	}
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		if _, err := tx.Exec("UPDATE users SET password_hash = ? WHERE user_id = ?", hashPassword(req.NewPassword), sess.UserID); err != nil {
			return err
		}
		if req.LogoutDevices == nil || *req.LogoutDevices {
			return s.deleteAllDevices(tx, sess.UserID, sess.DeviceID)
		}
		return nil
	})
}

func (s *Server) listDevices(userID, deviceID string) ([]map[string]any, error) {
	q := "SELECT device_id, display_name, last_seen_ts, last_seen_ip FROM devices WHERE user_id = ?"
	args := []any{userID}
	if deviceID != "" {
		q += " AND device_id = ?"
		args = append(args, deviceID)
	}
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id string
		var name, ip sql.NullString
		var ts sql.NullInt64
		rows.Scan(&id, &name, &ts, &ip)
		d := map[string]any{"device_id": id}
		if name.Valid {
			d["display_name"] = name.String
		}
		if ts.Valid {
			d["last_seen_ts"] = ts.Int64
		}
		if ip.Valid {
			d["last_seen_ip"] = ip.String
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Server) hDevices(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	d, err := s.listDevices(sess.UserID, "")
	return map[string]any{"devices": d}, err
}

func (s *Server) hDevice(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	d, err := s.listDevices(sess.UserID, r.PathValue("deviceId"))
	if err != nil {
		return nil, err
	}
	if len(d) == 0 {
		return nil, errNotFound("no such device")
	}
	return d[0], nil
}

func (s *Server) hUpdateDevice(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	var n int64
	err := s.write(func(tx *sql.Tx) error {
		res, err := tx.Exec("UPDATE devices SET display_name = ? WHERE user_id = ? AND device_id = ?",
			req.DisplayName, sess.UserID, r.PathValue("deviceId"))
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return s.markDeviceListChange(tx, sess.UserID)
	})
	if err == nil && n == 0 {
		return nil, errNotFound("no such device")
	}
	return map[string]any{}, err
}

func (s *Server) hDeleteDevice(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		Auth *uiaAuth `json:"auth"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if err := s.requirePassword(r, sess.UserID, req.Auth); err != nil {
		return nil, err
	}
	id := r.PathValue("deviceId")
	return map[string]any{}, s.write(func(tx *sql.Tx) error { return s.deleteDevice(tx, sess.UserID, id) })
}

func (s *Server) hDeleteDevices(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		Devices []string `json:"devices"`
		Auth    *uiaAuth `json:"auth"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if err := s.requirePassword(r, sess.UserID, req.Auth); err != nil {
		return nil, err
	}
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		for _, id := range req.Devices {
			if err := s.deleteDevice(tx, sess.UserID, id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Server) hCapabilities(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	return map[string]any{"capabilities": map[string]any{
		"m.change_password": map[string]any{"enabled": true},
		"m.room_versions": map[string]any{"default": defaultRoomVersion,
			"available": map[string]string{"10": "stable", "11": "stable"}},
		"m.set_displayname": map[string]any{"enabled": true},
		"m.set_avatar_url":  map[string]any{"enabled": true},
		"m.3pid_changes":    map[string]any{"enabled": false},
	}}, nil
}
