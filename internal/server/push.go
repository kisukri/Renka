package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Push notifications. We only ever send event ID, room ID and unread count
// (event_id_only); the app fetches the message itself.

const (
	pushGatewayPath   = "/_matrix/push/v1/notify"
	maxPushersPerUser = 20
	pushQueueSize     = 4096
	pushConcurrency   = 8
)

// ---- pushers API ----

func (s *Server) hGetPushers(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	rows, err := s.db.Query(`SELECT pushkey, kind, app_id, app_display_name, device_display_name, profile_tag, lang, data
		FROM pushers WHERE user_id = ?`, sess.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var key, kind, app, appName, devName, tag, lang, data string
		if rows.Scan(&key, &kind, &app, &appName, &devName, &tag, &lang, &data) != nil {
			continue
		}
		p := map[string]any{"pushkey": key, "kind": kind, "app_id": app, "app_display_name": appName,
			"device_display_name": devName, "lang": lang, "data": json.RawMessage(data)}
		if tag != "" {
			p["profile_tag"] = tag
		}
		out = append(out, p)
	}
	return map[string]any{"pushers": out}, rows.Err()
}

// validGatewayURL: https, path /_matrix/push/v1/notify.
func validGatewayURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != pushGatewayPath {
		return errInvalidParam("data.url must be an https URL ending in " + pushGatewayPath)
	}
	return nil
}

func (s *Server) hSetPusher(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		PushKey           string         `json:"pushkey"`
		Kind              *string        `json:"kind"`
		AppID             string         `json:"app_id"`
		AppDisplayName    string         `json:"app_display_name"`
		DeviceDisplayName string         `json:"device_display_name"`
		ProfileTag        string         `json:"profile_tag"`
		Lang              string         `json:"lang"`
		Data              map[string]any `json:"data"`
		Append            bool           `json:"append"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if req.PushKey == "" || len(req.PushKey) > 512 {
		return nil, errInvalidParam("pushkey must be 1-512 bytes")
	}
	if req.AppID == "" || len(req.AppID) > 64 {
		return nil, errInvalidParam("app_id must be 1-64 characters")
	}
	if req.Kind == nil { // "kind": null deletes the pusher
		return map[string]any{}, s.write(func(tx *sql.Tx) error {
			_, err := tx.Exec("DELETE FROM pushers WHERE user_id = ? AND app_id = ? AND pushkey = ?",
				sess.UserID, req.AppID, req.PushKey)
			return err
		})
	}
	if *req.Kind != "http" {
		return nil, errInvalidParam("only http pushers are supported")
	}
	gw, _ := req.Data["url"].(string)
	if err := validGatewayURL(gw); err != nil {
		return nil, err
	}
	for _, f := range []string{req.AppDisplayName, req.DeviceDisplayName, req.ProfileTag, req.Lang} {
		if len(f) > 255 {
			return nil, errInvalidParam("pusher field too long")
		}
	}
	data, _ := json.Marshal(req.Data)
	if len(data) > 4096 {
		return nil, errInvalidParam("pusher data too large")
	}
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		if !req.Append {
			// same phone, new account: drop the old pusher
			if _, err := tx.Exec("DELETE FROM pushers WHERE app_id = ? AND pushkey = ? AND user_id != ?",
				req.AppID, req.PushKey, sess.UserID); err != nil {
				return err
			}
		}
		var n int
		tx.QueryRow("SELECT COUNT(*) FROM pushers WHERE user_id = ? AND NOT (app_id = ? AND pushkey = ?)",
			sess.UserID, req.AppID, req.PushKey).Scan(&n)
		if n >= maxPushersPerUser {
			return errf(400, "M_LIMIT_EXCEEDED", "too many pushers")
		}
		_, err := tx.Exec(`INSERT OR REPLACE INTO pushers (user_id, device_id, app_id, pushkey, kind, app_display_name,
			device_display_name, profile_tag, lang, data, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			sess.UserID, sess.DeviceID, req.AppID, req.PushKey, *req.Kind, req.AppDisplayName,
			req.DeviceDisplayName, req.ProfileTag, req.Lang, string(data), nowMS())
		return err
	})
}

// ---- push rule evaluation ----

// pushEnv is what a rule can look at for one event and one recipient.
type pushEnv struct {
	event       map[string]any // type, sender, room_id, state_key, content
	uid         string
	displayName string
	memberCount int
	senderLevel int64
	notifLevels map[string]int64 // power_levels.notifications
}

// pushActions returns the first matching rule's actions (nil: no match).
func pushActions(rs *pushRuleSet, env *pushEnv) []any {
	for _, kind := range []string{"override", "content", "room", "sender", "underride"} {
		for _, rule := range rs.Global[kind] {
			if en, ok := rule["enabled"].(bool); ok && !en {
				continue
			}
			if ruleMatches(kind, rule, env) {
				actions, _ := rule["actions"].([]any)
				if actions == nil {
					actions = []any{}
				}
				return actions
			}
		}
	}
	return nil
}

func ruleMatches(kind string, rule map[string]any, env *pushEnv) bool {
	switch kind {
	case "override", "underride":
		conds, ok := rule["conditions"].([]any)
		if !ok {
			return false
		}
		for _, c := range conds {
			cm, ok := c.(map[string]any)
			if !ok || !condMatches(cm, env) {
				return false
			}
		}
		return true
	case "content":
		pattern, _ := rule["pattern"].(string)
		body, ok := lookupPath(env.event, "content.body").(string)
		return ok && pattern != "" && globMatch(pattern, body, true)
	case "room":
		return rule["rule_id"] == env.event["room_id"]
	case "sender":
		return rule["rule_id"] == env.event["sender"]
	}
	return false
}

func condMatches(c map[string]any, env *pushEnv) bool {
	key, _ := c["key"].(string)
	switch c["kind"] {
	case "event_match":
		pattern, _ := c["pattern"].(string)
		v, ok := lookupPath(env.event, key).(string)
		return ok && globMatch(pattern, v, key == "content.body")
	case "event_property_is":
		v, found := lookupPathOK(env.event, key)
		return found && jsonEqual(v, c["value"])
	case "event_property_contains":
		arr, _ := lookupPath(env.event, key).([]any)
		for _, el := range arr {
			if jsonEqual(el, c["value"]) {
				return true
			}
		}
		return false
	case "contains_display_name":
		body, _ := lookupPath(env.event, "content.body").(string)
		return env.displayName != "" && containsWord(body, env.displayName)
	case "room_member_count":
		is, _ := c["is"].(string)
		return memberCountMatches(is, env.memberCount)
	case "sender_notification_permission":
		need, ok := env.notifLevels[key]
		if !ok {
			need = 50
		}
		return env.senderLevel >= need
	}
	return false // unknown condition kinds never match (spec)
}

// splitPath splits a dotted key; "\." is a literal dot and "\\" a backslash.
func splitPath(key string) []string {
	var parts []string
	var cur strings.Builder
	for i := 0; i < len(key); i++ {
		switch {
		case key[i] == '\\' && i+1 < len(key) && (key[i+1] == '.' || key[i+1] == '\\'):
			cur.WriteByte(key[i+1])
			i++
		case key[i] == '.':
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(key[i])
		}
	}
	return append(parts, cur.String())
}

func lookupPathOK(obj map[string]any, key string) (any, bool) {
	var cur any = obj
	for _, p := range splitPath(key) {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[p]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func lookupPath(obj map[string]any, key string) any {
	v, _ := lookupPathOK(obj, key)
	return v
}

// jsonEqual compares JSON scalars, treating 5, 5.0 and json.Number("5") alike.
func jsonEqual(a, b any) bool {
	norm := func(v any) any {
		switch x := v.(type) {
		case json.Number:
			if n, err := x.Int64(); err == nil {
				return n
			}
			return string(x)
		case float64:
			if x == float64(int64(x)) {
				return int64(x)
			}
		case int:
			return int64(x)
		}
		return v
	}
	a, b = norm(a), norm(b)
	switch a.(type) {
	case string, int64, bool, nil, float64:
		return a == b
	}
	return false
}

var memberCountRe = regexp.MustCompile(`^(==|<=|>=|<|>)?([0-9]{1,9})$`)

func memberCountMatches(is string, n int) bool {
	m := memberCountRe.FindStringSubmatch(is)
	if m == nil {
		return false
	}
	var want int
	fmt.Sscan(m[2], &want)
	switch m[1] {
	case "<":
		return n < want
	case ">":
		return n > want
	case "<=":
		return n <= want
	case ">=":
		return n >= want
	}
	return n == want
}

var globCache sync.Map // pattern -> *regexp.Regexp

// globMatch matches * and ? case-insensitively. wordBoundary: match whole
// words anywhere (for content.body).
func globMatch(pattern, value string, wordBoundary bool) bool {
	if len(pattern) > 1000 {
		return false
	}
	ck := fmt.Sprint(wordBoundary, "\x00", pattern)
	re, ok := globCache.Load(ck)
	if !ok {
		var b strings.Builder
		for _, r := range pattern {
			switch r {
			case '*':
				b.WriteString(".*?")
			case '?':
				b.WriteString(".")
			default:
				b.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
		expr := "(?is)^" + b.String() + "$"
		if wordBoundary {
			expr = `(?is)(?:^|\W)` + b.String() + `(?:\W|$)`
		}
		compiled, err := regexp.Compile(expr)
		if err != nil {
			return false
		}
		if n := globCacheSize(); n > 2000 {
			globCache.Clear()
		}
		globCache.Store(ck, compiled)
		re = compiled
	}
	return re.(*regexp.Regexp).MatchString(value)
}

func globCacheSize() int {
	n := 0
	globCache.Range(func(any, any) bool { n++; return true })
	return n
}

// containsWord reports whether body contains word as a whole word, ignoring case.
func containsWord(body, word string) bool {
	ck := "word\x00" + word
	re, ok := globCache.Load(ck)
	if !ok {
		compiled, err := regexp.Compile(`(?is)(?:^|\W)` + regexp.QuoteMeta(word) + `(?:\W|$)`)
		if err != nil {
			return false
		}
		globCache.Store(ck, compiled)
		re = compiled
	}
	return re.(*regexp.Regexp).MatchString(body)
}

// notifyTweaks reports whether actions say to notify, and the tweaks.
func notifyTweaks(actions []any) (bool, map[string]any) {
	notify := false
	tweaks := map[string]any{}
	for _, a := range actions {
		switch x := a.(type) {
		case string:
			if x == "notify" {
				notify = true
			}
		case map[string]any:
			if name, ok := x["set_tweak"].(string); ok {
				v, has := x["value"]
				if !has && name == "highlight" {
					v = true
				}
				tweaks[name] = v
			}
		}
	}
	return notify, tweaks
}

// ---- delivery ----

type pushJob struct {
	ev     *Event // a new event to consider, or
	reader string // a user whose unread count may have dropped (read receipt)
}

// enqueuePush never blocks; a full queue drops the push.
func (s *Server) enqueuePush(evs []*Event, readers []string) {
	if s.pushQ == nil {
		return
	}
	jobs := make([]pushJob, 0, len(evs)+len(readers))
	for _, e := range evs {
		jobs = append(jobs, pushJob{ev: e})
	}
	for _, u := range readers {
		jobs = append(jobs, pushJob{reader: u})
	}
	for _, j := range jobs {
		select {
		case s.pushQ <- j:
		default:
			if time.Since(s.pushDropLogged) > time.Minute {
				s.pushDropLogged = time.Now()
				log.Printf("push: queue full, dropping notifications")
			}
		}
	}
}

func (s *Server) startPusher() {
	s.pushQ = make(chan pushJob, pushQueueSize)
	s.pushSem = make(chan struct{}, pushConcurrency)
	s.lastBadge = map[string]int{}
	if s.pushClient == nil {
		s.pushClient = newPushClient(false)
	}
	go func() {
		for j := range s.pushQ {
			if j.ev != nil {
				s.pushEvent(j.ev)
			} else {
				s.pushBadge(j.reader)
			}
		}
	}()
}

// pushEvent notifies room members whose rules say so.
func (s *Server) pushEvent(ev *Event) {
	target := ""
	if ev.Type == "m.room.member" && ev.StateKey != nil {
		var c struct {
			Membership string `json:"membership"`
		}
		json.Unmarshal(ev.Content, &c)
		if c.Membership == "invite" {
			target = *ev.StateKey // invited users aren't joined yet but should hear about it
		}
	}
	rows, err := s.db.Query(`SELECT DISTINCT p.user_id FROM pushers p JOIN memberships m
		ON m.user_id = p.user_id AND m.room_id = ?
		WHERE (m.membership = 'join' OR (m.membership = 'invite' AND m.user_id = ?)) AND p.user_id != ?`,
		ev.RoomID, target, ev.Sender)
	if err != nil {
		return
	}
	var users []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			users = append(users, u)
		}
	}
	rows.Close()
	if len(users) == 0 {
		return
	}

	var content map[string]any
	dec := json.NewDecoder(bytes.NewReader(ev.Content))
	dec.UseNumber()
	dec.Decode(&content)
	event := map[string]any{"type": ev.Type, "sender": ev.Sender, "room_id": ev.RoomID, "content": content}
	if ev.StateKey != nil {
		event["state_key"] = *ev.StateKey
	}
	var members int
	s.db.QueryRow("SELECT COUNT(*) FROM memberships WHERE room_id = ? AND membership = 'join'", ev.RoomID).Scan(&members)
	create, _ := getStateEvent(s.db, ev.RoomID, "m.room.create", "")
	pl, _ := loadPowerLevels(s.db, ev.RoomID, create)
	notifLevels := map[string]int64{}
	if pe, _ := getStateEvent(s.db, ev.RoomID, "m.room.power_levels", ""); pe != nil {
		var raw struct {
			Notifications map[string]any `json:"notifications"`
		}
		json.Unmarshal(pe.Content, &raw)
		for k, v := range raw.Notifications {
			notifLevels[k] = toInt(v, 50)
		}
	}
	senderLevel := int64(0)
	if pl != nil {
		senderLevel = pl.userLevel(ev.Sender)
	}

	for _, uid := range users {
		env := &pushEnv{event: event, uid: uid, displayName: stateString(s.db, ev.RoomID, "m.room.member", uid, "displayname"),
			memberCount: members, senderLevel: senderLevel, notifLevels: notifLevels}
		notify, tweaks := notifyTweaks(pushActions(loadPushRules(s.db, uid), env))
		if !notify {
			continue
		}
		prio := "low"
		switch ev.Type {
		case "m.room.message", "m.room.encrypted", "m.sticker", "m.call.invite", "m.room.member":
			prio = "high"
		}
		n := s.totalUnread(uid)
		s.sendToPushers(uid, map[string]any{
			"event_id": ev.EventID, "room_id": ev.RoomID, "prio": prio,
			"counts": map[string]any{"unread": n},
		}, tweaks, n)
	}
}

// pushBadge sends a counts-only push after a read receipt so badges clear.
func (s *Server) pushBadge(uid string) {
	var has int
	if s.db.QueryRow("SELECT 1 FROM pushers WHERE user_id = ? LIMIT 1", uid).Scan(&has) != nil {
		return
	}
	n := s.totalUnread(uid)
	s.sendToPushers(uid, map[string]any{"prio": "high", "counts": map[string]any{"unread": n}}, map[string]any{}, n)
}

// totalUnread is the badge number: notifying messages across joined rooms.
func (s *Server) totalUnread(uid string) int {
	cur := s.committed.Load()
	total := 0
	for room := range s.joinedRooms(uid) {
		n, _ := s.unreadCounts(s.db, room, uid, joinStream(s.db, room, uid, cur), cur)
		total += n
	}
	return total
}

type pusherRow struct {
	appID, pushKey string
	data           map[string]any
	ts             int64
}

func (s *Server) sendToPushers(uid string, notif, tweaks map[string]any, count int) {
	rows, err := s.db.Query("SELECT app_id, pushkey, data, ts FROM pushers WHERE user_id = ?", uid)
	if err != nil {
		return
	}
	var ps []pusherRow
	for rows.Next() {
		var p pusherRow
		var data string
		if rows.Scan(&p.appID, &p.pushKey, &data, &p.ts) == nil && json.Unmarshal([]byte(data), &p.data) == nil {
			ps = append(ps, p)
		}
	}
	rows.Close()
	badgeOnly := notif["event_id"] == nil
	for _, p := range ps {
		key := p.appID + "\x00" + p.pushKey
		s.pushMu.Lock()
		last, seen := s.lastBadge[key]
		if badgeOnly && seen && last == count {
			s.pushMu.Unlock()
			continue
		}
		s.lastBadge[key] = count
		s.pushMu.Unlock()

		gw, _ := p.data["url"].(string)
		if validGatewayURL(gw) != nil {
			continue
		}
		data := map[string]any{}
		for k, v := range p.data {
			if k != "url" { // the gateway gets the pusher data minus the url (spec)
				data[k] = v
			}
		}
		n := map[string]any{}
		for k, v := range notif {
			n[k] = v
		}
		n["devices"] = []any{map[string]any{"app_id": p.appID, "pushkey": p.pushKey, "pushkey_ts": p.ts / 1000,
			"data": data, "tweaks": tweaks}}
		body, _ := json.Marshal(map[string]any{"notification": n})
		s.pushSem <- struct{}{}
		go func(gw, uid, appID string) {
			defer func() { <-s.pushSem }()
			s.deliver(gw, body, uid, appID)
		}(gw, uid, p.appID)
	}
}

// deliver POSTs to a gateway (a few retries) and drops rejected pushkeys.
func (s *Server) deliver(gw string, body []byte, uid, appID string) {
	for attempt, wait := 0, 2*time.Second; attempt < 3; attempt, wait = attempt+1, wait*4 {
		if attempt > 0 {
			time.Sleep(wait)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "POST", gw, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.pushClient.Do(req)
		if err != nil {
			cancel()
			if errors.Is(err, errPushAddress) {
				return // refused by policy: retrying won't help
			}
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		cancel()
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			continue
		}
		if resp.StatusCode == 200 {
			var r struct {
				Rejected []string `json:"rejected"`
			}
			if json.Unmarshal(raw, &r) == nil && len(r.Rejected) > 0 {
				s.write(func(tx *sql.Tx) error {
					for _, k := range r.Rejected {
						if _, err := tx.Exec("DELETE FROM pushers WHERE user_id = ? AND app_id = ? AND pushkey = ?", uid, appID, k); err != nil {
							return err
						}
					}
					return nil
				})
			}
		}
		return
	}
}

// ---- an HTTP client that can't be pointed at the inside ----

var errPushAddress = errors.New("push gateway address is not a public address")

// publicIP: not loopback, private, link-local (cloud metadata!), CGNAT,
// multicast or unspecified.
func publicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0, v4[0] == 100 && v4[1]&0xc0 == 64, // 0.0.0.0/8, 100.64.0.0/10
			v4[0] == 192 && v4[1] == 0 && v4[2] == 0, // 192.0.0.0/24
			v4[0] == 198 && v4[1]&0xfe == 18,         // 198.18.0.0/15
			v4[0] >= 240:                             // reserved, broadcast
			return false
		}
	}
	return true
}

// newPushClient: users pick the URL, so guard against SSRF. The IP is
// checked when dialing (after DNS), no redirects, no env proxy.
func newPushClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return errPushAddress
		}
		ip := net.ParseIP(host)
		if ip == nil || (!allowPrivate && !publicIP(ip)) {
			return errPushAddress
		}
		return nil
	}}
	return &http.Client{
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 15 * time.Second,
			MaxIdleConns:          16,
			IdleConnTimeout:       90 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       30 * time.Second,
	}
}
