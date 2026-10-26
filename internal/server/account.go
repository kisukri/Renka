package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func itoa(n int) string { return strconv.Itoa(n) }

// ---- profile ----

func (s *Server) profile(userID string) (map[string]any, error) {
	var dn, av sql.NullString
	if err := s.db.QueryRow("SELECT displayname, avatar_url FROM users WHERE user_id = ?", userID).Scan(&dn, &av); err != nil {
		return nil, errNotFound("profile not found")
	}
	p := map[string]any{}
	if dn.String != "" {
		p["displayname"] = dn.String
	}
	if av.String != "" {
		p["avatar_url"] = av.String
	}
	return p, nil
}

func (s *Server) hProfile(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	uid := r.PathValue("userId")
	if s.remoteLookupAllowed(uid, sess) {
		return s.remoteProfile(r.Context(), uid, "")
	}
	return s.profile(uid)
}

// remoteLookupAllowed: only logged-in users can make us call other servers.
func (s *Server) remoteLookupAllowed(id string, sess *Session) bool {
	_, server, ok := splitID(id)
	return ok && s.cfg.Federation && sess != nil && server != s.cfg.ServerName
}

func (s *Server) hProfileField(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	uid := r.PathValue("userId")
	var p map[string]any
	var err error
	if s.remoteLookupAllowed(uid, sess) {
		p, err = s.remoteProfile(r.Context(), uid, r.PathValue("field"))
	} else {
		p, err = s.profile(uid)
	}
	if err != nil {
		return nil, err
	}
	f := r.PathValue("field")
	v, ok := p[f]
	if !ok {
		return nil, errNotFound("profile field not set")
	}
	return map[string]any{f: v}, nil
}

func (s *Server) hSetProfileField(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	if r.PathValue("userId") != sess.UserID {
		return nil, errForbidden("you can only change your own profile")
	}
	f := r.PathValue("field")
	if f != "displayname" && f != "avatar_url" {
		return nil, errf(400, "M_UNRECOGNIZED", "unsupported profile field")
	}
	var req map[string]any
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	v, _ := req[f].(string)
	if len(v) > 256 && f == "displayname" {
		return nil, errInvalidParam("displayname too long")
	}
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		if _, err := tx.Exec("UPDATE users SET "+f+" = ? WHERE user_id = ?", nullStr(v), sess.UserID); err != nil {
			return err
		}
		// update the member event in every joined room, like other servers do
		rows, err := tx.Query("SELECT room_id FROM memberships WHERE user_id = ? AND membership = 'join'", sess.UserID)
		if err != nil {
			return err
		}
		var rooms []string
		for rows.Next() {
			var id string
			rows.Scan(&id)
			rooms = append(rooms, id)
		}
		rows.Close()
		for _, room := range rooms {
			ev := s.newEvent(room, sess.UserID, "m.room.member", sp(sess.UserID), s.memberContent(tx, sess.UserID, "join", nil))
			if err := s.storeEvent(tx, ev); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Server) hUserSearch(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		Term  string `json:"search_term"`
		Limit int    `json:"limit"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if req.Limit <= 0 || req.Limit > 50 {
		req.Limit = 10
	}
	like := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(strings.ToLower(req.Term)) + "%"
	// like Synapse: only people you share a room with, or in public rooms
	// (search_all_users = true to search everyone)
	rows, err := s.db.Query(`SELECT u.user_id, u.displayname, u.avatar_url FROM users u
		WHERE (lower(u.user_id) LIKE ?1 ESCAPE '\' OR lower(u.displayname) LIKE ?1 ESCAPE '\')
		AND u.deactivated = 0 AND u.user_id != ?5
		AND (?3 OR u.user_id = ?4
			OR EXISTS (SELECT 1 FROM memberships a JOIN memberships b ON b.room_id = a.room_id
				WHERE a.user_id = ?4 AND a.membership IN ('join', 'invite')
				AND b.user_id = u.user_id AND b.membership IN ('join', 'invite'))
			OR EXISTS (SELECT 1 FROM memberships b
				JOIN room_state st ON st.room_id = b.room_id AND st.type = 'm.room.join_rules' AND st.state_key = ''
				JOIN events e ON e.event_id = st.event_id
				WHERE b.user_id = u.user_id AND b.membership = 'join'
				AND json_extract(e.content, '$.join_rule') = 'public'))
		LIMIT ?2`, like, req.Limit+1, s.cfg.SearchAllUsers, sess.UserID, s.botID())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	res := []any{}
	for rows.Next() {
		var id string
		var dn, av sql.NullString
		rows.Scan(&id, &dn, &av)
		e := map[string]any{"user_id": id}
		if dn.String != "" {
			e["display_name"] = dn.String
		}
		if av.String != "" {
			e["avatar_url"] = av.String
		}
		res = append(res, e)
	}
	limited := len(res) > req.Limit
	if limited {
		res = res[:req.Limit]
	}
	return map[string]any{"results": res, "limited": limited}, nil
}

// ---- account data ----

func (s *Server) setAccountData(tx *sql.Tx, uid, roomID, typ string, content []byte) error {
	_, err := tx.Exec(`INSERT OR REPLACE INTO account_data (user_id, room_id, type, content, stream) VALUES (?,?,?,?,?)`,
		uid, roomID, typ, string(content), s.nextFor(change{user: uid}))
	return err
}

func (s *Server) hGetAccountData(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	if r.PathValue("userId") != sess.UserID {
		return nil, errForbidden("you can only read your own account data")
	}
	var c string
	if s.db.QueryRow("SELECT content FROM account_data WHERE user_id = ? AND room_id = ? AND type = ?",
		sess.UserID, r.PathValue("roomId"), r.PathValue("type")).Scan(&c) != nil {
		return nil, errNotFound("account data not found")
	}
	return json.RawMessage(c), nil
}

func (s *Server) hPutAccountData(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	if r.PathValue("userId") != sess.UserID {
		return nil, errForbidden("you can only set your own account data")
	}
	// these have their own APIs; the spec says refuse
	if t := r.PathValue("type"); t == "m.push_rules" || t == "m.fully_read" {
		return nil, errf(405, "M_BAD_JSON", "%s cannot be set with this API", t)
	}
	var c map[string]any
	if err := readJSON(r, &c); err != nil {
		return nil, err
	}
	if c == nil {
		c = map[string]any{}
	}
	b, _ := json.Marshal(c)
	if len(b) > 65536 {
		return nil, errf(413, "M_TOO_LARGE", "account data too large")
	}
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		return s.setAccountData(tx, sess.UserID, r.PathValue("roomId"), r.PathValue("type"), b)
	})
}

// ---- typing & receipts ----

func (s *Server) hTyping(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	if r.PathValue("userId") != sess.UserID {
		return nil, errForbidden("you can only set your own typing state")
	}
	if err := s.requireJoined(roomID, sess.UserID); err != nil {
		return nil, err
	}
	var req struct {
		Typing  bool  `json:"typing"`
		Timeout int64 `json:"timeout"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if req.Timeout <= 0 || req.Timeout > 120000 {
		req.Timeout = 30000
	}
	if s.setTyping(roomID, sess.UserID, req.Typing, req.Timeout) {
		s.queueTypingEDU(roomID, sess.UserID, req.Typing)
	}
	return map[string]any{}, nil
}

// setTyping records whether a user is typing; true if that changed.
func (s *Server) setTyping(roomID, uid string, typing bool, timeout int64) bool {
	s.tmu.Lock()
	_, was := s.typing[roomID][uid]
	if typing {
		if s.typing[roomID] == nil {
			s.typing[roomID] = map[string]int64{}
		}
		s.typing[roomID][uid] = nowMS() + timeout
	} else {
		delete(s.typing[roomID], uid)
	}
	s.tmu.Unlock()
	if was != typing {
		s.bumpTyping([]string{roomID})
		return true
	}
	return false
}

func (s *Server) bumpTyping(rooms []string) error {
	return s.write(func(tx *sql.Tx) error {
		for _, room := range rooms {
			p := s.nextFor(change{room: room})
			s.tmu.Lock()
			s.typingPos[room] = p
			s.tmu.Unlock()
		}
		return nil
	})
}

// typingReaper clears typing notifications whose timeout has passed.
func (s *Server) typingReaper() {
	for range time.Tick(3 * time.Second) {
		now := nowMS()
		var changed []string
		s.tmu.Lock()
		for room, users := range s.typing {
			for u, exp := range users {
				if exp < now {
					delete(users, u)
					changed = append(changed, room)
				}
			}
			if len(users) == 0 {
				delete(s.typing, room)
			}
		}
		s.tmu.Unlock()
		if len(changed) > 0 {
			s.bumpTyping(changed)
		}
	}
}

func (s *Server) setReceipt(tx *sql.Tx, roomID, uid, typ, eventID string) error {
	if typ == "m.fully_read" {
		b, _ := json.Marshal(map[string]any{"event_id": eventID})
		return s.setAccountData(tx, uid, roomID, "m.fully_read", b)
	}
	if typ != "m.read" && typ != "m.read.private" {
		return errInvalidParam("unsupported receipt type")
	}
	var x int
	if tx.QueryRow("SELECT 1 FROM events WHERE event_id = ? AND room_id = ?", eventID, roomID).Scan(&x) != nil {
		return errNotFound("event not found")
	}
	_, err := tx.Exec(`INSERT OR REPLACE INTO receipts (room_id, user_id, type, event_id, ts, stream) VALUES (?,?,?,?,?,?)`,
		roomID, uid, typ, eventID, nowMS(), s.nextFor(change{room: roomID}))
	if err == nil {
		s.pendingReaders = append(s.pendingReaders, uid)
		if typ == "m.read" {
			s.queueReceiptEDU(roomID, uid, eventID, nowMS())
		}
	}
	return err
}

func (s *Server) hReceipt(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	if err := s.requireJoined(roomID, sess.UserID); err != nil {
		return nil, err
	}
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		return s.setReceipt(tx, roomID, sess.UserID, r.PathValue("receiptType"), r.PathValue("eventId"))
	})
}

func (s *Server) hReadMarkers(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	if err := s.requireJoined(roomID, sess.UserID); err != nil {
		return nil, err
	}
	var req map[string]any // other keys (e.g. "m.hidden") may be present and aren't strings
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		for _, t := range []string{"m.fully_read", "m.read", "m.read.private"} {
			if id, _ := req[t].(string); id != "" {
				if err := s.setReceipt(tx, roomID, sess.UserID, t, id); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ---- push rules (stored as the m.push_rules account data event) ----

const defaultPushRules = `{"global":{
"override":[
 {"rule_id":".m.rule.master","default":true,"enabled":false,"conditions":[],"actions":[]},
 {"rule_id":".m.rule.suppress_notices","default":true,"enabled":true,"conditions":[{"kind":"event_match","key":"content.msgtype","pattern":"m.notice"}],"actions":[]},
 {"rule_id":".m.rule.invite_for_me","default":true,"enabled":true,"conditions":[{"kind":"event_match","key":"type","pattern":"m.room.member"},{"kind":"event_match","key":"content.membership","pattern":"invite"},{"kind":"event_match","key":"state_key","pattern":"@USER@"}],"actions":["notify",{"set_tweak":"sound","value":"default"}]},
 {"rule_id":".m.rule.member_event","default":true,"enabled":true,"conditions":[{"kind":"event_match","key":"type","pattern":"m.room.member"}],"actions":[]},
 {"rule_id":".m.rule.is_user_mention","default":true,"enabled":true,"conditions":[{"kind":"event_property_contains","key":"content.m\\.mentions.user_ids","value":"@USER@"}],"actions":["notify",{"set_tweak":"sound","value":"default"},{"set_tweak":"highlight"}]},
 {"rule_id":".m.rule.is_room_mention","default":true,"enabled":true,"conditions":[{"kind":"event_property_is","key":"content.m\\.mentions.room","value":true},{"kind":"sender_notification_permission","key":"room"}],"actions":["notify",{"set_tweak":"highlight"}]},
 {"rule_id":".m.rule.tombstone","default":true,"enabled":true,"conditions":[{"kind":"event_match","key":"type","pattern":"m.room.tombstone"},{"kind":"event_match","key":"state_key","pattern":""}],"actions":["notify",{"set_tweak":"highlight"}]},
 {"rule_id":".m.rule.reaction","default":true,"enabled":true,"conditions":[{"kind":"event_match","key":"type","pattern":"m.reaction"}],"actions":[]},
 {"rule_id":".m.rule.suppress_edits","default":true,"enabled":true,"conditions":[{"kind":"event_property_is","key":"content.m\\.relates_to.rel_type","value":"m.replace"}],"actions":[]}
],
"content":[],"room":[],"sender":[],
"underride":[
 {"rule_id":".m.rule.call","default":true,"enabled":true,"conditions":[{"kind":"event_match","key":"type","pattern":"m.call.invite"}],"actions":["notify",{"set_tweak":"sound","value":"ring"}]},
 {"rule_id":".m.rule.encrypted_room_one_to_one","default":true,"enabled":true,"conditions":[{"kind":"room_member_count","is":"2"},{"kind":"event_match","key":"type","pattern":"m.room.encrypted"}],"actions":["notify",{"set_tweak":"sound","value":"default"}]},
 {"rule_id":".m.rule.room_one_to_one","default":true,"enabled":true,"conditions":[{"kind":"room_member_count","is":"2"},{"kind":"event_match","key":"type","pattern":"m.room.message"}],"actions":["notify",{"set_tweak":"sound","value":"default"}]},
 {"rule_id":".m.rule.message","default":true,"enabled":true,"conditions":[{"kind":"event_match","key":"type","pattern":"m.room.message"}],"actions":["notify"]},
 {"rule_id":".m.rule.encrypted","default":true,"enabled":true,"conditions":[{"kind":"event_match","key":"type","pattern":"m.room.encrypted"}],"actions":["notify"]}
]}}`

type pushRuleSet struct {
	Global map[string][]map[string]any `json:"global"`
}

// loadPushRules returns the user's rules, or the defaults.
func loadPushRules(q querier, uid string) *pushRuleSet {
	var c string
	if q.QueryRow("SELECT content FROM account_data WHERE user_id = ? AND room_id = '' AND type = 'm.push_rules'", uid).Scan(&c) != nil {
		c = strings.ReplaceAll(defaultPushRules, "@USER@", uid)
	}
	var rs pushRuleSet
	json.Unmarshal([]byte(c), &rs)
	// "global" may be missing
	if rs.Global == nil {
		rs.Global = map[string][]map[string]any{}
	}
	for _, k := range []string{"override", "content", "room", "sender", "underride"} {
		// drop entries that aren't objects so later code never writes into a nil map
		clean := []map[string]any{}
		for _, rule := range rs.Global[k] {
			if rule != nil {
				clean = append(clean, rule)
			}
		}
		rs.Global[k] = clean
	}
	return &rs
}

func findRule(rules []map[string]any, id string) int {
	for i, rule := range rules {
		if rule["rule_id"] == id {
			return i
		}
	}
	return -1
}

const (
	maxPushRulesPerKind = 500
	maxPushRulesBytes   = 256 << 10
)

func (s *Server) hGetPushRules(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	rs := loadPushRules(s.db, sess.UserID)
	if strings.HasSuffix(r.URL.Path, "/global/") {
		return rs.Global, nil
	}
	return rs, nil
}

func (s *Server) hPushRule(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	kind, id, attr := r.PathValue("kind"), r.PathValue("ruleId"), r.PathValue("attr")
	switch kind {
	case "override", "content", "room", "sender", "underride":
	default:
		return nil, errInvalidParam("unknown rule kind")
	}
	if r.Method == http.MethodGet {
		rules := loadPushRules(s.db, sess.UserID).Global[kind]
		idx := findRule(rules, id)
		if idx < 0 {
			return nil, errNotFound("push rule not found")
		}
		if attr != "" {
			return map[string]any{attr: rules[idx][attr]}, nil
		}
		return rules[idx], nil
	}

	var body map[string]any
	if r.Method != http.MethodDelete {
		if err := readJSON(r, &body); err != nil {
			return nil, err
		}
	}
	isArray := func(v any) bool { _, ok := v.([]any); return ok }

	// read-modify-write in one tx
	err := s.write(func(tx *sql.Tx) error {
		rs := loadPushRules(tx, sess.UserID)
		rules := rs.Global[kind]
		idx := findRule(rules, id)
		switch {
		case r.Method == http.MethodDelete:
			if idx < 0 {
				return errNotFound("push rule not found")
			}
			if d, _ := rules[idx]["default"].(bool); d {
				return errForbidden("cannot delete a server-default rule")
			}
			rs.Global[kind] = append(rules[:idx], rules[idx+1:]...)

		case attr != "":
			if idx < 0 {
				return errNotFound("push rule not found")
			}
			v := body[attr]
			switch attr {
			case "enabled":
				if _, ok := v.(bool); !ok {
					return errBadJSON("enabled must be a boolean")
				}
			case "actions":
				if !isArray(v) {
					return errBadJSON("actions must be an array")
				}
			default:
				return errInvalidParam("unknown attribute")
			}
			rules[idx][attr] = v

		default:
			if strings.HasPrefix(id, ".") {
				return errInvalidParam("rule IDs starting with . are reserved")
			}
			if id == "" || len(id) > 255 {
				return errInvalidParam("invalid rule ID")
			}
			actions := body["actions"]
			if actions == nil {
				actions = []any{}
			} else if !isArray(actions) {
				return errBadJSON("actions must be an array")
			}
			rule := map[string]any{"rule_id": id, "default": false, "enabled": true, "actions": actions}
			switch kind {
			case "override", "underride":
				conds := body["conditions"]
				if conds == nil {
					conds = []any{}
				} else if !isArray(conds) {
					return errBadJSON("conditions must be an array")
				}
				rule["conditions"] = conds
			case "content":
				p, ok := body["pattern"].(string)
				if !ok || p == "" {
					return errBadJSON("content rules need a pattern string")
				}
				rule["pattern"] = p
			}
			if idx >= 0 {
				rules[idx] = rule
			} else {
				if len(rules) >= maxPushRulesPerKind {
					return errf(400, "M_LIMIT_EXCEEDED", "too many push rules")
				}
				pos := 0
				if kind == "override" && len(rules) > 0 && rules[0]["rule_id"] == ".m.rule.master" {
					pos = 1
				}
				rs.Global[kind] = append(rules[:pos], append([]map[string]any{rule}, rules[pos:]...)...)
			}
		}
		b, err := json.Marshal(rs)
		if err != nil {
			return err
		}
		if len(b) > maxPushRulesBytes {
			return errf(413, "M_TOO_LARGE", "push rules too large")
		}
		return s.setAccountData(tx, sess.UserID, "", "m.push_rules", b)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{}, nil
}
