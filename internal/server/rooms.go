package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net/http"
	"strings"
	"time"
)

func (s *Server) memberContent(q querier, userID, membership string, extra map[string]any) map[string]any {
	c := map[string]any{"membership": membership}
	if membership == "join" || membership == "invite" {
		var dn, av sql.NullString
		q.QueryRow("SELECT displayname, avatar_url FROM users WHERE user_id = ?", userID).Scan(&dn, &av)
		if dn.String != "" {
			c["displayname"] = dn.String
		}
		if av.String != "" {
			c["avatar_url"] = av.String
		}
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

// resolveRoom turns "!id:server" or "#alias:server" into a known local room ID.
func (s *Server) resolveRoom(q querier, idOrAlias string) (string, error) {
	if strings.HasPrefix(idOrAlias, "#") {
		var id string
		if q.QueryRow("SELECT room_id FROM aliases WHERE alias = ?", idOrAlias).Scan(&id) != nil {
			if !s.isLocal(idOrAlias) {
				return "", errNotFound("this server does not support federation")
			}
			return "", errNotFound("room alias not found")
		}
		return id, nil
	}
	var x int
	if q.QueryRow("SELECT 1 FROM rooms WHERE room_id = ?", idOrAlias).Scan(&x) != nil {
		if !s.isLocal(idOrAlias) {
			return "", errNotFound("this server does not support federation")
		}
		return "", errNotFound("room not found")
	}
	return idOrAlias, nil
}

func (s *Server) hCreateRoom(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		Visibility      string         `json:"visibility"`
		AliasName       string         `json:"room_alias_name"`
		Name            *string        `json:"name"`
		Topic           *string        `json:"topic"`
		Invite          []string       `json:"invite"`
		RoomVersion     string         `json:"room_version"`
		CreationContent map[string]any `json:"creation_content"`
		InitialState    []struct {
			Type     string          `json:"type"`
			StateKey string          `json:"state_key"`
			Content  json.RawMessage `json:"content"`
		} `json:"initial_state"`
		Preset     string         `json:"preset"`
		IsDirect   bool           `json:"is_direct"`
		PLOverride map[string]any `json:"power_level_content_override"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	ver := req.RoomVersion
	if ver == "" {
		ver = defaultRoomVersion
	}
	if ver != "10" && ver != "11" {
		return nil, errf(400, "M_UNSUPPORTED_ROOM_VERSION", "supported room versions: 10, 11")
	}
	preset := req.Preset
	if preset == "" {
		preset = "private_chat"
		if req.Visibility == "public" {
			preset = "public_chat"
		}
	}
	if preset != "private_chat" && preset != "trusted_private_chat" && preset != "public_chat" {
		return nil, errInvalidParam("unknown preset")
	}
	alias := ""
	if req.AliasName != "" {
		if !validLocalpart(strings.ToLower(req.AliasName)) && !validAliasName(req.AliasName) {
			return nil, errf(400, "M_INVALID_PARAM", "invalid alias name")
		}
		alias = "#" + req.AliasName + ":" + s.cfg.ServerName
	}
	// same check as Synapse: don't lock the creator out mid-creation
	if users, ok := req.PLOverride["users"]; ok {
		m, isMap := users.(map[string]any)
		if _, has := m[sess.UserID]; !isMap || !has {
			return nil, errInvalidParam("power_level_content_override.users must include " + sess.UserID)
		}
	}
	var remoteInvites []string
	for _, u := range req.Invite {
		if !s.isLocal(u) {
			if !s.cfg.Federation {
				return nil, errForbidden("federation is disabled: cannot invite " + u)
			}
			if !isUserID(u) {
				return nil, errInvalidParam("invalid user ID " + u)
			}
			remoteInvites = append(remoteInvites, u)
		}
	}
	roomID := "!" + randString(18) + ":" + s.cfg.ServerName
	me := sess.UserID

	err := s.write(func(tx *sql.Tx) error {
		if alias != "" {
			var x int
			if tx.QueryRow("SELECT 1 FROM aliases WHERE alias = ?", alias).Scan(&x) == nil {
				return errf(400, "M_ROOM_IN_USE", "room alias already taken")
			}
		}
		pub := 0
		if req.Visibility == "public" {
			pub = 1
		}
		// federated unless m.federate is anything but true (as in the auth rules)
		fed := 0
		if v, set := req.CreationContent["m.federate"]; s.cfg.Federation && (!set || v == true) {
			fed = 1
		}
		if _, err := tx.Exec("INSERT INTO rooms (room_id, version, creator, published, created_ts, federated) VALUES (?,?,?,?,?,?)",
			roomID, ver, me, pub, nowMS(), fed); err != nil {
			return err
		}
		store := func(typ string, key string, content any) error {
			return s.storeEvent(tx, s.newEvent(roomID, me, typ, sp(key), content))
		}
		cc := map[string]any{}
		for k, v := range req.CreationContent {
			cc[k] = v
		}
		cc["room_version"] = ver
		if ver == "10" {
			cc["creator"] = me
		}
		if err := store("m.room.create", "", cc); err != nil {
			return err
		}
		if err := store("m.room.member", me, s.memberContent(tx, me, "join", nil)); err != nil {
			return err
		}
		users := map[string]any{me: 100}
		if preset == "trusted_private_chat" {
			for _, u := range req.Invite {
				users[u] = 100
			}
		}
		pl := map[string]any{
			"users": users, "users_default": 0, "events_default": 0, "state_default": 50,
			"ban": 50, "kick": 50, "redact": 50, "invite": 0,
			"events": map[string]any{
				"m.room.name": 50, "m.room.power_levels": 100, "m.room.history_visibility": 100,
				"m.room.canonical_alias": 50, "m.room.avatar": 50, "m.room.tombstone": 100,
				"m.room.server_acl": 100, "m.room.encryption": 100, "m.room.topic": 50, "m.room.pinned_events": 50,
			},
			"notifications": map[string]any{"room": 50},
		}
		for k, v := range req.PLOverride {
			pl[k] = v
		}
		if err := store("m.room.power_levels", "", pl); err != nil {
			return err
		}
		if alias != "" {
			if _, err := tx.Exec("INSERT INTO aliases (alias, room_id, creator) VALUES (?,?,?)", alias, roomID, me); err != nil {
				return err
			}
			if err := store("m.room.canonical_alias", "", map[string]any{"alias": alias}); err != nil {
				return err
			}
		}
		joinRule := "invite"
		if preset == "public_chat" {
			joinRule = "public"
		}
		if err := store("m.room.join_rules", "", map[string]any{"join_rule": joinRule}); err != nil {
			return err
		}
		if err := store("m.room.history_visibility", "", map[string]any{"history_visibility": "shared"}); err != nil {
			return err
		}
		if preset != "public_chat" {
			if err := store("m.room.guest_access", "", map[string]any{"guest_access": "can_join"}); err != nil {
				return err
			}
		}
		for _, st := range req.InitialState {
			if st.Type == "m.room.create" || st.Type == "m.room.member" || st.Type == "" {
				continue
			}
			ev := &Event{RoomID: roomID, Sender: me, Type: st.Type, StateKey: sp(st.StateKey), Content: st.Content}
			if len(ev.Content) == 0 || ev.Content[0] != '{' {
				return errBadJSON("initial_state content must be an object")
			}
			if err := s.storeEvent(tx, ev); err != nil {
				return err
			}
		}
		if req.Name != nil {
			if err := store("m.room.name", "", map[string]any{"name": *req.Name}); err != nil {
				return err
			}
		}
		if req.Topic != nil {
			if err := store("m.room.topic", "", map[string]any{"topic": *req.Topic}); err != nil {
				return err
			}
		}
		for _, u := range req.Invite {
			if !s.isLocal(u) {
				continue // invited through their server below
			}
			var extra map[string]any
			if req.IsDirect {
				extra = map[string]any{"is_direct": true}
			}
			ev := s.newEvent(roomID, me, "m.room.member", sp(u), s.memberContent(tx, u, "invite", extra))
			if err := s.sendEvent(tx, ev); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, u := range remoteInvites {
		ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
		err := s.inviteRemote(ctx, sess, roomID, u, "", req.IsDirect)
		cancel()
		if err != nil {
			log.Printf("createRoom: inviting %s: %v", u, err)
		}
	}
	resp := map[string]any{"room_id": roomID}
	if alias != "" {
		resp["room_alias"] = alias
	}
	return resp, nil
}

func validAliasName(n string) bool {
	return n != "" && !strings.ContainsAny(n, ":# \t\n") && len(n) < 200
}

func (s *Server) hJoinedRooms(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	rows, err := s.db.Query("SELECT room_id FROM memberships WHERE user_id = ? AND membership = 'join'", sess.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return map[string]any{"joined_rooms": ids}, nil
}

// setMembership sends a membership event for target in room.
func (s *Server) setMembership(sess *Session, roomID, target, membership string, reason string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if membership == "invite" && !s.isLocal(target) {
		return s.inviteRemote(ctx, sess, roomID, target, reason, false)
	}
	if membership == "leave" && target == sess.UserID {
		var x int
		if s.db.QueryRow("SELECT 1 FROM remote_invites WHERE room_id = ? AND user_id = ?", roomID, target).Scan(&x) == nil {
			return s.rejectRemoteInvite(ctx, target, roomID)
		}
	}
	return s.write(func(tx *sql.Tx) error {
		extra := map[string]any{}
		if reason != "" {
			extra["reason"] = reason
		}
		if membership == "join" {
			m, _ := getMembership(tx, roomID, target)
			if m == "join" {
				return nil // already joined
			}
			if m != "invite" {
				if au := s.joinAuthoriser(tx, roomID, target); au != "" {
					extra["join_authorised_via_users_server"] = au
				}
			}
		}
		ev := s.newEvent(roomID, sess.UserID, "m.room.member", sp(target), s.memberContent(tx, target, membership, extra))
		return s.sendEvent(tx, ev)
	})
}

// joinAuthoriser picks who vouches for a restricted join (the member with
// the most power who could invite). "" if it doesn't apply.
func (s *Server) joinAuthoriser(q querier, roomID, uid string) string {
	jr, err := getStateEvent(q, roomID, "m.room.join_rules", "")
	if err != nil || jr == nil {
		return ""
	}
	c := contentOf(jr)
	if rule, _ := c["join_rule"].(string); rule != "restricted" && rule != "knock_restricted" {
		return ""
	}
	allow, _ := c["allow"].([]any)
	qualifies := false
	for _, a := range allow {
		entry, _ := a.(map[string]any)
		if t, _ := entry["type"].(string); t != "m.room_membership" {
			continue
		}
		if other, _ := entry["room_id"].(string); other != "" {
			if m, _ := getMembership(q, other, uid); m == "join" {
				qualifies = true
				break
			}
		}
	}
	if !qualifies {
		return ""
	}
	create, _ := getStateEvent(q, roomID, "m.room.create", "")
	pl, err := loadPowerLevels(q, roomID, create)
	if err != nil {
		return ""
	}
	rows, err := q.Query("SELECT user_id FROM memberships WHERE room_id = ? AND membership = 'join' ORDER BY user_id", roomID)
	if err != nil {
		return ""
	}
	defer rows.Close()
	best, bestLevel := "", int64(0)
	for rows.Next() {
		var u string
		if rows.Scan(&u) != nil || !s.isLocal(u) {
			continue
		}
		if l := pl.userLevel(u); l >= pl.invite && (best == "" || l > bestLevel) {
			best, bestLevel = u, l
		}
	}
	return best
}

type membershipReq struct {
	UserID string `json:"user_id"`
	Reason string `json:"reason"`
}

func (s *Server) hJoin(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	target := r.PathValue("roomIdOrAlias")
	if target == "" {
		target = r.PathValue("roomId")
	}
	var req membershipReq
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	q := r.URL.Query()
	servers := append(q["via"], q["server_name"]...)
	roomID := target
	if strings.HasPrefix(target, "#") && !s.isLocal(target) && s.cfg.Federation {
		res, err := s.remoteAlias(r.Context(), target)
		if err != nil {
			return nil, err
		}
		roomID = res["room_id"].(string)
		servers = append(servers, res["servers"].([]string)...)
	} else if !s.needsRemoteJoin(target) {
		var err error
		if roomID, err = s.resolveRoom(s.db, target); err != nil {
			return nil, err
		}
	}
	if s.needsRemoteJoin(roomID) {
		if m, _ := getMembership(s.db, roomID, sess.UserID); m == "ban" {
			return nil, errForbidden("you are banned from this room")
		}
		servers = append(servers, s.inviteServers(roomID, sess.UserID)...)
		if err := s.joinRemote(r.Context(), sess.UserID, roomID, servers); err != nil {
			return nil, err
		}
		return map[string]any{"room_id": roomID}, nil
	}
	if err := s.setMembership(sess, roomID, sess.UserID, "join", req.Reason); err != nil {
		return nil, err
	}
	return map[string]any{"room_id": roomID}, nil
}

// needsRemoteJoin: none of our users is in the room, so join via another server.
func (s *Server) needsRemoteJoin(roomID string) bool {
	if !s.cfg.Federation || !strings.HasPrefix(roomID, "!") {
		return false
	}
	ri, known := getRoomInfo(s.db, roomID)
	if !known {
		return !s.isLocal(roomID)
	}
	return ri.federated && !s.localMemberIn(roomID) && (!s.isLocal(roomID) || len(s.roomServers(s.db, roomID)) > 0 ||
		s.hasRemoteInvite(roomID))
}

func (s *Server) hasRemoteInvite(roomID string) bool {
	var x int
	return s.db.QueryRow("SELECT 1 FROM remote_invites WHERE room_id = ? LIMIT 1", roomID).Scan(&x) == nil
}

// inviteServers: the server that invited uid to the room, if any.
func (s *Server) inviteServers(roomID, uid string) []string {
	var id string
	if s.db.QueryRow("SELECT event_id FROM remote_invites WHERE room_id = ? AND user_id = ?", roomID, uid).Scan(&id) != nil {
		return nil
	}
	if e, _ := getEvent(s.db, id); e != nil {
		return []string{domainOf(e.Sender)}
	}
	return nil
}

func (s *Server) memberAction(membership string, self bool) handler {
	return func(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
		var req membershipReq
		if err := readJSON(r, &req); err != nil {
			return nil, err
		}
		target := req.UserID
		if self {
			target = sess.UserID
		}
		if target == "" {
			return nil, errBadJSON("user_id is required")
		}
		return map[string]any{}, s.setMembership(sess, r.PathValue("roomId"), target, membership, req.Reason)
	}
}

func (s *Server) hInvite(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	return s.memberAction("invite", false)(w, r, sess)
}
func (s *Server) hLeave(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	return s.memberAction("leave", true)(w, r, sess)
}
func (s *Server) hKick(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	return s.memberAction("leave", false)(w, r, sess)
}
func (s *Server) hBan(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	return s.memberAction("ban", false)(w, r, sess)
}
func (s *Server) hUnban(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req membershipReq
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if m, _ := getMembership(s.db, r.PathValue("roomId"), req.UserID); m != "ban" {
		return nil, errForbidden("user is not banned")
	}
	return map[string]any{}, s.setMembership(sess, r.PathValue("roomId"), req.UserID, "leave", req.Reason)
}

// checkTxn returns the event ID previously stored for this transaction, if any.
func checkTxn(tx *sql.Tx, sess *Session, txnID string) string {
	var id string
	tx.QueryRow("SELECT event_id FROM txns WHERE user_id = ? AND device_id = ? AND txn_id = ?",
		sess.UserID, sess.DeviceID, txnID).Scan(&id)
	return id
}

func saveTxn(tx *sql.Tx, sess *Session, txnID, eventID string) error {
	_, err := tx.Exec("INSERT OR REPLACE INTO txns (user_id, device_id, txn_id, event_id) VALUES (?,?,?,?)",
		sess.UserID, sess.DeviceID, txnID, eventID)
	return err
}

func (s *Server) hSend(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID, typ, txn := r.PathValue("roomId"), r.PathValue("type"), "ev:"+r.PathValue("txnId")
	var content map[string]any
	if err := readJSON(r, &content); err != nil {
		return nil, err
	}
	var eventID string
	err := s.write(func(tx *sql.Tx) error {
		if eventID = checkTxn(tx, sess, txn); eventID != "" {
			return nil
		}
		var ev *Event
		if typ == "m.room.redaction" {
			target, _ := content["redacts"].(string)
			var err error
			if ev, err = s.redact(tx, roomID, sess.UserID, target, content, sess, r.PathValue("txnId")); err != nil {
				return err
			}
		} else {
			ev = s.newEvent(roomID, sess.UserID, typ, nil, content)
			ev.TxnDevice, ev.TxnID = sess.DeviceID, r.PathValue("txnId")
			if err := s.sendEvent(tx, ev); err != nil {
				return err
			}
		}
		eventID = ev.EventID
		return saveTxn(tx, sess, txn, eventID)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"event_id": eventID}, nil
}

func (s *Server) hRedact(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var content map[string]any
	if err := readJSON(r, &content); err != nil {
		return nil, err
	}
	txn := "ev:" + r.PathValue("txnId")
	var eventID string
	err := s.write(func(tx *sql.Tx) error {
		if eventID = checkTxn(tx, sess, txn); eventID != "" {
			return nil
		}
		ev, err := s.redact(tx, r.PathValue("roomId"), sess.UserID, r.PathValue("eventId"), content, sess, r.PathValue("txnId"))
		if err != nil {
			return err
		}
		eventID = ev.EventID
		return saveTxn(tx, sess, txn, eventID)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"event_id": eventID}, nil
}

func (s *Server) hPutState(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var content map[string]any
	if err := readJSON(r, &content); err != nil {
		return nil, err
	}
	if content == nil {
		return nil, errBadJSON("content must be a JSON object")
	}
	var eventID string
	err := s.write(func(tx *sql.Tx) error {
		ev := s.newEvent(r.PathValue("roomId"), sess.UserID, r.PathValue("type"), sp(r.PathValue("stateKey")), content)
		if err := s.authorize(tx, ev); err != nil {
			return err
		}
		if ev.Type == "m.room.canonical_alias" && *ev.StateKey == "" {
			if err := checkCanonicalAlias(tx, ev.RoomID, content); err != nil {
				return err
			}
		}
		if err := s.storeEvent(tx, ev); err != nil {
			return err
		}
		eventID = ev.EventID
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"event_id": eventID}, nil
}

// checkCanonicalAlias: aliases must exist and point here (M_BAD_ALIAS),
// so a room can't claim someone else's alias.
func checkCanonicalAlias(q querier, roomID string, content map[string]any) error {
	var aliases []string
	if v, ok := content["alias"]; ok && v != nil {
		a, ok := v.(string)
		if !ok {
			return errBadJSON("alias must be a string")
		}
		if a != "" {
			aliases = append(aliases, a)
		}
	}
	if v, ok := content["alt_aliases"]; ok && v != nil {
		list, ok := v.([]any)
		if !ok {
			return errBadJSON("alt_aliases must be an array")
		}
		for _, x := range list {
			a, ok := x.(string)
			if !ok {
				return errBadJSON("alt_aliases must contain strings")
			}
			aliases = append(aliases, a)
		}
	}
	for _, a := range aliases {
		var id string
		if q.QueryRow("SELECT room_id FROM aliases WHERE alias = ?", a).Scan(&id) != nil || id != roomID {
			return errf(400, "M_BAD_ALIAS", "alias %s does not point to this room", a)
		}
	}
	return nil
}

// stateEventAt returns a state event as of stream position max.
func stateEventAt(q querier, roomID, typ, key string, max int64) (*Event, error) {
	e, err := scanEvent(q.QueryRow("SELECT "+evCols+` FROM events
		WHERE room_id = ? AND hidden = 0 AND type = ? AND state_key = ? AND stream <= ? ORDER BY stream DESC LIMIT 1`,
		roomID, typ, key, max))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

// visibleUntil: how far the user may read (former members: until they left).
func (s *Server) visibleUntil(q querier, roomID, userID string) (int64, error) {
	m, st := getMembership(q, roomID, userID)
	switch m {
	case "join":
		return s.committed.Load(), nil
	case "leave", "ban":
		var x int
		if q.QueryRow(`SELECT 1 FROM events WHERE room_id = ? AND hidden = 0 AND type = 'm.room.member' AND state_key = ?
			AND json_extract(content, '$.membership') = 'join' LIMIT 1`, roomID, userID).Scan(&x) == nil {
			return st, nil
		}
	}
	if stateString(q, roomID, "m.room.history_visibility", "", "history_visibility") == "world_readable" {
		return s.committed.Load(), nil
	}
	return 0, errForbidden("you are not a member of this room")
}

func (s *Server) requireJoined(roomID, userID string) error {
	if m, _ := getMembership(s.db, roomID, userID); m != "join" {
		return errForbidden("you are not joined to this room")
	}
	return nil
}

func (s *Server) hGetAllState(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	if err := s.requireJoined(roomID, sess.UserID); err != nil {
		return nil, err
	}
	evs, err := currentState(s.db, roomID)
	if err != nil {
		return nil, err
	}
	return renderEvents(evs, sess.UserID, sess.DeviceID, true), nil
}

func (s *Server) hGetState(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	max, err := s.visibleUntil(s.db, roomID, sess.UserID)
	if err != nil {
		return nil, err
	}
	ev, err := stateEventAt(s.db, roomID, r.PathValue("type"), r.PathValue("stateKey"), max)
	if err != nil {
		return nil, err
	}
	if ev == nil {
		return nil, errNotFound("state event not found")
	}
	if r.URL.Query().Get("format") == "event" {
		return ev.clientJSON(sess.UserID, sess.DeviceID, true), nil
	}
	return ev.Content, nil
}

func (s *Server) hGetEvent(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	max, err := s.visibleUntil(s.db, roomID, sess.UserID)
	if err != nil {
		return nil, err
	}
	ev, err := getEvent(s.db, r.PathValue("eventId"))
	if err != nil {
		return nil, err
	}
	if ev == nil || ev.RoomID != roomID || ev.Stream > max {
		return nil, errNotFound("event not found")
	}
	s.bundle([]*Event{ev}, sess.UserID)
	return ev.clientJSON(sess.UserID, sess.DeviceID, true), nil
}

// memberStateFor returns current member events for the senders of evs.
func (s *Server) memberStateFor(roomID string, evs []*Event, sess *Session, max int64) []any {
	seen := map[string]bool{}
	var out []*Event
	for _, e := range evs {
		if seen[e.Sender] {
			continue
		}
		seen[e.Sender] = true
		if m, _ := stateEventAt(s.db, roomID, "m.room.member", e.Sender, max); m != nil {
			out = append(out, m)
		}
	}
	return renderEvents(out, sess.UserID, sess.DeviceID, true)
}

func (s *Server) hMessages(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	q := r.URL.Query()
	max, err := s.visibleUntil(s.db, roomID, sess.UserID)
	if err != nil {
		return nil, err
	}
	dir := q.Get("dir")
	if dir == "" {
		dir = "b"
	}
	limit := atoiDefault(q.Get("limit"), 10)
	if limit < 1 || limit > 200 {
		limit = 50
	}
	var from int64
	if f := q.Get("from"); f != "" {
		var ok bool
		if from, ok = parseHistoryToken(f); !ok {
			return nil, errInvalidParam("invalid from token")
		}
	} else if dir == "b" {
		from = s.committed.Load()
	}
	var to int64 = math.MinInt64 // history fetched from other servers sits below 0
	if t := q.Get("to"); t != "" {
		to, _ = parseHistoryToken(t)
	}
	var evs []*Event
	resp := map[string]any{"start": tok(from)}
	if dir == "b" {
		upper := min(from, max)
		page := func() ([]*Event, error) {
			return queryEvents(s.db, "SELECT "+evCols+` FROM events WHERE room_id = ? AND hidden = 0 AND stream <= ? AND stream > ?
				ORDER BY stream DESC LIMIT ?`, roomID, upper, to, limit)
		}
		evs, err = page()
		// out of history: backfill from another server
		if err == nil && len(evs) < limit && to == math.MinInt64 {
			if m, _ := getMembership(s.db, roomID, sess.UserID); m == "join" {
				ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
				fetched := s.backfill(ctx, roomID, limit-len(evs))
				cancel()
				if fetched {
					evs, err = page()
				}
			}
		}
		if len(evs) == limit {
			resp["end"] = tok(evs[len(evs)-1].Stream - 1)
		}
	} else {
		upper := max
		if to != math.MinInt64 && to < upper {
			upper = to
		}
		evs, err = queryEvents(s.db, "SELECT "+evCols+` FROM events WHERE room_id = ? AND hidden = 0 AND stream > ? AND stream <= ?
			ORDER BY stream ASC LIMIT ?`, roomID, from, upper, limit)
		if len(evs) == limit {
			resp["end"] = tok(evs[len(evs)-1].Stream)
		}
	}
	if err != nil {
		return nil, err
	}
	s.bundle(evs, sess.UserID)
	resp["chunk"] = renderEvents(evs, sess.UserID, sess.DeviceID, true)
	resp["state"] = s.memberStateFor(roomID, evs, sess, max)
	return resp, nil
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func (s *Server) hContext(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	max, err := s.visibleUntil(s.db, roomID, sess.UserID)
	if err != nil {
		return nil, err
	}
	ev, err := getEvent(s.db, r.PathValue("eventId"))
	if err != nil {
		return nil, err
	}
	if ev == nil || ev.RoomID != roomID || ev.Stream > max {
		return nil, errNotFound("event not found")
	}
	limit := atoiDefault(r.URL.Query().Get("limit"), 10)
	if limit < 0 || limit > 100 {
		limit = 10
	}
	half := limit / 2
	before, err := queryEvents(s.db, "SELECT "+evCols+` FROM events WHERE room_id = ? AND hidden = 0 AND stream < ?
		ORDER BY stream DESC LIMIT ?`, roomID, ev.Stream, half)
	if err != nil {
		return nil, err
	}
	after, err := queryEvents(s.db, "SELECT "+evCols+` FROM events WHERE room_id = ? AND hidden = 0 AND stream > ? AND stream <= ?
		ORDER BY stream ASC LIMIT ?`, roomID, ev.Stream, max, limit-half)
	if err != nil {
		return nil, err
	}
	start, end := ev.Stream-1, ev.Stream
	if len(before) > 0 {
		start = before[len(before)-1].Stream - 1
	}
	if len(after) > 0 {
		end = after[len(after)-1].Stream
	}
	all := append(append([]*Event{ev}, before...), after...)
	s.bundle(all, sess.UserID)
	return map[string]any{
		"event":         ev.clientJSON(sess.UserID, sess.DeviceID, true),
		"events_before": renderEvents(before, sess.UserID, sess.DeviceID, true),
		"events_after":  renderEvents(after, sess.UserID, sess.DeviceID, true),
		"start":         tok(start), "end": tok(end),
		"state": s.memberStateFor(roomID, all, sess, max),
	}, nil
}

func (s *Server) hMembers(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	max, err := s.visibleUntil(s.db, roomID, sess.UserID)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	// latest member event per user up to max (= current state for members)
	evs, err := queryEvents(s.db, "SELECT "+evCols+` FROM (
		SELECT *, ROW_NUMBER() OVER (PARTITION BY state_key ORDER BY stream DESC) AS rn
		FROM events WHERE room_id = ? AND hidden = 0 AND type = 'm.room.member' AND state_key IS NOT NULL AND stream <= ?)
		WHERE rn = 1`, roomID, max)
	if err != nil {
		return nil, err
	}
	out := []*Event{}
	for _, e := range evs {
		var c struct {
			Membership string `json:"membership"`
		}
		json.Unmarshal(e.Content, &c)
		if m := q.Get("membership"); m != "" && c.Membership != m {
			continue
		}
		if m := q.Get("not_membership"); m != "" && c.Membership == m {
			continue
		}
		out = append(out, e)
	}
	return map[string]any{"chunk": renderEvents(out, sess.UserID, sess.DeviceID, true)}, nil
}

func (s *Server) hJoinedMembers(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	if err := s.requireJoined(roomID, sess.UserID); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT s.state_key, json_extract(e.content,'$.displayname'), json_extract(e.content,'$.avatar_url')
		FROM room_state s JOIN events e ON e.event_id = s.event_id JOIN memberships m
		  ON m.room_id = s.room_id AND m.user_id = s.state_key
		WHERE s.room_id = ? AND s.type = 'm.room.member' AND m.membership = 'join'`, roomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	joined := map[string]any{}
	for rows.Next() {
		var uid string
		var dn, av sql.NullString
		rows.Scan(&uid, &dn, &av)
		m := map[string]any{}
		if dn.Valid {
			m["display_name"] = dn.String
		}
		if av.Valid {
			m["avatar_url"] = av.String
		}
		joined[uid] = m
	}
	return map[string]any{"joined": joined}, nil
}

// ---- relations & threads ----

// bundle adds unsigned["m.relations"] thread summaries to thread roots.
func (s *Server) bundle(evs []*Event, viewer string) {
	for _, e := range evs {
		if e.StateKey != nil {
			continue
		}
		var count int64
		var latest sql.NullString
		s.db.QueryRow(`SELECT COUNT(*), (SELECT event_id FROM events WHERE rel_event_id = ?1 AND rel_type = 'm.thread'
			ORDER BY stream DESC LIMIT 1) FROM events WHERE rel_event_id = ?1 AND rel_type = 'm.thread'`, e.EventID).Scan(&count, &latest)
		if count == 0 {
			continue
		}
		le, _ := getEvent(s.db, latest.String)
		var mine int
		s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE rel_event_id = ? AND rel_type = 'm.thread' AND sender = ?`,
			e.EventID, viewer).Scan(&mine)
		th := map[string]any{"count": count, "current_user_participated": mine > 0 || e.Sender == viewer}
		if le != nil {
			th["latest_event"] = le.clientJSON(viewer, "", true)
		}
		if e.Unsigned == nil {
			e.Unsigned = map[string]any{}
		}
		e.Unsigned["m.relations"] = map[string]any{"m.thread": th}
	}
}

func (s *Server) hRelations(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	max, err := s.visibleUntil(s.db, roomID, sess.UserID)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 20)
	if limit < 1 || limit > 100 {
		limit = 20
	}
	forward := q.Get("dir") == "f"
	// "from": upper bound going back, lower bound going forward
	var lower int64
	upper := max
	if f := q.Get("from"); f != "" {
		if n, ok := parseToken(f); ok {
			if forward {
				lower = n
			} else if n < upper {
				upper = n
			}
		}
	}
	sqlq := "SELECT " + evCols + " FROM events WHERE room_id = ? AND hidden = 0 AND rel_event_id = ? AND stream > ? AND stream <= ?"
	args := []any{roomID, r.PathValue("eventId"), lower, upper}
	if rt := r.PathValue("relType"); rt != "" {
		sqlq += " AND rel_type = ?"
		args = append(args, rt)
	}
	if et := r.PathValue("eventType"); et != "" {
		sqlq += " AND type = ?"
		args = append(args, et)
	}
	order := "DESC"
	if forward {
		order = "ASC"
	}
	sqlq += " ORDER BY stream " + order + " LIMIT ?"
	args = append(args, limit)
	evs, err := queryEvents(s.db, sqlq, args...)
	if err != nil {
		return nil, err
	}
	resp := map[string]any{"chunk": renderEvents(evs, sess.UserID, sess.DeviceID, true)}
	if len(evs) == limit {
		last := evs[len(evs)-1].Stream
		if forward {
			resp["next_batch"] = tok(last)
		} else {
			resp["next_batch"] = tok(last - 1)
		}
	}
	return resp, nil
}

func (s *Server) hThreads(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	max, err := s.visibleUntil(s.db, roomID, sess.UserID)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 20)
	if limit < 1 || limit > 100 {
		limit = 20
	}
	upper := max
	if f := q.Get("from"); f != "" {
		if n, ok := parseToken(f); ok && n < upper {
			upper = n
		}
	}
	// Threads ordered by their latest reply; the token is that reply's stream position.
	rows, err := s.db.Query(`SELECT rel_event_id, MAX(stream) m FROM events WHERE room_id = ? AND hidden = 0 AND rel_type = 'm.thread'
		GROUP BY rel_event_id HAVING m <= ? ORDER BY m DESC LIMIT ?`, roomID, upper, limit)
	if err != nil {
		return nil, err
	}
	type th struct {
		id   string
		last int64
	}
	var list []th
	for rows.Next() {
		var t th
		rows.Scan(&t.id, &t.last)
		list = append(list, t)
	}
	rows.Close()
	var evs []*Event
	for _, t := range list {
		if e, _ := getEvent(s.db, t.id); e != nil && e.Stream <= max {
			if q.Get("include") == "participated" {
				var n int
				s.db.QueryRow("SELECT COUNT(*) FROM events WHERE rel_event_id = ? AND sender = ?", t.id, sess.UserID).Scan(&n)
				if n == 0 && e.Sender != sess.UserID {
					continue
				}
			}
			evs = append(evs, e)
		}
	}
	s.bundle(evs, sess.UserID)
	resp := map[string]any{"chunk": renderEvents(evs, sess.UserID, sess.DeviceID, true)}
	if len(list) == limit {
		resp["next_batch"] = tok(list[len(list)-1].last - 1)
	}
	return resp, nil
}

// ---- aliases & directory ----

func (s *Server) hPutAlias(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	alias := r.PathValue("alias")
	var req struct {
		RoomID string `json:"room_id"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if !s.isLocal(alias) || !strings.HasPrefix(alias, "#") {
		return nil, errInvalidParam("alias must be #name:" + s.cfg.ServerName)
	}
	if local, _, _ := splitID(alias); !validAliasName(local) || len(alias) > 255 {
		return nil, errInvalidParam("invalid alias name")
	}
	if err := s.requireJoined(req.RoomID, sess.UserID); err != nil {
		return nil, err
	}
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		res, err := tx.Exec("INSERT OR IGNORE INTO aliases (alias, room_id, creator) VALUES (?,?,?)", alias, req.RoomID, sess.UserID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errf(409, "M_UNKNOWN", "alias already exists")
		}
		return nil
	})
}

func (s *Server) hGetAlias(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	if alias := r.PathValue("alias"); s.remoteLookupAllowed(alias, sess) {
		return s.remoteAlias(r.Context(), alias)
	}
	var id string
	if s.db.QueryRow("SELECT room_id FROM aliases WHERE alias = ?", r.PathValue("alias")).Scan(&id) != nil {
		return nil, errNotFound("room alias not found")
	}
	return map[string]any{"room_id": id, "servers": []string{s.cfg.ServerName}}, nil
}

func (s *Server) hDeleteAlias(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	alias := r.PathValue("alias")
	var creator, roomID string
	if s.db.QueryRow("SELECT creator, room_id FROM aliases WHERE alias = ?", alias).Scan(&creator, &roomID) != nil {
		return nil, errNotFound("room alias not found")
	}
	if creator != sess.UserID && !sess.Admin {
		create, _ := getStateEvent(s.db, roomID, "m.room.create", "")
		pl, err := loadPowerLevels(s.db, roomID, create)
		if err != nil {
			return nil, err
		}
		if pl.userLevel(sess.UserID) < pl.eventLevel("m.room.canonical_alias", true) {
			return nil, errForbidden("you cannot delete this alias")
		}
	}
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec("DELETE FROM aliases WHERE alias = ?", alias)
		return err
	})
}

func (s *Server) hRoomAliases(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	if err := s.requireJoined(roomID, sess.UserID); err != nil {
		return nil, err
	}
	rows, err := s.db.Query("SELECT alias FROM aliases WHERE room_id = ?", roomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var a string
		rows.Scan(&a)
		out = append(out, a)
	}
	return map[string]any{"aliases": out}, nil
}

func (s *Server) hGetVisibility(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	var pub int
	if s.db.QueryRow("SELECT published FROM rooms WHERE room_id = ?", r.PathValue("roomId")).Scan(&pub) != nil {
		return nil, errNotFound("room not found")
	}
	v := "private"
	if pub == 1 {
		v = "public"
	}
	return map[string]any{"visibility": v}, nil
}

func (s *Server) hPutVisibility(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	roomID := r.PathValue("roomId")
	var req struct {
		Visibility string `json:"visibility"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if err := s.requireJoined(roomID, sess.UserID); err != nil {
		return nil, err
	}
	create, _ := getStateEvent(s.db, roomID, "m.room.create", "")
	pl, err := loadPowerLevels(s.db, roomID, create)
	if err != nil {
		return nil, err
	}
	if pl.userLevel(sess.UserID) < pl.eventLevel("m.room.canonical_alias", true) {
		return nil, errForbidden("you cannot change the directory visibility of this room")
	}
	pub := 0
	if req.Visibility == "public" {
		pub = 1
	}
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		_, err := tx.Exec("UPDATE rooms SET published = ? WHERE room_id = ?", pub, roomID)
		return err
	})
}

func (s *Server) hPublicRooms(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	var req struct {
		Limit  int    `json:"limit"`
		Since  string `json:"since"`
		Filter struct {
			Term string `json:"generic_search_term"`
		} `json:"filter"`
	}
	if r.Method == http.MethodPost {
		if err := readJSON(r, &req); err != nil {
			return nil, err
		}
	} else {
		req.Limit = atoiDefault(r.URL.Query().Get("limit"), 0)
		req.Since = r.URL.Query().Get("since")
	}
	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 100
	}
	offset := atoiDefault(req.Since, 0)
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query("SELECT room_id FROM rooms WHERE published = 1 AND blocked = 0 ORDER BY created_ts")
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	term := strings.ToLower(req.Filter.Term)
	chunk := []any{}
	for _, id := range ids {
		name := stateString(s.db, id, "m.room.name", "", "name")
		topic := stateString(s.db, id, "m.room.topic", "", "topic")
		alias := stateString(s.db, id, "m.room.canonical_alias", "", "alias")
		if term != "" && !strings.Contains(strings.ToLower(name+" "+topic+" "+alias), term) {
			continue
		}
		var n int
		s.db.QueryRow("SELECT COUNT(*) FROM memberships WHERE room_id = ? AND membership = 'join'", id).Scan(&n)
		e := map[string]any{
			"room_id": id, "num_joined_members": n,
			"world_readable": stateString(s.db, id, "m.room.history_visibility", "", "history_visibility") == "world_readable",
			"guest_can_join": stateString(s.db, id, "m.room.guest_access", "", "guest_access") == "can_join",
			"join_rule":      stateString(s.db, id, "m.room.join_rules", "", "join_rule"),
		}
		if name != "" {
			e["name"] = name
		}
		if topic != "" {
			e["topic"] = topic
		}
		if alias != "" {
			e["canonical_alias"] = alias
		}
		if av := stateString(s.db, id, "m.room.avatar", "", "url"); av != "" {
			e["avatar_url"] = av
		}
		if t := stateString(s.db, id, "m.room.create", "", "type"); t != "" {
			e["room_type"] = t
		}
		chunk = append(chunk, e)
	}
	total := len(chunk)
	if offset > len(chunk) {
		offset = len(chunk)
	}
	chunk = chunk[offset:]
	resp := map[string]any{"total_room_count_estimate": total}
	if len(chunk) > req.Limit {
		chunk = chunk[:req.Limit]
		resp["next_batch"] = itoa(offset + req.Limit)
	}
	if offset > 0 {
		resp["prev_batch"] = itoa(max(0, offset-req.Limit))
	}
	resp["chunk"] = chunk
	return resp, nil
}
