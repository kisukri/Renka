package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// /sync runs off one global counter: every change gets the next position,
// and token "sN" means "you have everything up to N".

func (s *Server) hPostFilter(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	if r.PathValue("userId") != sess.UserID {
		return nil, errForbidden("you can only create filters for yourself")
	}
	var f map[string]any
	if err := readJSON(r, &f); err != nil {
		return nil, err
	}
	b, _ := json.Marshal(f)
	var id int64
	err := s.write(func(tx *sql.Tx) error {
		res, err := tx.Exec("INSERT INTO filters (user_id, filter) VALUES (?, ?)", sess.UserID, string(b))
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return map[string]any{"filter_id": strconv.FormatInt(id, 10)}, err
}

func (s *Server) hGetFilter(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var f string
	if s.db.QueryRow("SELECT filter FROM filters WHERE id = ? AND user_id = ?", r.PathValue("filterId"), sess.UserID).Scan(&f) != nil {
		return nil, errNotFound("filter not found")
	}
	return json.RawMessage(f), nil
}

func (s *Server) timelineLimit(userID, filter string) int {
	limit := 20
	raw := filter
	if filter != "" && !strings.HasPrefix(filter, "{") {
		raw = ""
		s.db.QueryRow("SELECT filter FROM filters WHERE id = ? AND user_id = ?", filter, userID).Scan(&raw)
	}
	var f struct {
		Room struct {
			Timeline struct {
				Limit int `json:"limit"`
			} `json:"timeline"`
		} `json:"room"`
	}
	if json.Unmarshal([]byte(raw), &f) == nil && f.Room.Timeline.Limit > 0 {
		limit = min(f.Room.Timeline.Limit, 100)
	}
	return limit
}

func (s *Server) hSync(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	q := r.URL.Query()
	var since int64
	if t := q.Get("since"); t != "" {
		since, _ = parseToken(t)
	}
	if since > s.committed.Load() {
		since = 0 // token from the future (e.g. database was reset): start over
	}
	fullState := q.Get("full_state") == "true"
	timeout := min(max(atoiDefault(q.Get("timeout"), 0), 0), 60000)
	limit := s.timelineLimit(sess.UserID, q.Get("filter"))
	deadline := time.Now().Add(time.Duration(timeout) * time.Millisecond)

	var resp map[string]any
	var seen int64 // nothing for this device in (since, seen]
	var rooms, shared map[string]bool
	for {
		ch := s.waitCh() // grab before reading the position so no commit is missed
		cur := s.committed.Load()
		// Most commits are about other users; ask the change log first.
		if resp == nil || s.touches(sess.UserID, rooms, shared, seen, cur) {
			built, has, err := s.buildSync(sess, since, cur, fullState, limit)
			if err != nil {
				return nil, err
			}
			resp = built
			if has || since == 0 || fullState {
				return resp, nil
			}
			// Changes to this set are member events in these rooms or aimed
			// at the user, so they can't be missed.
			rooms = s.joinedRooms(sess.UserID)
			shared = s.sharedUsers(sess.UserID)
		}
		// Nothing new. next_batch is from the last real build, so a miss
		// would just show up on the next sync.
		seen = cur
		if !time.Now().Before(deadline) {
			return resp, nil
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-ch:
			timer.Stop()
		case <-timer.C:
		case <-r.Context().Done():
			timer.Stop()
			return resp, nil
		}
	}
}

// unreadCounts returns (notifications, highlights) since the user's read
// receipt or join. Edits and notices don't count. Used by /sync and push
// badges so they agree.
func (s *Server) unreadCounts(q querier, roomID, uid string, joinedAt, upTo int64) (int, int) {
	var readUpTo sql.NullInt64
	q.QueryRow(`SELECT MAX(e.stream) FROM receipts r JOIN events e ON e.event_id = r.event_id
		WHERE r.room_id = ? AND r.user_id = ? AND r.type IN ('m.read', 'm.read.private')`, roomID, uid).Scan(&readUpTo)
	from := joinedAt
	if readUpTo.Valid && readUpTo.Int64 > from {
		from = readUpTo.Int64
	}
	var notif, highlight int
	q.QueryRow(`SELECT COUNT(*), COALESCE(SUM(instr(content, ?) > 0), 0) FROM events
		WHERE room_id = ? AND hidden = 0 AND stream > ? AND stream <= ? AND sender != ? AND redacted_because IS NULL
		AND type IN ('m.room.message', 'm.room.encrypted', 'm.sticker')
		AND COALESCE(rel_type, '') != 'm.replace'
		AND NOT (type = 'm.room.message' AND json_extract(content, '$.msgtype') = 'm.notice')`,
		`"`+uid+`"`, roomID, from, upTo, uid).Scan(&notif, &highlight)
	return notif, highlight
}

// joinStream is where the user last became joined (profile changes don't count).
func joinStream(q querier, roomID, userID string, upTo int64) int64 {
	var st sql.NullInt64
	q.QueryRow(`SELECT MAX(stream) FROM events WHERE room_id = ? AND hidden = 0 AND type = 'm.room.member' AND state_key = ?
		AND stream <= ? AND json_extract(content, '$.membership') = 'join'
		AND COALESCE(json_extract(prev_content, '$.membership'), '') != 'join'`, roomID, userID, upTo).Scan(&st)
	return st.Int64
}

type membershipRow struct {
	room, membership string
	stream           int64
}

func (s *Server) buildSync(sess *Session, since, cur int64, fullState bool, limit int) (map[string]any, bool, error) {
	uid := sess.UserID
	rows, err := s.db.Query("SELECT room_id, membership, stream FROM memberships WHERE user_id = ?", uid)
	if err != nil {
		return nil, false, err
	}
	var mems []membershipRow
	for rows.Next() {
		var m membershipRow
		rows.Scan(&m.room, &m.membership, &m.stream)
		mems = append(mems, m)
	}
	rows.Close()

	has := false
	join, invite, leave := map[string]any{}, map[string]any{}, map[string]any{}
	for _, m := range mems {
		if m.stream > cur {
			continue // changed after this sync's snapshot; picked up next time
		}
		switch m.membership {
		case "join":
			js := joinStream(s.db, m.room, uid, cur)
			// m.stream also moves on profile changes; only a real join counts.
			full := since == 0 || fullState || js > since
			room, ok, err := s.syncJoinedRoom(sess, m, since, cur, full, limit, js)
			if err != nil {
				return nil, false, err
			}
			if ok {
				join[m.room] = room
				has = true
			}
		case "invite":
			if m.stream > since {
				invite[m.room] = map[string]any{"invite_state": map[string]any{"events": s.strippedState(m.room, uid)}}
				has = true
			}
		case "leave", "ban":
			if since > 0 && m.stream > since {
				evs, _ := queryEvents(s.db, "SELECT "+evCols+" FROM events WHERE stream = ?", m.stream)
				leave[m.room] = map[string]any{
					"timeline": map[string]any{"events": renderEvents(evs, uid, sess.DeviceID, false),
						"limited": false, "prev_batch": tok(m.stream - 1)},
					"state":        map[string]any{"events": []any{}},
					"account_data": map[string]any{"events": []any{}},
				}
				has = true
			}
		}
	}

	acct, err := s.accountDataSince(uid, "", since, cur)
	if err != nil {
		return nil, false, err
	}
	if len(acct) > 0 {
		has = true
	}

	// to-device up to `since` has been received; delete it (via write()).
	if since > 0 {
		var x int
		if s.db.QueryRow("SELECT 1 FROM to_device WHERE user_id = ? AND device_id = ? AND stream <= ? LIMIT 1",
			uid, sess.DeviceID, since).Scan(&x) == nil {
			if err := s.write(func(tx *sql.Tx) error {
				_, err := tx.Exec("DELETE FROM to_device WHERE user_id = ? AND device_id = ? AND stream <= ?", uid, sess.DeviceID, since)
				return err
			}); err != nil {
				return nil, false, err
			}
		}
	}
	toDevice := []any{}
	trows, err := s.db.Query(`SELECT sender, type, content FROM to_device WHERE user_id = ? AND device_id = ?
		AND stream > ? AND stream <= ? ORDER BY stream`, uid, sess.DeviceID, since, cur)
	if err != nil {
		return nil, false, err
	}
	for trows.Next() {
		var sender, typ, content string
		trows.Scan(&sender, &typ, &content)
		toDevice = append(toDevice, map[string]any{"sender": sender, "type": typ, "content": json.RawMessage(content)})
	}
	trows.Close()
	if len(toDevice) > 0 {
		has = true
	}

	changed, left := []string{}, []string{}
	if since > 0 {
		changed, left = s.deviceListChanges(uid, since, cur)
		if len(changed)+len(left) > 0 {
			has = true
		}
	}

	otk, fallback := s.keyCounts(uid, sess.DeviceID)

	resp := map[string]any{
		"next_batch":                       tok(cur),
		"rooms":                            map[string]any{"join": join, "invite": invite, "leave": leave},
		"account_data":                     map[string]any{"events": acct},
		"to_device":                        map[string]any{"events": toDevice},
		"device_lists":                     map[string]any{"changed": changed, "left": left},
		"device_one_time_keys_count":       otk,
		"device_unused_fallback_key_types": fallback,
		"presence":                         map[string]any{"events": []any{}},
	}
	return resp, has, nil
}

// keyCounts returns the device's one-time key counts and unused fallback key types.
func (s *Server) keyCounts(uid, device string) (map[string]int, []string) {
	otk := map[string]int{}
	krows, _ := s.db.Query("SELECT algorithm, COUNT(*) FROM one_time_keys WHERE user_id = ? AND device_id = ? GROUP BY algorithm", uid, device)
	if krows != nil {
		for krows.Next() {
			var a string
			var n int
			krows.Scan(&a, &n)
			otk[a] = n
		}
		krows.Close()
	}
	fallback := []string{}
	frows, _ := s.db.Query("SELECT algorithm FROM fallback_keys WHERE user_id = ? AND device_id = ? AND used = 0", uid, device)
	if frows != nil {
		for frows.Next() {
			var a string
			frows.Scan(&a)
			fallback = append(fallback, a)
		}
		frows.Close()
	}
	return otk, fallback
}

func (s *Server) accountDataSince(uid, roomID string, since, cur int64) ([]any, error) {
	rows, err := s.db.Query(`SELECT type, content FROM account_data WHERE user_id = ? AND room_id = ?
		AND stream > ? AND stream <= ?`, uid, roomID, since, cur)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var t, c string
		rows.Scan(&t, &c)
		out = append(out, map[string]any{"type": t, "content": json.RawMessage(c)})
	}
	return out, rows.Err()
}

func (s *Server) syncJoinedRoom(sess *Session, m membershipRow, since, cur int64, full bool, limit int, joinedAt int64) (map[string]any, bool, error) {
	uid, roomID := sess.UserID, m.room
	fullRoom := full // initial sync, full_state, or newly joined
	lower := since
	if fullRoom {
		lower = 0
	}
	evs, err := queryEvents(s.db, "SELECT "+evCols+` FROM events WHERE room_id = ? AND hidden = 0 AND stream > ? AND stream <= ?
		ORDER BY stream DESC LIMIT ?`, roomID, lower, cur, limit+1)
	if err != nil {
		return nil, false, err
	}
	limited := len(evs) > limit
	if limited {
		evs = evs[:limit]
	}
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}

	var state []*Event
	if fullRoom {
		inTimeline := map[string]bool{}
		for _, e := range evs {
			inTimeline[e.EventID] = true
		}
		all, err := currentState(s.db, roomID)
		if err != nil {
			return nil, false, err
		}
		for _, e := range all {
			if !inTimeline[e.EventID] && e.Stream <= cur {
				state = append(state, e)
			}
		}
	} else if limited && len(evs) > 0 {
		// state that changed in the gap we are skipping over
		state, err = queryEvents(s.db, "SELECT "+prefixCols("e")+` FROM room_state s JOIN events e ON e.event_id = s.event_id
			WHERE s.room_id = ? AND s.stream > ? AND s.stream < ?`, roomID, since, evs[0].Stream)
		if err != nil {
			return nil, false, err
		}
	}

	ephemeral := []any{}
	s.tmu.Lock()
	tp := s.typingPos[roomID]
	if (fullRoom && len(s.typing[roomID]) > 0) || (tp > since && tp <= cur) {
		ids := []string{}
		for u := range s.typing[roomID] {
			ids = append(ids, u)
		}
		sort.Strings(ids)
		ephemeral = append(ephemeral, map[string]any{"type": "m.typing", "content": map[string]any{"user_ids": ids}})
	}
	s.tmu.Unlock()

	rrows, err := s.db.Query(`SELECT user_id, type, event_id, ts FROM receipts WHERE room_id = ? AND stream > ? AND stream <= ?`,
		roomID, lower, cur)
	if err != nil {
		return nil, false, err
	}
	receipts := map[string]map[string]map[string]any{}
	for rrows.Next() {
		var u, t, e string
		var ts int64
		rrows.Scan(&u, &t, &e, &ts)
		if t == "m.read.private" && u != uid {
			continue
		}
		if receipts[e] == nil {
			receipts[e] = map[string]map[string]any{}
		}
		if receipts[e][t] == nil {
			receipts[e][t] = map[string]any{}
		}
		receipts[e][t][u] = map[string]any{"ts": ts}
	}
	rrows.Close()
	if len(receipts) > 0 {
		ephemeral = append(ephemeral, map[string]any{"type": "m.receipt", "content": receipts})
	}

	acct, err := s.accountDataSince(uid, roomID, lower, cur)
	if err != nil {
		return nil, false, err
	}
	if !fullRoom && len(evs) == 0 && len(ephemeral) == 0 && len(acct) == 0 && len(state) == 0 {
		return nil, false, nil
	}

	notif, highlight := s.unreadCounts(s.db, roomID, uid, joinedAt, cur)

	var joined, invited int
	s.db.QueryRow(`SELECT COALESCE(SUM(membership = 'join'), 0), COALESCE(SUM(membership = 'invite'), 0)
		FROM memberships WHERE room_id = ?`, roomID).Scan(&joined, &invited)
	heroes := []string{}
	hrows, _ := s.db.Query(`SELECT user_id FROM memberships WHERE room_id = ? AND user_id != ?
		AND membership IN ('join', 'invite') ORDER BY stream LIMIT 5`, roomID, uid)
	if hrows != nil {
		for hrows.Next() {
			var h string
			hrows.Scan(&h)
			heroes = append(heroes, h)
		}
		hrows.Close()
	}

	prevBatch := tok(cur)
	if len(evs) > 0 {
		prevBatch = tok(evs[0].Stream - 1)
	}
	s.bundle(evs, uid)
	return map[string]any{
		"timeline": map[string]any{
			"events": renderEvents(evs, uid, sess.DeviceID, false), "limited": limited, "prev_batch": prevBatch,
		},
		"state":                map[string]any{"events": renderEvents(state, uid, sess.DeviceID, false)},
		"ephemeral":            map[string]any{"events": ephemeral},
		"account_data":         map[string]any{"events": acct},
		"unread_notifications": map[string]any{"notification_count": notif, "highlight_count": highlight},
		"summary": map[string]any{
			"m.joined_member_count": joined, "m.invited_member_count": invited, "m.heroes": heroes,
		},
	}, true, nil
}

// strippedState is the room preview shown with an invite.
func (s *Server) strippedState(roomID, uid string) []any {
	out := []any{}
	// invited from another server: what that server told us, plus the invite
	var inviteID, stripped string
	if s.db.QueryRow("SELECT event_id, invite_state FROM remote_invites WHERE room_id = ? AND user_id = ?", roomID, uid).Scan(&inviteID, &stripped) == nil {
		var evs []map[string]any
		json.Unmarshal([]byte(stripped), &evs)
		for _, e := range evs {
			out = append(out, e)
		}
		if e, _ := getEvent(s.db, inviteID); e != nil {
			out = append(out, map[string]any{"type": e.Type, "state_key": uid, "content": e.Content, "sender": e.Sender,
				"event_id": e.EventID, "origin_server_ts": e.OriginTS})
		}
		return out
	}
	for _, t := range []string{"m.room.create", "m.room.join_rules", "m.room.name", "m.room.avatar",
		"m.room.canonical_alias", "m.room.encryption", "m.room.topic"} {
		if e, _ := getStateEvent(s.db, roomID, t, ""); e != nil {
			out = append(out, map[string]any{"type": e.Type, "state_key": "", "content": e.Content, "sender": e.Sender})
		}
	}
	if e, _ := getStateEvent(s.db, roomID, "m.room.member", uid); e != nil {
		out = append(out, map[string]any{"type": e.Type, "state_key": uid, "content": e.Content, "sender": e.Sender,
			"event_id": e.EventID, "origin_server_ts": e.OriginTS})
	}
	// the inviter's member event lets clients show who invited you
	if e, _ := getStateEvent(s.db, roomID, "m.room.member", uid); e != nil && e.Sender != uid {
		if inv, _ := getStateEvent(s.db, roomID, "m.room.member", e.Sender); inv != nil {
			out = append(out, map[string]any{"type": inv.Type, "state_key": e.Sender, "content": inv.Content, "sender": inv.Sender})
		}
	}
	return out
}

// joinedRooms returns the rooms uid is joined to.
func (s *Server) joinedRooms(uid string) map[string]bool {
	out := map[string]bool{}
	rows, err := s.db.Query("SELECT room_id FROM memberships WHERE user_id = ? AND membership = 'join'", uid)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var r string
		if rows.Scan(&r) == nil {
			out[r] = true
		}
	}
	return out
}

// sharedUsers returns everyone who shares a room with uid (including uid).
func (s *Server) sharedUsers(uid string) map[string]bool {
	out := map[string]bool{uid: true}
	rows, err := s.db.Query(`SELECT DISTINCT m2.user_id FROM memberships m1 JOIN memberships m2 ON m1.room_id = m2.room_id
		WHERE m1.user_id = ? AND m1.membership = 'join' AND m2.membership IN ('join', 'invite')`, uid)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		rows.Scan(&u)
		out[u] = true
	}
	return out
}

// deviceListChanges tells E2EE clients whose device keys they must re-fetch.
func (s *Server) deviceListChanges(uid string, since, cur int64) ([]string, []string) {
	shared := s.sharedUsers(uid)
	changed := map[string]bool{}
	rows, err := s.db.Query("SELECT DISTINCT user_id FROM device_list_changes WHERE stream > ? AND stream <= ?", since, cur)
	if err == nil {
		for rows.Next() {
			var u string
			rows.Scan(&u)
			if shared[u] {
				changed[u] = true
			}
		}
		rows.Close()
	}
	// people who newly share a room with us (they joined, or we joined)
	rows, err = s.db.Query(`SELECT DISTINCT m2.user_id FROM memberships m1 JOIN memberships m2 ON m1.room_id = m2.room_id
		WHERE m1.user_id = ?1 AND m1.membership = 'join' AND m2.membership = 'join'
		AND ((m2.stream > ?2 AND m2.stream <= ?3) OR (m1.stream > ?2 AND m1.stream <= ?3))`, uid, since, cur)
	if err == nil {
		for rows.Next() {
			var u string
			rows.Scan(&u)
			changed[u] = true
		}
		rows.Close()
	}
	left := []string{}
	rows, err = s.db.Query(`SELECT DISTINCT m2.user_id FROM memberships m1 JOIN memberships m2 ON m1.room_id = m2.room_id
		WHERE m1.user_id = ? AND m2.membership IN ('leave', 'ban') AND m2.stream > ? AND m2.stream <= ?`, uid, since, cur)
	if err == nil {
		for rows.Next() {
			var u string
			rows.Scan(&u)
			if !shared[u] {
				left = append(left, u)
			}
		}
		rows.Close()
	}
	out := []string{}
	for u := range changed {
		out = append(out, u)
	}
	sort.Strings(out)
	return out, left
}
