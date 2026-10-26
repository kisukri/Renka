package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Outgoing federation. Each destination has a cursor into the events table
// (fed_destinations), so there's no queue to lose. Only typing and receipts
// live in memory. Backoff: 1 min up to 6 h.

const (
	fedTxnPDUs     = 50
	fedMaxBackoff  = 6 * time.Hour
	fedMinBackoff  = time.Minute
	fedMaxRounds   = 20 // transactions per destination per pass
	maxEDUsQueued  = 100
	sendJoinLimit  = 32 << 20 // a send_join answer carries the whole room state
	maxJoinEvents  = 20000    // rooms bigger than this are too heavy for a small server
	fedSendTimeout = 60 * time.Second
)

type fedOut struct {
	kick    chan struct{}
	mu      sync.Mutex
	edus    map[string][]map[string]any // destination -> queued EDUs
	running map[string]bool
}

func (s *Server) kickSender() {
	if s.fedOut == nil {
		return
	}
	select {
	case s.fedOut.kick <- struct{}{}:
	default:
	}
}

func (s *Server) startSender() {
	s.fedOut = &fedOut{kick: make(chan struct{}, 1), edus: map[string][]map[string]any{}, running: map[string]bool{}}
	go func() {
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-s.fedOut.kick:
			case <-tick.C:
			}
			s.sendPending()
		}
	}()
}

// queueEDU adds an EDU for every other server in the room.
func (s *Server) queueEDU(roomID string, edu map[string]any) {
	if s.fedOut == nil {
		return
	}
	if ri, ok := getRoomInfo(s.db, roomID); !ok || !ri.federated {
		return
	}
	servers := s.roomServers(s.db, roomID)
	if len(servers) == 0 {
		return
	}
	s.fedOut.mu.Lock()
	for _, d := range servers {
		q := append(s.fedOut.edus[d], edu)
		if len(q) > maxEDUsQueued {
			q = q[len(q)-maxEDUsQueued:]
		}
		s.fedOut.edus[d] = q
	}
	s.fedOut.mu.Unlock()
	s.kickSender()
}

func (s *Server) queueTypingEDU(roomID, uid string, typing bool) {
	s.queueEDU(roomID, map[string]any{"edu_type": "m.typing",
		"content": map[string]any{"room_id": roomID, "user_id": uid, "typing": typing}})
}

func (s *Server) queueReceiptEDU(roomID, uid, eventID string, ts int64) {
	s.queueEDU(roomID, map[string]any{"edu_type": "m.receipt", "content": map[string]any{
		roomID: map[string]any{"m.read": map[string]any{uid: map[string]any{"event_ids": []string{eventID}, "data": map[string]any{"ts": ts}}}}}})
}

// destinations lists servers sharing a federated room with us.
func (s *Server) destinations() []string {
	rows, err := s.db.Query(`SELECT DISTINCT m.user_id FROM memberships m JOIN rooms r ON r.room_id = m.room_id AND r.federated = 1
		WHERE m.membership = 'join' AND EXISTS (SELECT 1 FROM memberships l WHERE l.room_id = m.room_id
			AND l.membership = 'join' AND substr(l.user_id, -length(?) - 1) = ':' || ?)`, s.cfg.ServerName, s.cfg.ServerName)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var u string
		rows.Scan(&u)
		if d := domainOf(u); d != s.cfg.ServerName {
			seen[d] = true
		}
	}
	rows.Close()
	// servers that are behind, e.g. owed a kick of their last user
	r2, err := s.db.Query("SELECT server FROM fed_destinations WHERE last_stream < ? AND retry_at <= ?", s.committed.Load(), nowMS())
	if err == nil {
		for r2.Next() {
			var d string
			r2.Scan(&d)
			seen[d] = true
		}
		r2.Close()
	}
	if r3, err := s.db.Query("SELECT DISTINCT dest FROM fed_edus"); err == nil {
		for r3.Next() {
			var d string
			r3.Scan(&d)
			seen[d] = true
		}
		r3.Close()
	}
	s.fedOut.mu.Lock()
	for d := range s.fedOut.edus {
		seen[d] = true
	}
	s.fedOut.mu.Unlock()
	out := make([]string, 0, len(seen))
	for d := range seen {
		if validHostPort(d) {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) sendPending() {
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, d := range s.destinations() {
		s.fedOut.mu.Lock()
		busy := s.fedOut.running[d]
		if !busy {
			s.fedOut.running[d] = true
		}
		s.fedOut.mu.Unlock()
		if busy {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(d string) {
			defer func() {
				s.fedOut.mu.Lock()
				delete(s.fedOut.running, d)
				s.fedOut.mu.Unlock()
				<-sem
				wg.Done()
			}()
			s.sendTo(d)
		}(d)
	}
	wg.Wait()
}

// destState reads (creating) a destination's cursor and backoff.
func (s *Server) destState(dest string) (last, retryAt, backoff int64) {
	err := s.db.QueryRow("SELECT last_stream, retry_at, backoff FROM fed_destinations WHERE server = ?", dest).Scan(&last, &retryAt, &backoff)
	if err == nil {
		return
	}
	// New destination: start from when its users joined our rooms.
	var since sql.NullInt64
	s.db.QueryRow("SELECT MIN(stream) FROM memberships WHERE membership = 'join' AND "+userOfServer, dest, dest).Scan(&since)
	last = since.Int64 - 1
	if !since.Valid {
		last = s.committed.Load()
	}
	s.db.Exec("INSERT OR IGNORE INTO fed_destinations (server, last_stream, retry_at, backoff) VALUES (?,?,0,0)", dest, last)
	return last, 0, 0
}

// pendingFor lists PDUs owed to dest after stream position `after`.
func (s *Server) pendingFor(dest string, after int64) ([]int64, []json.RawMessage, error) {
	rows, err := s.db.Query(`SELECT e.stream, e.pdu FROM events e JOIN rooms r ON r.room_id = e.room_id AND r.federated = 1
		WHERE e.stream > ? AND e.hidden = 0 AND e.pdu IS NOT NULL
		AND substr(e.sender, -length(?) - 1) != ':' || ?
		AND (substr(e.sender, -length(?) - 1) = ':' || ? OR e.relay = 1)
		AND (EXISTS (SELECT 1 FROM memberships m WHERE m.room_id = e.room_id AND m.membership = 'join'
				AND substr(m.user_id, -length(?) - 1) = ':' || ?)
			OR (e.type = 'm.room.member' AND substr(e.state_key, -length(?) - 1) = ':' || ?))
		ORDER BY e.stream LIMIT ?`,
		after, dest, dest, s.cfg.ServerName, s.cfg.ServerName, dest, dest, dest, dest, fedTxnPDUs)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var streams []int64
	var pdus []json.RawMessage
	for rows.Next() {
		var st int64
		var pdu string
		if err := rows.Scan(&st, &pdu); err != nil {
			return nil, nil, err
		}
		streams = append(streams, st)
		pdus = append(pdus, json.RawMessage(pdu))
	}
	return streams, pdus, rows.Err()
}

func (s *Server) sendTo(dest string) {
	last, retryAt, backoff := s.destState(dest)
	if time.Now().UnixMilli() < retryAt {
		return
	}
	upTo := s.committed.Load()
	for round := 0; round < fedMaxRounds; round++ {
		streams, pdus, err := s.pendingFor(dest, last)
		if err != nil {
			log.Printf("federation: pending for %s: %v", dest, err)
			return
		}
		s.fedOut.mu.Lock()
		edus := s.fedOut.edus[dest]
		if len(edus) > 100 {
			edus = edus[:100]
		}
		s.fedOut.edus[dest] = s.fedOut.edus[dest][len(edus):]
		if len(s.fedOut.edus[dest]) == 0 {
			delete(s.fedOut.edus, dest)
		}
		s.fedOut.mu.Unlock()
		// EDUs kept in the database (to-device messages, device list changes)
		var storedIDs []int64
		if rows, err := s.db.Query("SELECT id, edu FROM fed_edus WHERE dest = ? ORDER BY id LIMIT ?", dest, 100-len(edus)); err == nil {
			for rows.Next() {
				var id int64
				var raw string
				rows.Scan(&id, &raw)
				var e map[string]any
				if json.Unmarshal([]byte(raw), &e) == nil {
					edus = append(edus, e)
				}
				storedIDs = append(storedIDs, id)
			}
			rows.Close()
		}
		if len(pdus) == 0 && len(edus) == 0 {
			if last < upTo {
				s.db.Exec("UPDATE fed_destinations SET last_stream = ? WHERE server = ? AND last_stream < ?", upTo, dest, upTo)
			}
			return
		}
		if pdus == nil {
			pdus = []json.RawMessage{}
		}
		if edus == nil {
			edus = []map[string]any{}
		}
		txnID := strconv.FormatInt(time.Now().UnixNano(), 36)
		body := map[string]any{"origin": s.cfg.ServerName, "origin_server_ts": nowMS(), "pdus": pdus, "edus": edus}
		ctx, cancel := context.WithTimeout(context.Background(), fedSendTimeout)
		err = s.fedRequest(ctx, "PUT", dest, "/_matrix/federation/v1/send/"+txnID, body, nil)
		cancel()
		if err != nil {
			next := time.Duration(backoff) * time.Millisecond * 2
			if next < fedMinBackoff {
				next = fedMinBackoff
			}
			if next > fedMaxBackoff {
				next = fedMaxBackoff
			}
			s.db.Exec("UPDATE fed_destinations SET retry_at = ?, backoff = ? WHERE server = ?",
				time.Now().Add(next).UnixMilli(), next.Milliseconds(), dest)
			log.Printf("federation: sending to %s failed (retry in %s): %v", dest, next, err)
			return
		}
		if len(streams) > 0 {
			last = streams[len(streams)-1]
		}
		backoff = 0
		s.db.Exec("UPDATE fed_destinations SET last_stream = ?, retry_at = 0, backoff = 0 WHERE server = ?", last, dest)
		for _, id := range storedIDs {
			s.db.Exec("DELETE FROM fed_edus WHERE id = ?", id)
		}
	}
	s.kickSender() // more left: come back soon
}

// ---- joining a room on another server ----

// joinRemote tries each server until one lets us in.
func (s *Server) joinRemote(ctx context.Context, uid, roomID string, servers []string) error {
	if !s.cfg.Federation {
		return errForbidden("federation is disabled on this server")
	}
	seen := map[string]bool{s.cfg.ServerName: true}
	var cands []string
	for _, sv := range append(append([]string(nil), servers...), domainOf(roomID)) {
		if sv != "" && !seen[sv] && validHostPort(sv) {
			seen[sv] = true
			cands = append(cands, sv)
		}
	}
	if len(cands) > 5 {
		cands = cands[:5]
	}
	var lastErr error = errNotFound("no server to join the room through")
	for _, sv := range cands {
		err := s.joinVia(ctx, uid, roomID, sv)
		if err == nil {
			return nil
		}
		log.Printf("federation: joining %s via %s: %v", roomID, sv, err)
		lastErr = err
		var fe *fedError
		if errors.As(err, &fe) && fe.status == 403 {
			return errForbidden("the room's server refused the join: " + fe.msg)
		}
	}
	var ae *apiError
	if errors.As(lastErr, &ae) {
		return lastErr
	}
	return errf(502, "M_UNKNOWN", "couldn't join the room through %s", strings.Join(cands, ", "))
}

func (s *Server) joinVia(ctx context.Context, uid, roomID, server string) error {
	var tmpl struct {
		RoomVersion string         `json:"room_version"`
		Event       map[string]any `json:"event"`
	}
	uri := "/_matrix/federation/v1/make_join/" + pathEscape(roomID) + "/" + pathEscape(uid) + "?ver=10&ver=11"
	if err := s.fedRequest(ctx, "GET", server, uri, nil, &tmpl); err != nil {
		return err
	}
	version := tmpl.RoomVersion
	if version == "" {
		version = "1"
	}
	rules, ok := rulesFor(version)
	if !ok {
		return errf(400, "M_UNSUPPORTED_ROOM_VERSION", "room version %s isn't supported", version)
	}
	pdu, err := s.fillTemplate(tmpl.Event, roomID, uid, "join")
	if err != nil {
		return err
	}
	eventID, err := hashAndSign(rules, pdu, s.cfg.ServerName, s.fedKey)
	if err != nil {
		return err
	}
	var resp struct {
		State     []json.RawMessage `json:"state"`
		AuthChain []json.RawMessage `json:"auth_chain"`
		Event     json.RawMessage   `json:"event"`
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	uri = "/_matrix/federation/v2/send_join/" + pathEscape(roomID) + "/" + pathEscape(eventID)
	if err := s.fedRequestLimit(ctx, "PUT", server, uri, pdu, &resp, sendJoinLimit); err != nil {
		return err
	}
	if len(resp.State)+len(resp.AuthChain) > maxJoinEvents {
		return errf(413, "M_TOO_LARGE", "this room is too large for this server to join")
	}
	join := fedEvent{}
	joinRaw, _ := canonicalJSON(pdu)
	if len(resp.Event) > 0 { // the resident server may have co-signed a restricted join
		joinRaw = resp.Event
	}
	jev, jpdu, err := parsePDU(version, joinRaw)
	if err != nil || jev.EventID != eventID {
		return fmt.Errorf("send_join returned a different event: %v", err)
	}
	// Check everything the room's state is made of.
	keys := map[string]map[string]int64{}
	var all []fedEvent
	var stateIDs []string
	for i, list := range [][]json.RawMessage{resp.State, resp.AuthChain} {
		for _, raw := range list {
			ev, pdu, err := parsePDU(version, raw)
			if err != nil || ev.RoomID != roomID {
				continue
			}
			sigs, _ := pdu["signatures"].(map[string]any)
			if ks, _ := sigs[domainOf(ev.Sender)].(map[string]any); ks != nil {
				for id := range ks {
					if keys[domainOf(ev.Sender)] == nil {
						keys[domainOf(ev.Sender)] = map[string]int64{}
					}
					keys[domainOf(ev.Sender)][id] = ev.OriginTS
				}
			}
			all = append(all, fedEvent{ev: ev, pdu: pdu})
			if i == 0 && ev.StateKey != nil {
				stateIDs = append(stateIDs, ev.EventID)
			}
		}
	}
	s.prefetchKeys(ctx, keys)
	var good []fedEvent
	for _, fe := range all {
		pdu, err := s.verifyPDU(ctx, version, fe.ev, fe.pdu)
		if err != nil {
			log.Printf("federation: joining %s: dropping %s: %v", roomID, fe.ev.EventID, err)
			continue
		}
		good = append(good, fedEvent{ev: fe.ev, pdu: pdu})
	}
	if jpdu, err = s.verifyPDU(ctx, version, jev, jpdu); err != nil {
		return fmt.Errorf("join event: %w", err)
	}
	join = fedEvent{ev: jev, pdu: jpdu}
	var create *Event
	for _, fe := range good {
		if fe.ev.Type == "m.room.create" && fe.ev.StateKey != nil && *fe.ev.StateKey == "" {
			create = fe.ev
		}
	}
	if create == nil {
		return errors.New("room state has no create event")
	}
	err = s.write(func(tx *sql.Tx) error {
		if ri, ok := getRoomInfo(tx, roomID); ok && !ri.federated {
			return errForbidden("room ID clashes with a local room")
		}
		if _, err := tx.Exec(`INSERT INTO rooms (room_id, version, creator, published, created_ts, federated)
			VALUES (?,?,?,0,?,1) ON CONFLICT (room_id) DO UPDATE SET federated = 1, version = excluded.version`,
			roomID, version, create.Sender, nowMS()); err != nil {
			return err
		}
		if err := s.storeOutliers(tx, version, good); err != nil {
			return err
		}
		get := pduGetter(tx, nil)
		state := stateMap{}
		for _, id := range stateIDs {
			if e := get(id); e != nil && !e.Rejected && e.StateKey != nil {
				state[stateTuple{e.Type, *e.StateKey}] = id
			}
		}
		if err := checkAgainstState(version, join.ev, state, get); err != nil {
			return fmt.Errorf("our join isn't allowed by the room state we got: %w", err)
		}
		after := stateMap{}
		for k, v := range state {
			after[k] = v
		}
		after[stateTuple{"m.room.member", uid}] = join.ev.EventID
		g, err := addStateGroupFor(tx, roomID, 0, nil, after)
		if err != nil {
			return err
		}
		if hidden, _, ok := haveEvent(tx, join.ev.EventID); ok && hidden == evOutlier {
			tx.Exec("DELETE FROM events WHERE event_id = ?", join.ev.EventID)
		}
		if err := s.insertPDU(tx, join.ev, join.pdu, evVisible, g); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM room_extremities WHERE room_id = ?", roomID); err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO room_extremities (room_id, event_id, depth) VALUES (?,?,?)", roomID, join.ev.EventID, join.ev.Depth); err != nil {
			return err
		}
		if err := s.setCurrentState(tx, roomID, g, after, join.ev.Stream); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM remote_invites WHERE room_id = ? AND user_id = ?", roomID, uid); err != nil {
			return err
		}
		// they get our join from the resident server; start after it
		for _, d := range s.roomServers(tx, roomID) {
			tx.Exec(`INSERT INTO fed_destinations (server, last_stream, retry_at, backoff) VALUES (?,?,0,0)
				ON CONFLICT (server) DO NOTHING`, d, join.ev.Stream)
		}
		return nil
	})
	if err == nil {
		s.kickSender()
	}
	return err
}

// fillTemplate turns a make_join/make_leave template into our event.
func (s *Server) fillTemplate(t map[string]any, roomID, uid, membership string) (map[string]any, error) {
	if t == nil || t["room_id"] != roomID || t["sender"] != uid || t["state_key"] != uid || t["type"] != "m.room.member" {
		return nil, errors.New("the server sent a bad event template")
	}
	content, _ := t["content"].(map[string]any)
	if content == nil || content["membership"] != membership {
		return nil, errors.New("the server sent a bad event template")
	}
	full := s.memberContent(s.db, uid, membership, nil)
	if au, ok := content["join_authorised_via_users_server"]; ok {
		full["join_authorised_via_users_server"] = au
	}
	pdu := map[string]any{}
	for _, k := range []string{"type", "room_id", "sender", "state_key", "depth", "prev_events", "auth_events"} {
		v, ok := t[k]
		if !ok {
			return nil, fmt.Errorf("template has no %s", k)
		}
		pdu[k] = v
	}
	// re-decode so numbers are exact
	b, err := canonicalJSON(pdu)
	if err != nil {
		return nil, err
	}
	v, _ := decodeJSONNumbers(b)
	pdu = v.(map[string]any)
	pdu["content"] = full
	pdu["origin_server_ts"] = nowMS()
	return pdu, nil
}

// ---- inviting a user of another server ----

var errBuildOnly = errors.New("build only")

// inviteRemote: we sign, their server co-signs, then it goes in the room.
func (s *Server) inviteRemote(ctx context.Context, sess *Session, roomID, target, reason string, isDirect bool) error {
	if !s.cfg.Federation {
		return errForbidden("federation is disabled on this server")
	}
	if !isUserID(target) || !validHostPort(domainOf(target)) {
		return errInvalidParam("invalid user ID")
	}
	ri, ok := getRoomInfo(s.db, roomID)
	if !ok {
		return errNotFound("room not found")
	}
	if !ri.federated {
		return errForbidden("this room can't have members from other servers (created without federation or with m.federate: false)")
	}
	content := map[string]any{"membership": "invite"}
	if reason != "" {
		content["reason"] = reason
	}
	if isDirect {
		content["is_direct"] = true
	}
	var pduJSON string
	var ev *Event
	err := s.write(func(tx *sql.Tx) error {
		if err := s.authorizeBase(tx, roomID); err != nil {
			return err
		}
		ev = s.newEvent(roomID, sess.UserID, "m.room.member", sp(target), content)
		if err := s.storeEvent(tx, ev); err != nil {
			return err
		}
		if err := tx.QueryRow("SELECT pdu FROM events WHERE event_id = ?", ev.EventID).Scan(&pduJSON); err != nil {
			return err
		}
		return errBuildOnly // keep nothing: their server must sign first
	})
	if err != errBuildOnly {
		return err
	}
	var invite struct {
		Event json.RawMessage `json:"event"`
	}
	body := map[string]any{"room_version": ri.version, "event": json.RawMessage(pduJSON),
		"invite_room_state": s.strippedState(roomID, target)}
	uri := "/_matrix/federation/v2/invite/" + pathEscape(roomID) + "/" + pathEscape(ev.EventID)
	if err := s.fedRequest(ctx, "PUT", domainOf(target), uri, body, &invite); err != nil {
		var fe *fedError
		if errors.As(err, &fe) && fe.status < 500 {
			return errForbidden("the user's server refused the invite: " + fe.msg)
		}
		log.Printf("federation: inviting %s: %v", target, err)
		return errf(502, "M_UNKNOWN", "couldn't reach %s", domainOf(target))
	}
	iev, ipdu, err := parsePDU(ri.version, invite.Event)
	if err != nil || iev.EventID != ev.EventID {
		return errf(502, "M_UNKNOWN", "the user's server returned a different event")
	}
	if ipdu, err = s.verifyPDU(ctx, ri.version, iev, ipdu); err != nil {
		return errf(502, "M_UNKNOWN", "bad invite signature: %v", err)
	}
	sigs, _ := ipdu["signatures"].(map[string]any)
	if _, ok := sigs[domainOf(target)]; !ok {
		return errf(502, "M_UNKNOWN", "the user's server didn't sign the invite")
	}
	r, _ := rulesFor(ri.version)
	if verifyPDUSignature(r, ipdu, s.cfg.ServerName, s.fedKey.id, s.fedKey.public()) != nil {
		return errf(502, "M_UNKNOWN", "the invite lost our signature")
	}
	err = s.write(func(tx *sql.Tx) error { return s.persistTimelineEvent(tx, ri.version, iev, ipdu) })
	if err == nil {
		s.kickSender()
	}
	return err
}

// authorizeBase: the room exists and isn't shut down.
func (s *Server) authorizeBase(tx *sql.Tx, roomID string) error {
	var blocked int
	if tx.QueryRow("SELECT blocked FROM rooms WHERE room_id = ?", roomID).Scan(&blocked) != nil {
		return errNotFound("room not found")
	}
	if blocked == 1 {
		return errForbidden("this room has been shut down by the server admin")
	}
	return nil
}

// ---- declining an invite from another server ----

func (s *Server) rejectRemoteInvite(ctx context.Context, uid, roomID string) error {
	var inviteID, version string
	if s.db.QueryRow("SELECT event_id, room_version FROM remote_invites WHERE room_id = ? AND user_id = ?", roomID, uid).Scan(&inviteID, &version) != nil {
		return errNotFound("no invite to this room")
	}
	inv, _ := getEvent(s.db, inviteID)
	var leave *fedEvent
	if inv != nil && s.cfg.Federation {
		if fe, err := s.leaveVia(ctx, uid, roomID, domainOf(inv.Sender), version); err != nil {
			log.Printf("federation: declining invite to %s: %v (forgetting it locally)", roomID, err)
		} else {
			leave = &fe
		}
	}
	return s.write(func(tx *sql.Tx) error {
		var st int64
		if leave != nil {
			if _, _, ok := haveEvent(tx, leave.ev.EventID); !ok {
				if err := s.insertPDU(tx, leave.ev, leave.pdu, evOutlier, 0); err != nil {
					return err
				}
			}
			st = s.nextFor(change{user: uid})
		} else {
			st = s.nextFor(change{user: uid})
		}
		if _, err := tx.Exec("DELETE FROM remote_invites WHERE room_id = ? AND user_id = ?", roomID, uid); err != nil {
			return err
		}
		_, err := tx.Exec("UPDATE memberships SET membership = 'leave', stream = ? WHERE room_id = ? AND user_id = ?", st, roomID, uid)
		return err
	})
}

func (s *Server) leaveVia(ctx context.Context, uid, roomID, server, version string) (fedEvent, error) {
	var tmpl struct {
		Event map[string]any `json:"event"`
	}
	uri := "/_matrix/federation/v1/make_leave/" + pathEscape(roomID) + "/" + pathEscape(uid)
	if err := s.fedRequest(ctx, "GET", server, uri, nil, &tmpl); err != nil {
		return fedEvent{}, err
	}
	rules, ok := rulesFor(version)
	if !ok {
		return fedEvent{}, errors.New("unsupported room version")
	}
	pdu, err := s.fillTemplate(tmpl.Event, roomID, uid, "leave")
	if err != nil {
		return fedEvent{}, err
	}
	id, err := hashAndSign(rules, pdu, s.cfg.ServerName, s.fedKey)
	if err != nil {
		return fedEvent{}, err
	}
	uri = "/_matrix/federation/v2/send_leave/" + pathEscape(roomID) + "/" + pathEscape(id)
	if err := s.fedRequest(ctx, "PUT", server, uri, pdu, nil); err != nil {
		return fedEvent{}, err
	}
	raw, _ := canonicalJSON(pdu)
	ev, p, err := parsePDU(version, raw)
	if err != nil {
		return fedEvent{}, err
	}
	return fedEvent{ev: ev, pdu: p}, nil
}

var _ = strings.HasPrefix
