package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Federation endpoints. A server only sees rooms its users are in; history
// from before it joined is redacted if the room is members-only (like Synapse).

func pathEscape(s string) string  { return url.PathEscape(s) }
func queryEscape(s string) string { return url.QueryEscape(s) }

// userOfServer is the SQL test "user_id belongs to server ?".
const userOfServer = "substr(user_id, -length(?) - 1) = ':' || ?"

func serverInRoom(q querier, roomID, server string) bool {
	var x int
	return q.QueryRow("SELECT 1 FROM memberships WHERE room_id = ? AND membership = 'join' AND "+userOfServer+" LIMIT 1",
		roomID, server, server).Scan(&x) == nil
}

// roomServers lists the other servers with users joined to the room.
func (s *Server) roomServers(q querier, roomID string) []string {
	rows, err := q.Query("SELECT user_id FROM memberships WHERE room_id = ? AND membership = 'join'", roomID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var u string
		rows.Scan(&u)
		if d := domainOf(u); d != "" && d != s.cfg.ServerName && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

// aclAllows applies the room's m.room.server_acl to a server.
func aclAllows(q querier, roomID, server string) bool {
	e, err := getStateEvent(q, roomID, "m.room.server_acl", "")
	if err != nil || e == nil {
		return true
	}
	host := server
	if h, _, err := net.SplitHostPort(server); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	c := contentOf(e)
	if v, ok := c["allow_ip_literals"]; ok && v == false && net.ParseIP(host) != nil {
		return false
	}
	match := func(key string) bool {
		list, _ := c[key].([]any)
		for _, p := range list {
			if ps, ok := p.(string); ok && globMatch(ps, host, false) {
				return true
			}
		}
		return false
	}
	return !match("deny") && match("allow")
}

func (s *Server) federatedRoom(q querier, roomID string) (roomInfo, error) {
	ri, ok := getRoomInfo(q, roomID)
	if !ok || !ri.federated {
		return ri, errNotFound("unknown room")
	}
	return ri, nil
}

// checkServerAccess: the room is federated, the server is in it and allowed.
func (s *Server) checkServerAccess(q querier, roomID, server string) (roomInfo, error) {
	ri, err := s.federatedRoom(q, roomID)
	if err != nil {
		return ri, err
	}
	if !aclAllows(q, roomID, server) {
		return ri, errForbidden("server is banned by the room's ACL")
	}
	if !serverInRoom(q, roomID, server) {
		return ri, errForbidden("server is not in the room")
	}
	return ri, nil
}

// pduForServer returns the event, redacted if server couldn't see it back then.
func (s *Server) pduForServer(q querier, id, server string) (map[string]any, *storedPDU, error) {
	return s.pduFor(q, id, server, true)
}

// statePDU: state and auth events skip the history check.
func (s *Server) statePDU(q querier, id, server string) (map[string]any, *storedPDU, error) {
	return s.pduFor(q, id, server, false)
}

func (s *Server) pduFor(q querier, id, server string, checkHistory bool) (map[string]any, *storedPDU, error) {
	sp, err := loadPDU(q, id)
	if err != nil || sp == nil || sp.hidden == evRejected {
		return nil, nil, errNotFound("event not found")
	}
	v, err := decodeJSONNumbers([]byte(sp.pdu))
	if err != nil {
		return nil, nil, err
	}
	pdu := v.(map[string]any)
	if checkHistory && sp.group.Valid && !historyVisibleTo(q, sp.group.Int64, server) {
		r, _ := rulesFor(roomVersion(q, sp.ev.RoomID))
		pdu = redactPDU(r, pdu)
	}
	return pdu, sp, nil
}

// historyVisibleTo: in the given state, may server's users see events?
func historyVisibleTo(q querier, group int64, server string) bool {
	st, err := loadStateGroup(q, group)
	if err != nil {
		return false
	}
	vis := "shared"
	if id, ok := st[stateTuple{"m.room.history_visibility", ""}]; ok {
		if e, _ := getEvent(q, id); e != nil {
			if v, _ := contentOf(e)["history_visibility"].(string); v != "" {
				vis = v
			}
		}
	}
	if vis == "world_readable" || vis == "shared" {
		return true
	}
	for k, id := range st {
		if k.typ != "m.room.member" || domainOf(k.key) != server {
			continue
		}
		e, _ := getEvent(q, id)
		if m := membershipOf(e); m == "join" || (vis == "invited" && m == "invite") {
			return true
		}
	}
	return false
}

func (s *Server) fedResponse(pdus []any) map[string]any {
	return map[string]any{"origin": s.cfg.ServerName, "origin_server_ts": nowMS(), "pdus": pdus}
}

func (s *Server) hFedEvent(w http.ResponseWriter, r *http.Request, origin string, _ []byte) (any, error) {
	pdu, sp, err := s.pduForServer(s.db, r.PathValue("eventId"), origin)
	if err != nil {
		return nil, err
	}
	if _, err := s.checkServerAccess(s.db, sp.ev.RoomID, origin); err != nil {
		return nil, errNotFound("event not found")
	}
	return s.fedResponse([]any{pdu}), nil
}

// stateBeforeEvent is the room state just before a stored event.
func stateBeforeEvent(q *sql.Tx, version string, ev *Event) (stateMap, error) {
	if len(ev.PrevEvents) == 0 {
		return stateMap{}, nil
	}
	st, _, err := stateBefore(q, version, ev, pduGetter(q, nil))
	return st, err
}

// readTx runs fn in a read-only transaction (for consistent multi-query reads).
func (s *Server) readTx(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return fn(tx)
}

func (s *Server) stateForServer(r *http.Request, origin string, full bool) (any, error) {
	roomID, eventID := r.PathValue("roomId"), r.URL.Query().Get("event_id")
	var out map[string]any
	err := s.readTx(func(tx *sql.Tx) error {
		ri, err := s.checkServerAccess(tx, roomID, origin)
		if err != nil {
			return err
		}
		sp, err := loadPDU(tx, eventID)
		if err != nil || sp == nil || sp.ev.RoomID != roomID || sp.hidden == evRejected {
			return errNotFound("event not found")
		}
		st, err := stateBeforeEvent(tx, ri.version, sp.ev)
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(st))
		for _, id := range st {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		chain := authChain(ids, pduGetter(tx, nil))
		for _, id := range ids {
			delete(chain, id)
		}
		var chainIDs []string
		for id := range chain {
			chainIDs = append(chainIDs, id)
		}
		sort.Strings(chainIDs)
		if !full {
			out = map[string]any{"pdu_ids": ids, "auth_chain_ids": chainIDs}
			return nil
		}
		pdus, err := s.statePDUs(tx, ids, origin)
		if err != nil {
			return err
		}
		chainPDUs, err := s.statePDUs(tx, chainIDs, origin)
		if err != nil {
			return err
		}
		out = map[string]any{"pdus": pdus, "auth_chain": chainPDUs}
		return nil
	})
	return out, err
}

// statePDUs returns state / auth chain events for a server.
func (s *Server) statePDUs(q querier, ids []string, server string) ([]any, error) {
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		pdu, _, err := s.statePDU(q, id, server)
		if err != nil {
			continue
		}
		out = append(out, pdu)
	}
	return out, nil
}

func (s *Server) hFedStateIDs(w http.ResponseWriter, r *http.Request, origin string, _ []byte) (any, error) {
	return s.stateForServer(r, origin, false)
}

func (s *Server) hFedState(w http.ResponseWriter, r *http.Request, origin string, _ []byte) (any, error) {
	return s.stateForServer(r, origin, true)
}

func (s *Server) hFedEventAuth(w http.ResponseWriter, r *http.Request, origin string, _ []byte) (any, error) {
	roomID := r.PathValue("roomId")
	var out any
	err := s.readTx(func(tx *sql.Tx) error {
		if _, err := s.checkServerAccess(tx, roomID, origin); err != nil {
			return err
		}
		sp, err := loadPDU(tx, r.PathValue("eventId"))
		if err != nil || sp == nil || sp.ev.RoomID != roomID {
			return errNotFound("event not found")
		}
		chain := authChain(sp.ev.AuthEvents, pduGetter(tx, nil))
		ids := make([]string, 0, len(chain))
		for id := range chain {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		pdus, err := s.statePDUs(tx, ids, origin)
		out = map[string]any{"auth_chain": pdus}
		return err
	})
	return out, err
}

// walkBack walks prev_events back from start (newest first), stopping at stop.
func walkBack(q querier, start []string, stop map[string]bool, limit int, minDepth int64, includeStart bool) []string {
	get := pduGetter(q, nil)
	seen := map[string]bool{}
	var out []string
	frontier := append([]string(nil), start...)
	if !includeStart {
		frontier = nil
		for _, id := range start {
			seen[id] = true
			if e := get(id); e != nil {
				frontier = append(frontier, e.PrevEvents...)
			}
		}
	}
	for len(frontier) > 0 && len(out) < limit {
		// newest (deepest) first
		sort.Slice(frontier, func(i, j int) bool {
			a, b := get(frontier[i]), get(frontier[j])
			if a == nil || b == nil {
				return a != nil
			}
			return a.Depth > b.Depth
		})
		id := frontier[0]
		frontier = frontier[1:]
		if seen[id] || stop[id] {
			continue
		}
		seen[id] = true
		e := get(id)
		if e == nil || e.Depth < minDepth {
			continue
		}
		out = append(out, id)
		frontier = append(frontier, e.PrevEvents...)
	}
	return out
}

func (s *Server) hFedMissingEvents(w http.ResponseWriter, r *http.Request, origin string, body []byte) (any, error) {
	var req struct {
		Earliest []string `json:"earliest_events"`
		Latest   []string `json:"latest_events"`
		Limit    int      `json:"limit"`
		MinDepth int64    `json:"min_depth"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errBadJSON("invalid body")
	}
	if req.Limit <= 0 || req.Limit > 20 {
		req.Limit = 10
	}
	roomID := r.PathValue("roomId")
	var out any
	err := s.readTx(func(tx *sql.Tx) error {
		if _, err := s.checkServerAccess(tx, roomID, origin); err != nil {
			return err
		}
		stop := map[string]bool{}
		for _, id := range req.Earliest {
			stop[id] = true
		}
		ids := walkBack(tx, req.Latest, stop, req.Limit, req.MinDepth, false)
		var evs []any
		for i := len(ids) - 1; i >= 0; i-- {
			if pdu, sp, err := s.pduForServer(tx, ids[i], origin); err == nil && sp.ev.RoomID == roomID {
				evs = append(evs, pdu)
			}
		}
		if evs == nil {
			evs = []any{}
		}
		out = map[string]any{"events": evs}
		return nil
	})
	return out, err
}

func (s *Server) hFedBackfill(w http.ResponseWriter, r *http.Request, origin string, _ []byte) (any, error) {
	roomID := r.PathValue("roomId")
	limit := atoiDefault(r.URL.Query().Get("limit"), 50)
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	var out any
	err := s.readTx(func(tx *sql.Tx) error {
		if _, err := s.checkServerAccess(tx, roomID, origin); err != nil {
			return err
		}
		ids := walkBack(tx, r.URL.Query()["v"], nil, limit, 0, true)
		var pdus []any
		for _, id := range ids {
			if pdu, sp, err := s.pduForServer(tx, id, origin); err == nil && sp.ev.RoomID == roomID {
				pdus = append(pdus, pdu)
			}
		}
		if pdus == nil {
			pdus = []any{}
		}
		out = s.fedResponse(pdus)
		return nil
	})
	return out, err
}

// ---- transactions ----

type txnSeen struct {
	mu   sync.Mutex
	seen map[string]map[string]any
}

func (s *Server) hFedSend(w http.ResponseWriter, r *http.Request, origin string, body []byte) (any, error) {
	if s.fedRefuseTxns.Load() {
		return nil, errf(503, "M_UNKNOWN", "not now")
	}
	var txn struct {
		Origin string            `json:"origin"`
		PDUs   []json.RawMessage `json:"pdus"`
		EDUs   []json.RawMessage `json:"edus"`
	}
	if err := json.Unmarshal(body, &txn); err != nil {
		return nil, errBadJSON("invalid transaction")
	}
	if txn.Origin != "" && txn.Origin != origin {
		return nil, errForbidden("origin doesn't match the request signature")
	}
	if len(txn.PDUs) > 50 || len(txn.EDUs) > 100 {
		return nil, errBadJSON("too many PDUs or EDUs in one transaction")
	}
	key := origin + "\x00" + r.PathValue("txnId")
	s.fedTxns.mu.Lock()
	if res, ok := s.fedTxns.seen[key]; ok {
		s.fedTxns.mu.Unlock()
		return res, nil
	}
	s.fedTxns.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
	defer cancel()
	results := map[string]any{}
	for _, raw := range txn.PDUs {
		var head struct {
			RoomID string `json:"room_id"`
		}
		json.Unmarshal(raw, &head)
		ri, ok := getRoomInfo(s.db, head.RoomID)
		if !ok || !ri.federated || !s.localMemberIn(head.RoomID) {
			continue // not a room we're in: nothing to key the result by
		}
		ev, pdu, err := parsePDU(ri.version, raw)
		if err != nil {
			log.Printf("federation: bad PDU from %s: %v", origin, err)
			continue
		}
		if !aclAllows(s.db, head.RoomID, origin) || !aclAllows(s.db, head.RoomID, domainOf(ev.Sender)) {
			results[ev.EventID] = map[string]any{"error": "server is banned by the room's ACL"}
			continue
		}
		if pdu, err = s.verifyPDU(ctx, ri.version, ev, pdu); err != nil {
			results[ev.EventID] = map[string]any{"error": err.Error()}
			continue
		}
		if err := s.handlePDU(ctx, origin, ri.version, fedEvent{ev: ev, pdu: pdu}, true); err != nil {
			log.Printf("federation: PDU %s from %s: %v", ev.EventID, origin, err)
			results[ev.EventID] = map[string]any{"error": err.Error()}
			continue
		}
		results[ev.EventID] = map[string]any{}
	}
	for _, raw := range txn.EDUs {
		s.handleEDU(origin, raw)
	}
	res := map[string]any{"pdus": results}
	s.fedTxns.mu.Lock()
	if len(s.fedTxns.seen) > 1000 {
		s.fedTxns.seen = map[string]map[string]any{}
	}
	s.fedTxns.seen[key] = res
	s.fedTxns.mu.Unlock()
	return res, nil
}

// localMemberIn: one of our users is joined to the room.
func (s *Server) localMemberIn(roomID string) bool {
	return serverInRoom(s.db, roomID, s.cfg.ServerName)
}

// handleEDU handles typing notifications and read receipts from other servers.
func (s *Server) handleEDU(origin string, raw json.RawMessage) {
	var edu struct {
		Type    string          `json:"edu_type"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &edu) != nil {
		return
	}
	if s.handleE2EEDU(origin, edu.Type, edu.Content) {
		return
	}
	switch edu.Type {
	case "m.typing":
		var c struct {
			RoomID string `json:"room_id"`
			UserID string `json:"user_id"`
			Typing bool   `json:"typing"`
		}
		if json.Unmarshal(edu.Content, &c) != nil || domainOf(c.UserID) != origin {
			return
		}
		if m, _ := getMembership(s.db, c.RoomID, c.UserID); m != "join" || !s.localMemberIn(c.RoomID) {
			return
		}
		s.setTyping(c.RoomID, c.UserID, c.Typing, 30000)
	case "m.receipt":
		var c map[string]map[string]map[string]struct {
			EventIDs []string `json:"event_ids"`
			Data     struct {
				TS int64 `json:"ts"`
			} `json:"data"`
		}
		if json.Unmarshal(edu.Content, &c) != nil {
			return
		}
		for room, types := range c {
			if !s.localMemberIn(room) {
				continue
			}
			for uid, rc := range types["m.read"] {
				if domainOf(uid) != origin || len(rc.EventIDs) == 0 {
					continue
				}
				if m, _ := getMembership(s.db, room, uid); m != "join" {
					continue
				}
				evID := rc.EventIDs[0]
				s.write(func(tx *sql.Tx) error {
					var x int
					if tx.QueryRow("SELECT 1 FROM events WHERE event_id = ? AND room_id = ? AND hidden = 0", evID, room).Scan(&x) != nil {
						return nil
					}
					st := s.nextFor(change{room: room})
					_, err := tx.Exec(`INSERT OR REPLACE INTO receipts (room_id, user_id, type, event_id, ts, stream)
						VALUES (?,?,?,?,?,?)`, room, uid, "m.read", evID, rc.Data.TS, st)
					return err
				})
			}
		}
	}
}

// ---- joining and leaving through us ----

func (s *Server) hFedMakeMembership(membership string) fedHandler {
	return func(w http.ResponseWriter, r *http.Request, origin string, _ []byte) (any, error) {
		roomID, uid := r.PathValue("roomId"), r.PathValue("userId")
		if domainOf(uid) != origin || !isUserID(uid) {
			return nil, errForbidden("user is not from the requesting server")
		}
		var out any
		err := s.readTx(func(tx *sql.Tx) error {
			ri, err := s.federatedRoom(tx, roomID)
			if err != nil {
				return err
			}
			if !aclAllows(tx, roomID, origin) {
				return errForbidden("server is banned by the room's ACL")
			}
			if !serverInRoom(tx, roomID, s.cfg.ServerName) {
				return errNotFound("this server is not in the room")
			}
			if membership == "join" {
				vers := r.URL.Query()["ver"]
				if len(vers) == 0 {
					vers = []string{"1"}
				}
				ok := false
				for _, v := range vers {
					ok = ok || v == ri.version
				}
				if !ok {
					return &apiError{Status: 400, Code: "M_INCOMPATIBLE_ROOM_VERSION", Msg: "room version " + ri.version,
						Extra: map[string]any{"room_version": ri.version}}
				}
			}
			content := map[string]any{"membership": membership}
			if membership == "join" {
				if m, _ := getMembership(tx, roomID, uid); m != "invite" && m != "join" {
					if au := s.joinAuthoriser(tx, roomID, uid); au != "" {
						content["join_authorised_via_users_server"] = au
					}
				}
			}
			ev := s.newEvent(roomID, uid, "m.room.member", sp(uid), content)
			ev.OriginTS = nowMS()
			auth, authIDs, err := loadAuthState(tx, ev)
			if err != nil {
				return err
			}
			prevs, depth, err := prevEventsFor(tx, roomID, true)
			if err != nil {
				return err
			}
			if err := checkAuth(ri.version, ev, prevs, auth); err != nil {
				return err
			}
			if authIDs == nil {
				authIDs = []string{}
			}
			out = map[string]any{"room_version": ri.version, "event": map[string]any{
				"type": "m.room.member", "room_id": roomID, "sender": uid, "state_key": uid, "content": content,
				"origin_server_ts": ev.OriginTS, "depth": depth, "prev_events": prevs, "auth_events": authIDs}}
			return nil
		})
		return out, err
	}
}

// hFedSendMembership handles send_join / send_leave. We co-sign restricted joins.
func (s *Server) hFedSendMembership(membership string) fedHandler {
	return func(w http.ResponseWriter, r *http.Request, origin string, body []byte) (any, error) {
		roomID := r.PathValue("roomId")
		ri, err := s.federatedRoom(s.db, roomID)
		if err != nil {
			return nil, err
		}
		if !aclAllows(s.db, roomID, origin) {
			return nil, errForbidden("server is banned by the room's ACL")
		}
		ev, pdu, err := parsePDU(ri.version, body)
		if err != nil {
			return nil, errBadJSON(err.Error())
		}
		if ev.EventID != r.PathValue("eventId") || ev.RoomID != roomID {
			return nil, errBadJSON("event ID or room doesn't match the URL")
		}
		if ev.Type != "m.room.member" || ev.StateKey == nil || *ev.StateKey != ev.Sender || domainOf(ev.Sender) != origin {
			return nil, errForbidden("expected a membership event of a user of the requesting server")
		}
		if membershipOf(ev) != membership {
			return nil, errBadJSON("expected membership " + membership)
		}
		rules, _ := rulesFor(ri.version)
		if au, ok := contentOf(ev)["join_authorised_via_users_server"].(string); ok && membership == "join" && s.isLocal(au) {
			red := without(redactPDU(rules, pdu), "unsigned")
			if err := signJSON(red, s.cfg.ServerName, s.fedKey); err != nil {
				return nil, err
			}
			pdu["signatures"] = red["signatures"]
		}
		ctx, cancel := context.WithTimeout(r.Context(), 55*time.Second)
		defer cancel()
		if pdu, err = s.verifyPDU(ctx, ri.version, ev, pdu); err != nil {
			return nil, errForbidden(err.Error())
		}
		if err := s.handlePDU(ctx, origin, ri.version, fedEvent{ev, pdu, true}, true); err != nil {
			return nil, err
		}
		if hidden, _, ok := haveEvent(s.db, ev.EventID); !ok || hidden != evVisible {
			return nil, errForbidden("the event is not allowed in this room")
		}
		if membership != "join" {
			return map[string]any{}, nil
		}
		var out map[string]any
		err = s.readTx(func(tx *sql.Tx) error {
			sp, err := loadPDU(tx, ev.EventID)
			if err != nil || sp == nil {
				return errNotFound("event not found")
			}
			st, err := stateBeforeEvent(tx, ri.version, sp.ev)
			if err != nil {
				return err
			}
			ids := make([]string, 0, len(st))
			for _, id := range st {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			chain := authChain(append(ids, ev.AuthEvents...), pduGetter(tx, nil))
			var chainIDs []string
			for id := range chain {
				chainIDs = append(chainIDs, id)
			}
			sort.Strings(chainIDs)
			state, _ := s.statePDUs(tx, ids, origin)
			authPDUs, _ := s.statePDUs(tx, chainIDs, origin)
			servers := append([]string{s.cfg.ServerName}, s.roomServers(tx, roomID)...)
			out = map[string]any{"origin": s.cfg.ServerName, "state": state, "auth_chain": authPDUs,
				"event": pdu, "members_omitted": false, "servers_in_room": servers}
			return nil
		})
		return out, err
	}
}

// ---- invites to our users ----

func (s *Server) hFedInvite(w http.ResponseWriter, r *http.Request, origin string, body []byte) (any, error) {
	var req struct {
		RoomVersion string            `json:"room_version"`
		Event       json.RawMessage   `json:"event"`
		InviteState []json.RawMessage `json:"invite_room_state"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errBadJSON("invalid body")
	}
	if _, ok := rulesFor(req.RoomVersion); !ok {
		return nil, &apiError{Status: 400, Code: "M_INCOMPATIBLE_ROOM_VERSION", Msg: "unsupported room version",
			Extra: map[string]any{"room_version": req.RoomVersion}}
	}
	ev, pdu, err := parsePDU(req.RoomVersion, req.Event)
	if err != nil {
		return nil, errBadJSON(err.Error())
	}
	if ev.EventID != r.PathValue("eventId") || ev.RoomID != r.PathValue("roomId") {
		return nil, errBadJSON("event ID or room doesn't match the URL")
	}
	if ev.Type != "m.room.member" || ev.StateKey == nil || membershipOf(ev) != "invite" || domainOf(ev.Sender) != origin {
		return nil, errForbidden("expected an invite from a user of the requesting server")
	}
	target := *ev.StateKey
	var x int
	if !s.isLocal(target) || s.db.QueryRow("SELECT 1 FROM users WHERE user_id = ? AND deactivated = 0 AND password_hash != '!'", target).Scan(&x) != nil {
		return nil, errNotFound("no such user")
	}
	if ri, ok := getRoomInfo(s.db, ev.RoomID); ok && !ri.federated {
		return nil, errForbidden("room ID clashes with a local room")
	}
	if domainOf(ev.RoomID) == s.cfg.ServerName {
		if _, ok := getRoomInfo(s.db, ev.RoomID); !ok {
			return nil, errForbidden("unknown room of this server")
		}
	}
	var pending int
	s.db.QueryRow("SELECT COUNT(*) FROM remote_invites WHERE user_id = ?", target).Scan(&pending)
	if pending >= 200 {
		return nil, errf(429, "M_LIMIT_EXCEEDED", "too many pending invites")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if pdu, err = s.verifyPDU(ctx, req.RoomVersion, ev, pdu); err != nil {
		return nil, errForbidden(err.Error())
	}
	rules, _ := rulesFor(req.RoomVersion)
	red := without(redactPDU(rules, pdu), "unsigned")
	if err := signJSON(red, s.cfg.ServerName, s.fedKey); err != nil {
		return nil, err
	}
	pdu["signatures"] = red["signatures"]
	if s.localMemberIn(ev.RoomID) {
		// we're in the room: the invite reaches us through the room itself
		return map[string]any{"event": pdu}, nil
	}
	var stripped []any
	for i, raw := range req.InviteState {
		if i >= 20 {
			break
		}
		var st struct {
			Type     string          `json:"type"`
			StateKey *string         `json:"state_key"`
			Sender   string          `json:"sender"`
			Content  json.RawMessage `json:"content"`
		}
		if json.Unmarshal(raw, &st) != nil || st.StateKey == nil || len(st.Content) > 4096 || len(st.Type) > 255 {
			continue
		}
		stripped = append(stripped, map[string]any{"type": st.Type, "state_key": *st.StateKey, "sender": st.Sender, "content": st.Content})
	}
	strippedJSON, _ := json.Marshal(stripped)
	err = s.write(func(tx *sql.Tx) error {
		if _, _, ok := haveEvent(tx, ev.EventID); !ok {
			if err := s.insertPDU(tx, ev, pdu, evOutlier, 0); err != nil {
				return err
			}
		} else {
			sp, _ := loadPDU(tx, ev.EventID)
			ev.Stream = sp.ev.Stream
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO remote_invites (room_id, user_id, event_id, room_version, invite_state)
			VALUES (?,?,?,?,?)`, ev.RoomID, target, ev.EventID, req.RoomVersion, string(strippedJSON)); err != nil {
			return err
		}
		st := s.nextFor(change{user: target})
		_, err := tx.Exec(`INSERT OR REPLACE INTO memberships (room_id, user_id, membership, stream) VALUES (?,?,'invite',?)`,
			ev.RoomID, target, st)
		return err
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"event": pdu}, nil
}
