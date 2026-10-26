package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Incoming PDUs. Checks, in spec order: format, signatures (bad hash =
// redact), auth events, state before, current state (fail = soft-fail).
// Anything we fetch is fetched before taking the write lock.

// limits on what one incoming event may make us fetch
const (
	maxMissingFetch   = 10   // events asked for with get_missing_events
	maxStateFetch     = 5000 // events fetched to fill the state at a gap
	maxAuthChainFetch = 5000
	maxGapsPerEvent   = 3 // unknown prev events we fetch the state at, per event
)

var errNotInRoom = errors.New("this server is not in the room")

// parsePDU checks the format and returns the event plus the raw PDU map.
func parsePDU(version string, raw []byte) (*Event, map[string]any, error) {
	r, ok := rulesFor(version)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported room version %s", version)
	}
	if len(raw) > maxPDUSize*2 {
		return nil, nil, errors.New("event too large")
	}
	v, err := decodeJSONNumbers(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid JSON: %w", err)
	}
	pdu, ok := v.(map[string]any)
	if !ok {
		return nil, nil, errors.New("event is not an object")
	}
	delete(pdu, "unsigned") // never trusted from other servers
	canon, err := canonicalJSON(pdu)
	if err != nil {
		return nil, nil, fmt.Errorf("event isn't valid canonical JSON: %w", err)
	}
	if len(canon) > maxPDUSize {
		return nil, nil, errors.New("event too large")
	}
	str := func(k string) (string, bool) { s, ok := pdu[k].(string); return s, ok }
	ev := &Event{}
	var okT, okR, okS bool
	ev.Type, okT = str("type")
	ev.RoomID, okR = str("room_id")
	ev.Sender, okS = str("sender")
	if !okT || !okR || !okS || !isUserID(ev.Sender) || !strings.HasPrefix(ev.RoomID, "!") {
		return nil, nil, errors.New("event needs type, room_id and a valid sender")
	}
	if sk, has := pdu["state_key"]; has {
		s, ok := sk.(string)
		if !ok {
			return nil, nil, errors.New("state_key must be a string")
		}
		ev.StateKey = &s
	}
	if len(ev.Type) > 255 || len(ev.Sender) > 255 || len(ev.RoomID) > 255 || (ev.StateKey != nil && len(*ev.StateKey) > 255) {
		return nil, nil, errors.New("type, sender, room_id or state_key too long")
	}
	content, ok := pdu["content"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("content must be an object")
	}
	if ev.Content, err = canonicalJSON(content); err != nil {
		return nil, nil, err
	}
	ts, ok := pdu["origin_server_ts"].(json.Number)
	if !ok || !isInt(ts) {
		return nil, nil, errors.New("origin_server_ts must be an integer")
	}
	ev.OriginTS = asLevel(ts)
	d, ok := pdu["depth"].(json.Number)
	if !ok || !isInt(d) || asLevel(d) < 0 {
		return nil, nil, errors.New("depth must be a non-negative integer")
	}
	ev.Depth = asLevel(d)
	ids := func(k string, max int) ([]string, error) {
		arr, ok := pdu[k].([]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an array", k)
		}
		if len(arr) > max {
			return nil, fmt.Errorf("too many %s", k)
		}
		out := make([]string, 0, len(arr))
		seen := map[string]bool{}
		for _, x := range arr {
			s, ok := x.(string)
			if !ok || !strings.HasPrefix(s, "$") || len(s) > 255 || seen[s] {
				return nil, fmt.Errorf("bad entry in %s", k)
			}
			seen[s] = true
			out = append(out, s)
		}
		return out, nil
	}
	if ev.AuthEvents, err = ids("auth_events", 10); err != nil {
		return nil, nil, err
	}
	if ev.PrevEvents, err = ids("prev_events", 20); err != nil {
		return nil, nil, err
	}
	hashes, _ := pdu["hashes"].(map[string]any)
	if _, ok := hashes["sha256"].(string); !ok {
		return nil, nil, errors.New("missing content hash")
	}
	if _, ok := pdu["signatures"].(map[string]any); !ok {
		return nil, nil, errors.New("missing signatures")
	}
	if ev.EventID, err = eventIDFor(r, pdu); err != nil {
		return nil, nil, err
	}
	if ev.Type == "m.room.create" && ev.StateKey != nil && *ev.StateKey == "" {
		if c := contentOf(ev); c["room_version"] != version && !(version == "1" && c["room_version"] == nil) {
			return nil, nil, errors.New("create event names a different room version")
		}
	}
	return ev, pdu, nil
}

// verifyPDU checks signatures; on a bad content hash it returns the redacted form.
func (s *Server) verifyPDU(ctx context.Context, version string, ev *Event, pdu map[string]any) (map[string]any, error) {
	r, _ := rulesFor(version)
	need := []string{domainOf(ev.Sender)}
	if ev.Type == "m.room.member" {
		c := contentOf(ev)
		if m, _ := c["membership"].(string); m == "join" {
			if au, ok := c["join_authorised_via_users_server"].(string); ok && isUserID(au) && domainOf(au) != need[0] {
				need = append(need, domainOf(au))
			}
		}
	}
	sigs, _ := pdu["signatures"].(map[string]any)
	for _, server := range need {
		theirs, _ := sigs[server].(map[string]any)
		ok := false
		var lastErr error
		ids := make([]string, 0, len(theirs))
		for id := range theirs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if !strings.HasPrefix(id, "ed25519:") {
				continue
			}
			pub, err := s.eventKey(ctx, server, id, ev.OriginTS)
			if err != nil {
				lastErr = err
				continue
			}
			if err := verifyPDUSignature(r, pdu, server, id, pub); err != nil {
				lastErr = err
				continue
			}
			ok = true
			break
		}
		if !ok {
			if lastErr == nil {
				lastErr = errors.New("no signature")
			}
			return nil, fmt.Errorf("not signed by %s: %v", server, lastErr)
		}
	}
	if !checkPDUHashes(pdu) {
		red := redactPDU(r, pdu)
		c, _ := red["content"].(map[string]any)
		b, err := canonicalJSON(c)
		if err != nil {
			return nil, err
		}
		ev.Content = b
		return red, nil
	}
	return pdu, nil
}

// ---- reading stored PDUs ----

type storedPDU struct {
	ev     *Event
	pdu    string
	hidden int
	group  sql.NullInt64
}

// loadPDU reads a stored event of a federated room with its graph fields.
func loadPDU(q querier, id string) (*storedPDU, error) {
	var sp storedPDU
	var pdu sql.NullString
	e, err := scanEvent(q.QueryRow("SELECT "+evCols+" FROM events WHERE event_id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := q.QueryRow("SELECT pdu, hidden, state_group FROM events WHERE event_id = ?", id).Scan(&pdu, &sp.hidden, &sp.group); err != nil {
		return nil, err
	}
	if !pdu.Valid {
		return nil, fmt.Errorf("event %s has no PDU", id)
	}
	sp.pdu = pdu.String
	var g struct {
		Auth  []string    `json:"auth_events"`
		Prev  []string    `json:"prev_events"`
		Depth json.Number `json:"depth"`
	}
	if err := json.Unmarshal([]byte(pdu.String), &g); err != nil {
		return nil, err
	}
	e.AuthEvents, e.PrevEvents, e.Depth = g.Auth, g.Prev, asLevel(g.Depth)
	e.Rejected = sp.hidden == evRejected
	sp.ev = e
	return &sp, nil
}

// getter returns an eventGetter over the database, memoized for one operation.
func pduGetter(q querier, extra map[string]*Event) eventGetter {
	memo := map[string]*Event{}
	return func(id string) *Event {
		if e, ok := extra[id]; ok {
			return e
		}
		if e, ok := memo[id]; ok {
			return e
		}
		sp, err := loadPDU(q, id)
		var e *Event
		if err == nil && sp != nil {
			e = sp.ev
		}
		memo[id] = e
		return e
	}
}

func haveEvent(q querier, id string) (hidden int, group sql.NullInt64, ok bool) {
	err := q.QueryRow("SELECT hidden, state_group FROM events WHERE event_id = ?", id).Scan(&hidden, &group)
	return hidden, group, err == nil
}

// ---- auth checks on received events ----

// checkAgainstAuthEvents is auth rules 2 and 3.
func checkAgainstAuthEvents(version string, ev *Event, get eventGetter) error {
	auth := authState{}
	allowed := map[stateTuple]bool{}
	for _, t := range authTypes(ev) {
		allowed[t] = true
	}
	for _, id := range ev.AuthEvents {
		a := get(id)
		if a == nil {
			return fmt.Errorf("unknown auth event %s", id)
		}
		if a.RoomID != ev.RoomID || a.StateKey == nil {
			return fmt.Errorf("auth event %s is not state of this room", id)
		}
		if a.Rejected {
			return fmt.Errorf("auth event %s was rejected", id)
		}
		k := stateTuple{a.Type, *a.StateKey}
		if auth[k] != nil {
			return fmt.Errorf("duplicate auth events for %v", k)
		}
		if !allowed[k] {
			return fmt.Errorf("unexpected auth event %v", k)
		}
		auth[k] = a
	}
	if ev.Type != "m.room.create" && auth[createTuple] == nil {
		return errors.New("no create event in auth events")
	}
	return checkAuth(version, ev, ev.PrevEvents, auth)
}

// checkAgainstState applies the auth rules with the auth events taken from a state.
func checkAgainstState(version string, ev *Event, state stateMap, get eventGetter) error {
	auth := authState{}
	for _, t := range authTypes(ev) {
		if id, ok := state[t]; ok {
			if a := get(id); a != nil && !a.Rejected {
				auth[t] = a
			}
		}
	}
	return checkAuth(version, ev, ev.PrevEvents, auth)
}

// ---- storing received events ----

// insertPDU stores a received event; hidden ones don't wake any /sync.
func (s *Server) insertPDU(tx *sql.Tx, ev *Event, pdu map[string]any, hidden int, group int64) error {
	return s.insertPDUAt(tx, ev, pdu, hidden, group, 0)
}

// insertPDUAt takes an explicit stream position (backfill); 0 = next.
func (s *Server) insertPDUAt(tx *sql.Tx, ev *Event, pdu map[string]any, hidden int, group, stream int64) error {
	raw, err := canonicalJSON(pdu)
	if err != nil {
		return err
	}
	if stream != 0 {
		ev.Stream = stream
	} else {
		c := change{}
		if hidden == evVisible {
			c.room = ev.RoomID
			if ev.Type == "m.room.member" && ev.StateKey != nil {
				c.user = *ev.StateKey
			}
		}
		ev.Stream = s.nextFor(c)
	}
	var relID, relType string
	if hidden == evVisible {
		relID, relType = relationOf(ev.Content)
		if stream == 0 {
			s.pendingEvents = append(s.pendingEvents, ev)
		}
	}
	var sk, prev, grp any
	if ev.StateKey != nil {
		sk = *ev.StateKey
		if hidden == evVisible && stream == 0 {
			if old, _ := getStateEvent(tx, ev.RoomID, ev.Type, *ev.StateKey); old != nil {
				prev = string(old.Content)
				ev.PrevContent = old.Content
			}
		}
	}
	if group != 0 {
		grp = group
	}
	_, err = tx.Exec(`INSERT INTO events (stream, event_id, room_id, type, state_key, sender, content, origin_ts,
		prev_content, rel_event_id, rel_type, pdu, state_group, hidden) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.Stream, ev.EventID, ev.RoomID, ev.Type, sk, ev.Sender, string(ev.Content), ev.OriginTS,
		prev, nullStr(relID), nullStr(relType), string(raw), grp, hidden)
	return err
}

// fedEvent is a received event ready to store: checked format and signatures.
type fedEvent struct {
	ev    *Event
	pdu   map[string]any
	relay bool // accepted for another server (send_join/send_leave): pass it on
}

// storeOutliers stores auth chain / state events; failures become rejected.
func (s *Server) storeOutliers(tx *sql.Tx, version string, evs []fedEvent) error {
	pending := map[string]*Event{}
	for _, fe := range evs {
		pending[fe.ev.EventID] = fe.ev
	}
	get := pduGetter(tx, nil)
	for _, fe := range sortByAuth(evs) {
		if _, _, ok := haveEvent(tx, fe.ev.EventID); ok {
			continue
		}
		hidden := evOutlier
		if err := checkAgainstAuthEvents(version, fe.ev, get); err != nil {
			hidden = evRejected
			fe.ev.Rejected = true
		}
		if err := s.insertPDU(tx, fe.ev, fe.pdu, hidden, 0); err != nil {
			return err
		}
		get = pduGetter(tx, nil) // the new event is now readable
	}
	return nil
}

// sortByAuth orders events so each comes after the auth events among them.
func sortByAuth(evs []fedEvent) []fedEvent {
	byID := map[string]fedEvent{}
	for _, fe := range evs {
		byID[fe.ev.EventID] = fe
	}
	var out []fedEvent
	done := map[string]bool{}
	var visit func(id string, depth int)
	visit = func(id string, depth int) {
		fe, ok := byID[id]
		if !ok || done[id] || depth > 10000 {
			return
		}
		done[id] = true
		for _, a := range fe.ev.AuthEvents {
			visit(a, depth+1)
		}
		out = append(out, fe)
	}
	sorted := append([]fedEvent(nil), evs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ev.Depth < sorted[j].ev.Depth })
	for _, fe := range sorted {
		visit(fe.ev.EventID, 0)
	}
	return out
}

// stateBefore resolves the states after ev's prevs. Also returns a group
// to store deltas against.
func stateBefore(tx *sql.Tx, version string, ev *Event, get eventGetter) (stateMap, int64, error) {
	var sets []stateMap
	var base int64
	for i, p := range ev.PrevEvents {
		st, g, err := stateAfter(tx, p)
		if err != nil {
			return nil, 0, err
		}
		if i == 0 {
			base = g
		}
		sets = append(sets, st)
	}
	if len(sets) == 0 {
		return stateMap{}, 0, nil
	}
	if len(sets) == 1 {
		return sets[0], base, nil
	}
	return resolveState(version, sets, get), base, nil
}

// persistTimelineEvent runs checks 3-5 and stores the event.
func (s *Server) persistTimelineEvent(tx *sql.Tx, version string, ev *Event, pdu map[string]any) error {
	return s.persistTimelineEventRelay(tx, version, ev, pdu, false)
}

func (s *Server) persistTimelineEventRelay(tx *sql.Tx, version string, ev *Event, pdu map[string]any, relay bool) error {
	if hidden, _, ok := haveEvent(tx, ev.EventID); ok && hidden != evOutlier {
		return nil // already have it
	} else if ok {
		// known as an outlier; it now joins the timeline
		if _, err := tx.Exec("DELETE FROM events WHERE event_id = ?", ev.EventID); err != nil {
			return err
		}
	}
	get := pduGetter(tx, nil)
	if err := checkAgainstAuthEvents(version, ev, get); err != nil {
		ev.Rejected = true
		log.Printf("federation: rejected %s: %v", ev.EventID, err)
		return s.insertPDU(tx, ev, pdu, evRejected, 0)
	}
	before, base, err := stateBefore(tx, version, ev, get)
	if err != nil {
		return err
	}
	if err := checkAgainstState(version, ev, before, get); err != nil {
		ev.Rejected = true
		log.Printf("federation: rejected %s (state before it): %v", ev.EventID, err)
		return s.insertPDU(tx, ev, pdu, evRejected, 0)
	}
	group := base
	after := before
	if ev.StateKey != nil {
		after = make(stateMap, len(before)+1)
		for k, v := range before {
			after[k] = v
		}
		after[stateTuple{ev.Type, *ev.StateKey}] = ev.EventID
	}
	if group, err = addStateGroupFor(tx, ev.RoomID, base, stateOf(tx, base), after); err != nil {
		return err
	}
	current, err := loadStateGroup(tx, currentStateGroup(tx, ev.RoomID))
	if err != nil {
		return err
	}
	hidden := evVisible
	if err := checkAgainstState(version, ev, current, get); err != nil {
		hidden = evSoftFailed
		log.Printf("federation: soft-failed %s: %v", ev.EventID, err)
	}
	if err := s.insertPDU(tx, ev, pdu, hidden, group); err != nil {
		return err
	}
	if hidden != evVisible {
		return nil
	}
	if relay {
		if _, err := tx.Exec("UPDATE events SET relay = 1 WHERE event_id = ?", ev.EventID); err != nil {
			return err
		}
	}
	return s.advanceRoom(tx, version, ev, after, group)
}

// stateOf loads a group, or returns empty state for 0.
func stateOf(q querier, g int64) stateMap {
	m, err := loadStateGroup(q, g)
	if err != nil {
		return stateMap{}
	}
	return m
}

// advanceRoom updates the extremities and the current state.
func (s *Server) advanceRoom(tx *sql.Tx, version string, ev *Event, after stateMap, group int64) error {
	for _, p := range ev.PrevEvents {
		if _, err := tx.Exec("DELETE FROM room_extremities WHERE room_id = ? AND event_id = ?", ev.RoomID, p); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("INSERT OR IGNORE INTO room_extremities (room_id, event_id, depth) VALUES (?,?,?)",
		ev.RoomID, ev.EventID, ev.Depth); err != nil {
		return err
	}
	rows, err := tx.Query("SELECT event_id FROM room_extremities WHERE room_id = ? ORDER BY depth DESC, event_id", ev.RoomID)
	if err != nil {
		return err
	}
	var ext []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ext = append(ext, id)
	}
	rows.Close()
	state, g := after, group
	if len(ext) > 1 {
		var sets []stateMap
		for _, id := range ext {
			st, _, err := stateAfter(tx, id)
			if err != nil {
				return err
			}
			sets = append(sets, st)
		}
		state = resolveState(version, sets, pduGetter(tx, nil))
		cur := currentStateGroup(tx, ev.RoomID)
		if g, err = addStateGroupFor(tx, ev.RoomID, cur, stateOf(tx, cur), state); err != nil {
			return err
		}
	}
	return s.setCurrentState(tx, ev.RoomID, g, state, ev.Stream)
}

// ---- fetching what an incoming event needs ----

// checkFetched parses and verifies a PDU fetched from another server.
func (s *Server) checkFetched(ctx context.Context, version, roomID string, raw json.RawMessage) (fedEvent, error) {
	ev, pdu, err := parsePDU(version, raw)
	if err != nil {
		return fedEvent{}, err
	}
	if ev.RoomID != roomID {
		return fedEvent{}, errors.New("event from another room")
	}
	pdu, err = s.verifyPDU(ctx, version, ev, pdu)
	if err != nil {
		return fedEvent{}, err
	}
	return fedEvent{ev: ev, pdu: pdu}, nil
}

// fetchEvent gets one event by ID from a server and checks it is that event.
func (s *Server) fetchEvent(ctx context.Context, server, version, roomID, id string) (fedEvent, error) {
	var resp struct {
		PDUs []json.RawMessage `json:"pdus"`
	}
	if err := s.fedRequest(ctx, "GET", server, "/_matrix/federation/v1/event/"+pathEscape(id), nil, &resp); err != nil {
		return fedEvent{}, err
	}
	if len(resp.PDUs) != 1 {
		return fedEvent{}, errors.New("expected one event")
	}
	fe, err := s.checkFetched(ctx, version, roomID, resp.PDUs[0])
	if err != nil {
		return fedEvent{}, err
	}
	if fe.ev.EventID != id {
		return fedEvent{}, fmt.Errorf("asked for %s, got %s", id, fe.ev.EventID)
	}
	return fe, nil
}

// fetchEvents gets many events, a few at a time, skipping ones that fail.
func (s *Server) fetchEvents(ctx context.Context, server, version, roomID string, ids []string) []fedEvent {
	out := make([]fedEvent, len(ids))
	ok := make([]bool, len(ids))
	sem := make(chan struct{}, 8)
	done := make(chan struct{})
	for i, id := range ids {
		go func(i int, id string) {
			sem <- struct{}{}
			defer func() { <-sem; done <- struct{}{} }()
			fe, err := s.fetchEvent(ctx, server, version, roomID, id)
			if err != nil {
				log.Printf("federation: fetching %s from %s: %v", id, server, err)
				return
			}
			out[i], ok[i] = fe, true
		}(i, id)
	}
	for range ids {
		<-done
	}
	var res []fedEvent
	for i := range out {
		if ok[i] {
			res = append(res, out[i])
		}
	}
	return res
}

func (s *Server) unknownEvents(ids []string) []string {
	var out []string
	for _, id := range ids {
		if _, _, ok := haveEvent(s.db, id); !ok {
			out = append(out, id)
		}
	}
	return out
}

// fetchAuthChain stores the auth events of ev we don't have yet.
func (s *Server) fetchAuthChain(ctx context.Context, origin, version string, ev *Event) error {
	if len(s.unknownEvents(ev.AuthEvents)) == 0 {
		return nil
	}
	var resp struct {
		Chain []json.RawMessage `json:"auth_chain"`
	}
	uri := "/_matrix/federation/v1/event_auth/" + pathEscape(ev.RoomID) + "/" + pathEscape(ev.EventID)
	if err := s.fedRequest(ctx, "GET", origin, uri, nil, &resp); err != nil {
		return err
	}
	if len(resp.Chain) > maxAuthChainFetch {
		return errors.New("auth chain too long")
	}
	var evs []fedEvent
	for _, raw := range resp.Chain {
		fe, err := s.checkFetched(ctx, version, ev.RoomID, raw)
		if err != nil {
			log.Printf("federation: auth chain event from %s: %v", origin, err)
			continue
		}
		evs = append(evs, fe)
	}
	return s.write(func(tx *sql.Tx) error { return s.storeOutliers(tx, version, evs) })
}

// prevsWithoutState lists prev events we don't know the state after.
func (s *Server) prevsWithoutState(ev *Event) []string {
	var out []string
	for _, p := range ev.PrevEvents {
		if _, g, ok := haveEvent(s.db, p); !ok || !g.Valid {
			out = append(out, p)
		}
	}
	return out
}

// fetchMissingEvents fills the gap between our extremities and ev.
func (s *Server) fetchMissingEvents(ctx context.Context, origin, version string, ev *Event) {
	var earliest []string
	rows, err := s.db.Query("SELECT event_id FROM room_extremities WHERE room_id = ?", ev.RoomID)
	if err != nil {
		return
	}
	for rows.Next() {
		var id string
		rows.Scan(&id)
		earliest = append(earliest, id)
	}
	rows.Close()
	var resp struct {
		Events []json.RawMessage `json:"events"`
	}
	body := map[string]any{"earliest_events": earliest, "latest_events": []string{ev.EventID}, "limit": maxMissingFetch, "min_depth": 0}
	if err := s.fedRequest(ctx, "POST", origin, "/_matrix/federation/v1/get_missing_events/"+pathEscape(ev.RoomID), body, &resp); err != nil {
		log.Printf("federation: get_missing_events from %s: %v", origin, err)
		return
	}
	var evs []fedEvent
	for i, raw := range resp.Events {
		if i >= maxMissingFetch {
			break
		}
		fe, err := s.checkFetched(ctx, version, ev.RoomID, raw)
		if err == nil {
			evs = append(evs, fe)
		}
	}
	sort.Slice(evs, func(i, j int) bool { return evs[i].ev.Depth < evs[j].ev.Depth })
	for _, fe := range evs {
		if err := s.handlePDU(ctx, origin, version, fe, false); err != nil {
			log.Printf("federation: missing event %s: %v", fe.ev.EventID, err)
		}
	}
}

// fetchStateAt gets the state after each event (state_ids + the event itself).
func (s *Server) fetchStateAt(ctx context.Context, origin, version, roomID string, ids []string) error {
	for _, p := range ids {
		var resp struct {
			PDUIDs  []string `json:"pdu_ids"`
			AuthIDs []string `json:"auth_chain_ids"`
		}
		uri := "/_matrix/federation/v1/state_ids/" + pathEscape(roomID) + "?event_id=" + queryEscape(p)
		if err := s.fedRequest(ctx, "GET", origin, uri, nil, &resp); err != nil {
			return fmt.Errorf("state at %s: %w", p, err)
		}
		if len(resp.PDUIDs)+len(resp.AuthIDs) > maxStateFetch {
			return errors.New("state too large to fetch")
		}
		need := s.unknownEvents(append(append(append([]string(nil), resp.PDUIDs...), resp.AuthIDs...), p))
		evs := s.fetchEvents(ctx, origin, version, roomID, need)
		err := s.write(func(tx *sql.Tx) error {
			if err := s.storeOutliers(tx, version, evs); err != nil {
				return err
			}
			state := stateMap{}
			for _, id := range resp.PDUIDs {
				e := pduGetter(tx, nil)(id)
				if e == nil || e.StateKey == nil || e.RoomID != roomID {
					return fmt.Errorf("state event %s missing or invalid", id)
				}
				state[stateTuple{e.Type, *e.StateKey}] = id
			}
			pe := pduGetter(tx, nil)(p)
			if pe == nil {
				return fmt.Errorf("couldn't fetch %s", p)
			}
			if pe.StateKey != nil && !pe.Rejected {
				state[stateTuple{pe.Type, *pe.StateKey}] = p
			}
			g, err := addStateGroupFor(tx, roomID, 0, nil, state)
			if err != nil {
				return err
			}
			_, err = tx.Exec("UPDATE events SET state_group = ? WHERE event_id = ?", g, p)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// handlePDU fetches what a verified PDU needs, then stores it.
func (s *Server) handlePDU(ctx context.Context, origin, version string, fe fedEvent, fetchMissing bool) error {
	if hidden, _, ok := haveEvent(s.db, fe.ev.EventID); ok && hidden != evOutlier {
		return nil
	}
	if err := s.fetchAuthChain(ctx, origin, version, fe.ev); err != nil {
		return fmt.Errorf("auth events: %w", err)
	}
	if missing := s.prevsWithoutState(fe.ev); len(missing) > 0 {
		if fetchMissing {
			s.fetchMissingEvents(ctx, origin, version, fe.ev)
			missing = s.prevsWithoutState(fe.ev)
		}
		if len(missing) > maxGapsPerEvent {
			return fmt.Errorf("%d earlier events unknown", len(missing))
		}
		if len(missing) > 0 {
			if err := s.fetchStateAt(ctx, origin, version, fe.ev.RoomID, missing); err != nil {
				return err
			}
		}
	}
	return s.write(func(tx *sql.Tx) error { return s.persistTimelineEventRelay(tx, version, fe.ev, fe.pdu, fe.relay) })
}

// ---- history from before we joined ----

// backfill fetches older history. It goes in at negative stream positions,
// so /messages sees it but /sync and push don't.
func (s *Server) backfill(ctx context.Context, roomID string, limit int) bool {
	ri, ok := getRoomInfo(s.db, roomID)
	if !ok || !ri.federated || !s.cfg.Federation {
		return false
	}
	var oldest string
	if s.db.QueryRow("SELECT event_id FROM events WHERE room_id = ? AND hidden = 0 ORDER BY stream LIMIT 1", roomID).Scan(&oldest) != nil {
		return false
	}
	e := pduGetter(s.db, nil)(oldest)
	if e == nil {
		return false
	}
	from := s.unknownEvents(e.PrevEvents)
	if len(from) == 0 {
		return false // we have the room from its start
	}
	q := url.Values{"v": from, "limit": {strconv.Itoa(limit)}}
	for i, server := range s.roomServers(s.db, roomID) {
		if i >= 3 {
			break
		}
		var resp struct {
			PDUs []json.RawMessage `json:"pdus"`
		}
		if err := s.fedRequest(ctx, "GET", server, "/_matrix/federation/v1/backfill/"+pathEscape(roomID)+"?"+q.Encode(), nil, &resp); err != nil {
			log.Printf("federation: backfill from %s: %v", server, err)
			continue
		}
		var evs []fedEvent
		for j, raw := range resp.PDUs {
			if j >= 100 {
				break
			}
			fe, err := s.checkFetched(ctx, ri.version, roomID, raw)
			if err != nil {
				continue
			}
			if err := s.fetchAuthChain(ctx, server, ri.version, fe.ev); err != nil {
				continue
			}
			evs = append(evs, fe)
		}
		if len(evs) == 0 {
			continue
		}
		// newest first, each one position below the last
		sort.Slice(evs, func(a, b int) bool { return evs[a].ev.Depth > evs[b].ev.Depth })
		stored := false
		err := s.write(func(tx *sql.Tx) error {
			var low sql.NullInt64
			tx.QueryRow("SELECT MIN(stream) FROM events").Scan(&low)
			next := min(low.Int64, 0) - 1
			get := pduGetter(tx, nil)
			for _, fe := range evs {
				if _, _, ok := haveEvent(tx, fe.ev.EventID); ok {
					continue
				}
				hidden := evVisible
				if checkAgainstAuthEvents(ri.version, fe.ev, get) != nil {
					hidden, fe.ev.Rejected = evRejected, true
				}
				if err := s.insertPDUAt(tx, fe.ev, fe.pdu, hidden, 0, next); err != nil {
					return err
				}
				next--
				stored = true
			}
			return nil
		})
		if err != nil {
			log.Printf("federation: backfill: %v", err)
			return false
		}
		return stored
	}
	return false
}
