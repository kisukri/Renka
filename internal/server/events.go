package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const defaultRoomVersion = "10"

// Event is a stored room event.
type Event struct {
	Stream          int64
	EventID         string
	RoomID          string
	Type            string
	StateKey        *string
	Sender          string
	Content         json.RawMessage
	OriginTS        int64
	PrevContent     json.RawMessage
	RedactedBecause json.RawMessage
	TxnDevice       string
	TxnID           string
	Unsigned        map[string]any // extra unsigned data computed at read time (e.g. bundled relations)

	// federation only (filled from the PDU when needed)
	AuthEvents, PrevEvents []string
	Depth                  int64
	Rejected               bool
}

const evCols = `stream, event_id, room_id, type, state_key, sender, content, origin_ts,
	prev_content, redacted_because, txn_device, txn_id`

func scanEvent(sc interface{ Scan(...any) error }) (*Event, error) {
	var e Event
	var sk, prev, red, td, ti sql.NullString
	var content string
	if err := sc.Scan(&e.Stream, &e.EventID, &e.RoomID, &e.Type, &sk, &e.Sender, &content, &e.OriginTS,
		&prev, &red, &td, &ti); err != nil {
		return nil, err
	}
	e.Content = json.RawMessage(content)
	if sk.Valid {
		e.StateKey = &sk.String
	}
	if prev.Valid {
		e.PrevContent = json.RawMessage(prev.String)
	}
	if red.Valid {
		e.RedactedBecause = json.RawMessage(red.String)
	}
	e.TxnDevice, e.TxnID = td.String, ti.String
	return &e, nil
}

func queryEvents(q querier, query string, args ...any) ([]*Event, error) {
	rows, err := q.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func getEvent(q querier, eventID string) (*Event, error) {
	e, err := scanEvent(q.QueryRow("SELECT "+evCols+" FROM events WHERE event_id = ?", eventID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

func getStateEvent(q querier, roomID, typ, key string) (*Event, error) {
	e, err := scanEvent(q.QueryRow("SELECT "+prefixCols("e")+` FROM room_state s JOIN events e ON e.event_id = s.event_id
		WHERE s.room_id = ? AND s.type = ? AND s.state_key = ?`, roomID, typ, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

func currentState(q querier, roomID string) ([]*Event, error) {
	return queryEvents(q, "SELECT "+prefixCols("e")+` FROM room_state s JOIN events e ON e.event_id = s.event_id
		WHERE s.room_id = ? ORDER BY e.stream`, roomID)
}

func prefixCols(p string) string {
	parts := strings.Split(evCols, ",")
	for i, c := range parts {
		parts[i] = p + "." + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

// stateString reads a string field from a state event's content, or "".
func stateString(q querier, roomID, typ, key, field string) string {
	var v sql.NullString
	q.QueryRow(`SELECT json_extract(e.content, '$.'||?) FROM room_state s JOIN events e ON e.event_id = s.event_id
		WHERE s.room_id = ? AND s.type = ? AND s.state_key = ?`, field, roomID, typ, key).Scan(&v)
	return v.String
}

func getMembership(q querier, roomID, userID string) (string, int64) {
	var m string
	var st int64
	q.QueryRow("SELECT membership, stream FROM memberships WHERE room_id = ? AND user_id = ?", roomID, userID).Scan(&m, &st)
	return m, st
}

func roomVersion(q querier, roomID string) string {
	var v string
	q.QueryRow("SELECT version FROM rooms WHERE room_id = ?", roomID).Scan(&v)
	return v
}

// clientJSON renders an event the way the client-server API expects.
func (e *Event) clientJSON(viewer, viewerDevice string, withRoomID bool) map[string]any {
	m := map[string]any{
		"event_id": e.EventID, "type": e.Type, "sender": e.Sender,
		"origin_server_ts": e.OriginTS, "content": e.Content,
	}
	if withRoomID {
		m["room_id"] = e.RoomID
	}
	if e.StateKey != nil {
		m["state_key"] = *e.StateKey
	}
	if e.Type == "m.room.redaction" {
		var c struct {
			Redacts string `json:"redacts"`
		}
		json.Unmarshal(e.Content, &c)
		if c.Redacts != "" {
			m["redacts"] = c.Redacts
		}
	}
	u := map[string]any{"age": nowMS() - e.OriginTS}
	if e.PrevContent != nil {
		u["prev_content"] = e.PrevContent
	}
	if e.RedactedBecause != nil {
		u["redacted_because"] = e.RedactedBecause
	}
	if e.TxnID != "" && e.Sender == viewer && e.TxnDevice == viewerDevice {
		u["transaction_id"] = e.TxnID
	}
	for k, v := range e.Unsigned {
		u[k] = v
	}
	m["unsigned"] = u
	return m
}

func renderEvents(evs []*Event, viewer, device string, withRoomID bool) []any {
	out := make([]any, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.clientJSON(viewer, device, withRoomID))
	}
	return out
}

// relationOf extracts content["m.relates_to"] = {rel_type, event_id}.
func relationOf(content json.RawMessage) (string, string) {
	var c struct {
		R struct {
			RelType string `json:"rel_type"`
			EventID string `json:"event_id"`
		} `json:"m.relates_to"`
	}
	json.Unmarshal(content, &c)
	if c.R.EventID == "" || c.R.RelType == "" {
		return "", ""
	}
	return c.R.EventID, c.R.RelType
}

func (s *Server) newEvent(roomID, sender, typ string, stateKey *string, content any) *Event {
	b, _ := json.Marshal(content)
	if string(b) == "null" {
		b = []byte("{}")
	}
	return &Event{RoomID: roomID, Sender: sender, Type: typ, StateKey: stateKey, Content: b}
}

// sendEvent authorizes and stores an event. Must run inside write().
func (s *Server) sendEvent(tx *sql.Tx, ev *Event) error {
	if err := s.authorize(tx, ev); err != nil {
		return err
	}
	return s.storeEvent(tx, ev)
}

// storeEvent runs the auth rules and stores the event (as a signed PDU in
// federated rooms). Server-side callers skip authorize, never the auth rules.
func (s *Server) storeEvent(tx *sql.Tx, ev *Event) error {
	if len(ev.Content) > 60000 {
		return errf(413, "M_TOO_LARGE", "event too large")
	}
	if len(ev.Type) > 255 || len(ev.Sender) > 255 || len(ev.RoomID) > 255 || (ev.StateKey != nil && len(*ev.StateKey) > 255) {
		return errf(413, "M_TOO_LARGE", "event type, sender or state key too long")
	}
	// here so createRoom's override / initial_state are covered too
	if ev.Type == "m.room.power_levels" && ev.StateKey != nil && *ev.StateKey == "" {
		if err := validatePowerLevels(ev.Content); err != nil {
			return err
		}
	}
	ri, ok := getRoomInfo(tx, ev.RoomID)
	if !ok {
		return errNotFound("room not found")
	}
	rules, ok := rulesFor(ri.version)
	if !ok {
		return errf(400, "M_UNSUPPORTED_ROOM_VERSION", "unsupported room version %s", ri.version)
	}
	if ev.OriginTS == 0 {
		ev.OriginTS = nowMS()
	}
	auth, authIDs, err := loadAuthState(tx, ev)
	if err != nil {
		return err
	}
	prevEvents, depth, err := prevEventsFor(tx, ev.RoomID, ri.federated)
	if err != nil {
		return err
	}
	if err := checkAuth(ri.version, ev, prevEvents, auth); err != nil {
		return err
	}
	var pdu, group any
	if ri.federated {
		b, err := s.buildPDU(tx, rules, ev, prevEvents, authIDs, depth)
		if err != nil {
			return err
		}
		pdu = string(b)
		// local events follow all extremities: state before = current state
		g := currentStateGroup(tx, ev.RoomID)
		if ev.StateKey != nil {
			if g, err = addStateGroup(tx, ev.RoomID, g, map[stateTuple]string{{ev.Type, *ev.StateKey}: ev.EventID}); err != nil {
				return err
			}
		}
		if _, err := tx.Exec("UPDATE rooms SET state_group = ? WHERE room_id = ?", g, ev.RoomID); err != nil {
			return err
		}
		group = g
	} else if ev.EventID == "" {
		ev.EventID = "$" + randString(43)
	}
	if ev.StateKey != nil {
		prev, err := getStateEvent(tx, ev.RoomID, ev.Type, *ev.StateKey)
		if err != nil {
			return err
		}
		if prev != nil {
			ev.PrevContent = prev.Content
		}
	}
	c := change{room: ev.RoomID}
	if ev.Type == "m.room.member" && ev.StateKey != nil {
		c.user = *ev.StateKey // the target must hear about it even before it is in the room
	}
	ev.Stream = s.nextFor(c)
	s.pendingEvents = append(s.pendingEvents, ev)
	relID, relType := relationOf(ev.Content)
	var prev any
	if ev.PrevContent != nil {
		prev = string(ev.PrevContent)
	}
	var sk any
	if ev.StateKey != nil {
		sk = *ev.StateKey
	}
	_, err = tx.Exec(`INSERT INTO events (stream, event_id, room_id, type, state_key, sender, content, origin_ts,
		prev_content, txn_device, txn_id, rel_event_id, rel_type, pdu, state_group) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.Stream, ev.EventID, ev.RoomID, ev.Type, sk, ev.Sender, string(ev.Content), ev.OriginTS,
		prev, nullStr(ev.TxnDevice), nullStr(ev.TxnID), nullStr(relID), nullStr(relType), pdu, group)
	if err != nil {
		return err
	}
	if ri.federated {
		// The new event replaces the ones it follows as the room's forward extremity.
		for _, p := range prevEvents {
			if _, err := tx.Exec("DELETE FROM room_extremities WHERE room_id = ? AND event_id = ?", ev.RoomID, p); err != nil {
				return err
			}
		}
		if _, err := tx.Exec("INSERT INTO room_extremities (room_id, event_id, depth) VALUES (?,?,?)", ev.RoomID, ev.EventID, depth); err != nil {
			return err
		}
	}
	if ev.StateKey == nil {
		return nil
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO room_state (room_id, type, state_key, event_id, stream)
		VALUES (?,?,?,?,?)`, ev.RoomID, ev.Type, *ev.StateKey, ev.EventID, ev.Stream); err != nil {
		return err
	}
	if ev.Type == "m.room.member" {
		var c struct {
			Membership string `json:"membership"`
		}
		json.Unmarshal(ev.Content, &c)
		if _, err := tx.Exec(`INSERT OR REPLACE INTO memberships (room_id, user_id, membership, stream)
			VALUES (?,?,?,?)`, ev.RoomID, *ev.StateKey, c.Membership, ev.Stream); err != nil {
			return err
		}
	}
	return nil
}

// ---- power levels ----

// maxSafeInt is the canonical-JSON integer range Matrix allows (2^53 - 1).
const maxSafeInt = 1<<53 - 1

func validPLInt(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, err := n.Int64() // rejects 1.5, 1e3 and anything out of int64 range
	return err == nil && i >= -maxSafeInt && i <= maxSafeInt
}

// validatePowerLevels: integers in the safe range only (v10+). Floats like
// 1e20 convert differently on different CPUs.
func validatePowerLevels(content json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return errBadJSON("m.room.power_levels content must be an object")
	}
	for _, k := range []string{"ban", "kick", "redact", "invite", "events_default", "state_default", "users_default"} {
		if v, ok := m[k]; ok && !validPLInt(v) {
			return errBadJSON("power level " + k + " must be an integer")
		}
	}
	for _, k := range []string{"events", "users", "notifications"} {
		v, ok := m[k]
		if !ok {
			continue
		}
		mm, ok := v.(map[string]any)
		if !ok {
			return errBadJSON("power levels " + k + " must be an object")
		}
		for kk, vv := range mm {
			if !validPLInt(vv) {
				return errBadJSON("power level " + k + "." + kk + " must be an integer")
			}
			if k == "users" {
				if _, _, ok := splitID(kk); !ok || !strings.HasPrefix(kk, "@") {
					return errBadJSON("power levels users key " + kk + " is not a user ID")
				}
			}
		}
	}
	return nil
}

type powerLevels struct {
	users                                     map[string]int64
	events                                    map[string]int64
	usersDefault, eventsDefault, stateDefault int64
	ban, kick, redact, invite                 int64
	top                                       map[string]int64 // all top-level numeric fields, for change checks
}

func parsePowerLevels(content json.RawMessage) *powerLevels {
	var m map[string]any
	json.Unmarshal(content, &m)
	p := &powerLevels{users: map[string]int64{}, events: map[string]int64{}, top: map[string]int64{}}
	p.usersDefault = toInt(m["users_default"], 0)
	p.eventsDefault = toInt(m["events_default"], 0)
	p.stateDefault = toInt(m["state_default"], 50)
	p.ban = toInt(m["ban"], 50)
	p.kick = toInt(m["kick"], 50)
	p.redact = toInt(m["redact"], 50)
	p.invite = toInt(m["invite"], 0)
	for _, k := range []string{"users_default", "events_default", "state_default", "ban", "kick", "redact", "invite"} {
		if v, ok := m[k]; ok {
			p.top[k] = toInt(v, 0)
		}
	}
	if u, ok := m["users"].(map[string]any); ok {
		for k, v := range u {
			p.users[k] = toInt(v, 0)
		}
	}
	if e, ok := m["events"].(map[string]any); ok {
		for k, v := range e {
			p.events[k] = toInt(v, 0)
		}
	}
	return p
}

func loadPowerLevels(q querier, roomID string, create *Event) (*powerLevels, error) {
	pe, err := getStateEvent(q, roomID, "m.room.power_levels", "")
	if err != nil {
		return nil, err
	}
	if pe != nil {
		return parsePowerLevels(pe.Content), nil
	}
	// No power levels yet: the creator has 100, everyone else 0 (auth rules).
	p := parsePowerLevels([]byte(`{}`))
	if create != nil {
		r, _ := rulesFor(roomVersion(q, roomID))
		p.users[creatorOf(r, create)] = 100
	}
	return p, nil
}

func (p *powerLevels) userLevel(u string) int64 {
	if v, ok := p.users[u]; ok {
		return v
	}
	return p.usersDefault
}

func (p *powerLevels) eventLevel(t string, state bool) int64 {
	if v, ok := p.events[t]; ok {
		return v
	}
	if state {
		return p.stateDefault
	}
	return p.eventsDefault
}

// ---- authorization ----

// authorize is our extra policy for client sends, on top of the auth rules.
func (s *Server) authorize(tx *sql.Tx, ev *Event) error {
	if ev.Type == "m.room.create" {
		return errForbidden("m.room.create cannot be sent")
	}
	var blocked int
	if tx.QueryRow("SELECT blocked FROM rooms WHERE room_id = ?", ev.RoomID).Scan(&blocked) != nil {
		return errNotFound("room not found")
	}
	if blocked == 1 {
		return errForbidden("this room has been shut down by the server admin")
	}
	// state-only types via /send
	if ev.StateKey == nil && (ev.Type == "m.room.member" || ev.Type == "m.room.power_levels") {
		return errBadJSON(ev.Type + " must be sent as a state event, not through /send")
	}
	if ev.Type == "m.room.member" {
		return s.memberPolicy(tx, ev)
	}
	return nil
}

// memberPolicy: what the auth rules leave to us (remote targets, real invitees).
func (s *Server) memberPolicy(tx *sql.Tx, ev *Event) error {
	target := *ev.StateKey
	membership, ok := contentOf(ev)["membership"].(string)
	if !ok {
		return errBadJSON("m.room.member content needs a membership")
	}
	if !s.isLocal(target) {
		// remote users join via their own server; we can only kick/ban them
		ri, _ := getRoomInfo(tx, ev.RoomID)
		if !ri.federated || (membership != "leave" && membership != "ban") {
			return errForbidden("users of other servers can't be added to this room this way")
		}
	}
	switch membership {
	case "join", "ban":
	case "leave":
		// the auth rules allow kicking someone who isn't there; we don't
		if target != ev.Sender {
			if m, _ := getMembership(tx, ev.RoomID, target); m != "join" && m != "invite" && m != "ban" && m != "knock" {
				return errForbidden("user is not in the room")
			}
		}
	case "invite":
		// don't tell non-members whether the account exists
		if m, _ := getMembership(tx, ev.RoomID, ev.Sender); m == "join" {
			var x int
			if tx.QueryRow("SELECT 1 FROM users WHERE user_id = ? AND deactivated = 0", target).Scan(&x) != nil {
				return errNotFound("user does not exist")
			}
		}
	case "knock":
		return errForbidden("knocking is not supported yet")
	default:
		return errBadJSON("unsupported membership " + membership)
	}
	return nil
}

// ---- redaction ----

func (s *Server) redact(tx *sql.Tx, roomID, sender, targetID string, content map[string]any, sess *Session, txnID string) (*Event, error) {
	target, err := getEvent(tx, targetID)
	if err != nil {
		return nil, err
	}
	if target == nil || target.RoomID != roomID {
		return nil, errNotFound("event not found")
	}
	// A redacted m.room.encryption loses its algorithm and later joiners
	// would send plaintext. Redacting the create event is pointless.
	if target.Type == "m.room.create" || target.Type == "m.room.encryption" {
		return nil, errForbidden("this event cannot be redacted")
	}
	if m, _ := getMembership(tx, roomID, sender); m != "join" {
		return nil, errForbidden("you are not joined to this room")
	}
	create, _ := getStateEvent(tx, roomID, "m.room.create", "")
	pl, err := loadPowerLevels(tx, roomID, create)
	if err != nil {
		return nil, err
	}
	// Sending the redaction event itself needs its event level, like any event.
	if need := pl.eventLevel("m.room.redaction", false); pl.userLevel(sender) < need {
		return nil, errForbidden(fmt.Sprintf("you need power level %d to send m.room.redaction", need))
	}
	if target.Sender != sender && pl.userLevel(sender) < pl.redact {
		return nil, errForbidden("you do not have permission to redact this event")
	}
	if content == nil {
		content = map[string]any{}
	}
	content["redacts"] = targetID
	ev := s.newEvent(roomID, sender, "m.room.redaction", nil, content)
	ev.TxnDevice, ev.TxnID = sess.DeviceID, txnID
	if err := s.storeEvent(tx, ev); err != nil {
		return nil, err
	}
	because, _ := json.Marshal(ev.clientJSON("", "", true))
	if target.RedactedBecause == nil {
		// m.relates_to is gone too
		ver := roomVersion(tx, roomID)
		var pdu sql.NullString
		if err := tx.QueryRow("SELECT pdu FROM events WHERE event_id = ?", targetID).Scan(&pdu); err != nil {
			return nil, err
		}
		if pdu.Valid {
			red, err := redactStoredPDU(ver, pdu.String)
			if err != nil {
				return nil, err
			}
			pdu.String = red
		}
		_, err = tx.Exec(`UPDATE events SET content = ?, redacted_because = ?, rel_event_id = NULL, rel_type = NULL,
			pdu = ? WHERE event_id = ?`,
			string(pruneContent(target.Type, target.Content, ver)), string(because), pdu, targetID)
	}
	return ev, err
}
