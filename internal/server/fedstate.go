package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// State groups: events.state_group is the state right after the event,
// stored as a delta on an older group (full copy every 50).
// rooms.state_group is the current state, mirrored in room_state.

const stateSnapshotEvery = 50

// event visibility (events.hidden)
const (
	evVisible    = 0 // in the timeline
	evOutlier    = 1 // known only to check auth or state; not part of the timeline
	evSoftFailed = 2 // valid, but not allowed by the room's current state: hidden from clients
	evRejected   = 3 // failed the auth rules
)

func loadStateGroup(q querier, id int64) (stateMap, error) {
	if id == 0 {
		return stateMap{}, nil
	}
	var deltas []string
	for cur := id; cur != 0; {
		var prev sql.NullInt64
		var delta string
		if err := q.QueryRow("SELECT prev, delta FROM state_groups WHERE id = ?", cur).Scan(&prev, &delta); err != nil {
			return nil, fmt.Errorf("state group %d: %w", cur, err)
		}
		deltas = append(deltas, delta)
		cur = prev.Int64
		if len(deltas) > 10*stateSnapshotEvery {
			return nil, errors.New("state group chain too long")
		}
	}
	out := stateMap{}
	for i := len(deltas) - 1; i >= 0; i-- {
		var rows [][3]string
		if err := json.Unmarshal([]byte(deltas[i]), &rows); err != nil {
			return nil, err
		}
		for _, r := range rows {
			k := stateTuple{r[0], r[1]}
			if r[2] == "" {
				delete(out, k)
			} else {
				out[k] = r[2]
			}
		}
	}
	return out, nil
}

func encodeStateRows(m map[stateTuple]string) string {
	rows := make([][3]string, 0, len(m))
	for k, v := range m {
		rows = append(rows, [3]string{k.typ, k.key, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i][0] != rows[j][0] {
			return rows[i][0] < rows[j][0]
		}
		return rows[i][1] < rows[j][1]
	})
	b, _ := json.Marshal(rows)
	return string(b)
}

// addStateGroup stores delta on top of prev ("" removes a key).
func addStateGroup(tx *sql.Tx, roomID string, prev int64, delta map[stateTuple]string) (int64, error) {
	if len(delta) == 0 && prev != 0 {
		return prev, nil
	}
	chain := 0
	if prev != 0 {
		if err := tx.QueryRow("SELECT chain FROM state_groups WHERE id = ?", prev).Scan(&chain); err != nil {
			return 0, err
		}
	}
	var prevArg any
	rows := delta
	if prev != 0 && chain+1 < stateSnapshotEvery {
		prevArg, chain = prev, chain+1
	} else {
		full, err := loadStateGroup(tx, prev)
		if err != nil {
			return 0, err
		}
		for k, v := range delta {
			if v == "" {
				delete(full, k)
			} else {
				full[k] = v
			}
		}
		rows, chain = full, 0
	}
	res, err := tx.Exec("INSERT INTO state_groups (room_id, prev, delta, chain) VALUES (?,?,?,?)",
		roomID, prevArg, encodeStateRows(rows), chain)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// addStateGroupFor stores `state` as a group, as a delta on base when given.
func addStateGroupFor(tx *sql.Tx, roomID string, base int64, baseState, state stateMap) (int64, error) {
	delta := map[stateTuple]string{}
	for k, v := range state {
		if baseState[k] != v {
			delta[k] = v
		}
	}
	for k := range baseState {
		if _, ok := state[k]; !ok {
			delta[k] = ""
		}
	}
	if base == 0 {
		return addStateGroup(tx, roomID, 0, delta)
	}
	return addStateGroup(tx, roomID, base, delta)
}

// currentStateGroup is the group of the room's current state (0 if none yet).
func currentStateGroup(q querier, roomID string) int64 {
	var g sql.NullInt64
	q.QueryRow("SELECT state_group FROM rooms WHERE room_id = ?", roomID).Scan(&g)
	return g.Int64
}

// setCurrentState updates room_state and memberships to match state.
func (s *Server) setCurrentState(tx *sql.Tx, roomID string, group int64, state stateMap, stream int64) error {
	old := stateMap{}
	rows, err := tx.Query("SELECT type, state_key, event_id FROM room_state WHERE room_id = ?", roomID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var k stateTuple
		var id string
		if err := rows.Scan(&k.typ, &k.key, &id); err != nil {
			rows.Close()
			return err
		}
		old[k] = id
	}
	rows.Close()
	for k, id := range state {
		if old[k] == id {
			continue
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO room_state (room_id, type, state_key, event_id, stream) VALUES (?,?,?,?,?)`,
			roomID, k.typ, k.key, id, stream); err != nil {
			return err
		}
		if k.typ == "m.room.member" {
			ev, err := getEvent(tx, id)
			if err != nil || ev == nil {
				return fmt.Errorf("state event %s missing: %v", id, err)
			}
			if _, err := tx.Exec(`INSERT OR REPLACE INTO memberships (room_id, user_id, membership, stream) VALUES (?,?,?,?)`,
				roomID, k.key, membershipOf(ev), stream); err != nil {
				return err
			}
		}
	}
	for k := range old {
		if _, ok := state[k]; ok {
			continue
		}
		if _, err := tx.Exec("DELETE FROM room_state WHERE room_id = ? AND type = ? AND state_key = ?", roomID, k.typ, k.key); err != nil {
			return err
		}
		if k.typ == "m.room.member" {
			if _, err := tx.Exec("DELETE FROM memberships WHERE room_id = ? AND user_id = ?", roomID, k.key); err != nil {
				return err
			}
		}
	}
	_, err = tx.Exec("UPDATE rooms SET state_group = ? WHERE room_id = ?", group, roomID)
	return err
}

// buildStateGroups backfills state groups for rooms made before they existed.
func buildStateGroups(db *sql.DB) error {
	rows, err := db.Query("SELECT room_id FROM rooms WHERE federated = 1 AND state_group IS NULL")
	if err != nil {
		return err
	}
	var rooms []string
	for rows.Next() {
		var r string
		rows.Scan(&r)
		rooms = append(rooms, r)
	}
	rows.Close()
	for _, room := range rooms {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if err := buildRoomStateGroups(tx, room); err != nil {
			tx.Rollback()
			return fmt.Errorf("room %s: %w", room, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func buildRoomStateGroups(tx *sql.Tx, room string) error {
	rows, err := tx.Query("SELECT event_id, type, state_key FROM events WHERE room_id = ? ORDER BY stream", room)
	if err != nil {
		return err
	}
	type row struct {
		id, typ string
		sk      sql.NullString
	}
	var evs []row
	for rows.Next() {
		var r row
		rows.Scan(&r.id, &r.typ, &r.sk)
		evs = append(evs, r)
	}
	rows.Close()
	var group int64
	for _, e := range evs {
		if e.sk.Valid {
			g, err := addStateGroup(tx, room, group, map[stateTuple]string{{e.typ, e.sk.String}: e.id})
			if err != nil {
				return err
			}
			group = g
		}
		if _, err := tx.Exec("UPDATE events SET state_group = ? WHERE event_id = ?", group, e.id); err != nil {
			return err
		}
	}
	_, err = tx.Exec("UPDATE rooms SET state_group = ? WHERE room_id = ?", group, room)
	return err
}

// stateAfter returns the state just after a stored event of a federated room.
func stateAfter(q querier, eventID string) (stateMap, int64, error) {
	var g sql.NullInt64
	if err := q.QueryRow("SELECT state_group FROM events WHERE event_id = ?", eventID).Scan(&g); err != nil {
		return nil, 0, err
	}
	if !g.Valid {
		return nil, 0, fmt.Errorf("no state known after %s", eventID)
	}
	m, err := loadStateGroup(q, g.Int64)
	return m, g.Int64, err
}
