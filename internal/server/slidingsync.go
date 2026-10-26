package server

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Sliding sync (MSC4186, "simplified sliding sync") is what Element X uses
// instead of /sync. The client asks for windows of its room list, sorted by
// recent activity, plus the rooms it has open. We remember in memory what
// each connection has been sent and only send what changed. After a restart
// clients get M_UNKNOWN_POS and start over.

const slidingSyncPath = "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync"

// events of these types move a room to the top of the list
const bumpTypes = `'m.room.create', 'm.room.message', 'm.room.encrypted', 'm.sticker',
	'm.call.invite', 'm.poll.start', 'm.beacon_info'`

const (
	ssMaxConns     = 2000
	ssMaxPerUser   = 20
	ssKeepSnaps    = 3
	ssIdle         = 24 * time.Hour
	ssMaxLimit     = 100
	ssMaxStateReqs = 100
)

// ---- request ----

type ssRoomConfig struct {
	RequiredState [][2]string `json:"required_state"`
	TimelineLimit *int        `json:"timeline_limit"`
}

type ssFilters struct {
	IsDM         *bool     `json:"is_dm"`
	IsEncrypted  *bool     `json:"is_encrypted"`
	IsInvite     *bool     `json:"is_invite"`
	RoomTypes    []*string `json:"room_types"`
	NotRoomTypes []*string `json:"not_room_types"`
	RoomNameLike string    `json:"room_name_like"`
	Tags         []string  `json:"tags"`
	NotTags      []string  `json:"not_tags"`
	Spaces       []string  `json:"spaces"`
}

type ssList struct {
	Ranges [][2]int64 `json:"ranges"`
	ssRoomConfig
	Filters *ssFilters `json:"filters"`
}

type ssToggle struct {
	Enabled *bool `json:"enabled"`
}

type ssRequest struct {
	ConnID            string                  `json:"conn_id"`
	TxnID             string                  `json:"txn_id"`
	Lists             map[string]*ssList      `json:"lists"`
	RoomSubscriptions map[string]ssRoomConfig `json:"room_subscriptions"`
	Extensions        *struct {
		ToDevice *struct {
			Enabled *bool  `json:"enabled"`
			Limit   int    `json:"limit"`
			Since   string `json:"since"`
		} `json:"to_device"`
		E2EE        *ssToggle `json:"e2ee"`
		AccountData *ssToggle `json:"account_data"`
		Receipts    *ssToggle `json:"receipts"`
		Typing      *ssToggle `json:"typing"`
	} `json:"extensions"`
}

type ssExt struct {
	toDevice, e2ee, accountData, receipts, typing bool
	toDeviceLimit                                 int
}

// ---- connection state ----

// ssSent is what a connection has been told about a room.
type ssSent struct {
	upTo             int64 // events up to here were considered
	membership       string
	bump             int64
	notif, highlight int
	state            string // required_state the full state was sent for
}

// ssSnap is a connection's state after one response; the response's pos
// names it. Snapshots are never changed, so a retried request (same pos)
// gets the same answer.
type ssSnap struct {
	pos          string
	stream       int64
	rooms        map[string]ssSent
	counts       map[string]int
	otk          map[string]int
	lists        map[string]*ssList
	subs         map[string]ssRoomConfig
	ext          ssExt
	toDeviceNext string
}

type ssConn struct {
	used  time.Time
	snaps []*ssSnap
}

type ssStore struct {
	mu    sync.Mutex
	conns map[string]*ssConn
	boot  string
	seq   atomic.Int64
}

func (st *ssStore) find(key, pos string) *ssSnap {
	st.mu.Lock()
	defer st.mu.Unlock()
	c := st.conns[key]
	if c == nil {
		return nil
	}
	for _, sn := range c.snaps {
		if sn.pos == pos {
			c.used = time.Now()
			return sn
		}
	}
	return nil
}

func (st *ssStore) add(key string, sn *ssSnap, fresh bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.conns == nil {
		st.conns = map[string]*ssConn{}
		b := make([]byte, 6)
		rand.Read(b)
		st.boot = hex.EncodeToString(b)
	}
	sn.pos = st.boot + "_" + strconv.FormatInt(st.seq.Add(1), 10)
	c := st.conns[key]
	if c == nil || fresh {
		if c == nil {
			st.makeRoom(key[:strings.IndexByte(key, 0)+1])
		}
		c = &ssConn{}
		st.conns[key] = c
	}
	c.used = time.Now()
	c.snaps = append(c.snaps, sn)
	if len(c.snaps) > ssKeepSnaps {
		c.snaps = c.snaps[len(c.snaps)-ssKeepSnaps:]
	}
}

// makeRoom drops idle connections, then the user's or everyone's least
// recently used one if there are too many. Under mu.
func (st *ssStore) makeRoom(userPrefix string) {
	var mine int
	var oldest, oldestMine string
	for k, c := range st.conns {
		if time.Since(c.used) > ssIdle {
			delete(st.conns, k)
			continue
		}
		if oldest == "" || c.used.Before(st.conns[oldest].used) {
			oldest = k
		}
		if strings.HasPrefix(k, userPrefix) {
			mine++
			if oldestMine == "" || c.used.Before(st.conns[oldestMine].used) {
				oldestMine = k
			}
		}
	}
	if mine >= ssMaxPerUser {
		delete(st.conns, oldestMine)
	} else if len(st.conns) >= ssMaxConns {
		delete(st.conns, oldest)
	}
}

// ---- handler ----

func (s *Server) hSlidingSync(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req ssRequest
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if len(req.ConnID) > 64 || len(req.TxnID) > 255 || len(req.Lists) > 32 || len(req.RoomSubscriptions) > 200 {
		return nil, errInvalidParam("request too large")
	}
	q := r.URL.Query()
	timeout := min(max(atoiDefault(q.Get("timeout"), 0), 0), 60000)
	key := sess.UserID + "\x00" + sess.DeviceID + "\x00" + req.ConnID
	var prev *ssSnap
	if pos := q.Get("pos"); pos != "" {
		if prev = s.ss.find(key, pos); prev == nil {
			return nil, errf(400, "M_UNKNOWN_POS", "unknown or expired pos; start a new connection")
		}
	}
	lists, subs, ext, err := stickyParams(prev, &req)
	if err != nil {
		return nil, err
	}
	toDeviceSince := ""
	if e := req.Extensions; e != nil && e.ToDevice != nil {
		toDeviceSince = e.ToDevice.Since
	}
	if toDeviceSince == "" && prev != nil {
		toDeviceSince = prev.toDeviceNext
	}

	deadline := time.Now().Add(time.Duration(timeout) * time.Millisecond)
	var resp map[string]any
	var snap *ssSnap
	var seen int64
	var rooms, shared map[string]bool
	for {
		ch := s.waitCh() // before reading the position, so no commit is missed
		cur := s.committed.Load()
		if resp == nil || s.touches(sess.UserID, rooms, shared, seen, cur) {
			built, sn, has, err := s.buildSliding(sess, lists, subs, ext, toDeviceSince, prev, cur)
			if err != nil {
				return nil, err
			}
			resp, snap = built, sn
			if has || prev == nil {
				break
			}
			rooms = s.memberRooms(sess.UserID)
			shared = s.sharedUsers(sess.UserID)
		}
		seen = cur
		if !time.Now().Before(deadline) {
			break
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-ch:
			timer.Stop()
			continue
		case <-timer.C:
		case <-r.Context().Done():
			timer.Stop()
			return nil, nil // the client is gone (or gave up and sent a new request)
		}
		break
	}
	s.ss.add(key, snap, prev == nil)
	resp["pos"] = snap.pos
	if req.TxnID != "" {
		resp["txn_id"] = req.TxnID
	}
	return resp, nil
}

// stickyParams fills in what the request left out from the previous one.
// MSC4186 clients send everything each time, but older ones only send changes.
func stickyParams(prev *ssSnap, req *ssRequest) (map[string]*ssList, map[string]ssRoomConfig, ssExt, error) {
	lists, subs := req.Lists, req.RoomSubscriptions
	var ext ssExt
	if prev != nil {
		ext = prev.ext
		if lists == nil {
			lists = prev.lists
		} else {
			for name, l := range lists {
				old := prev.lists[name]
				if l == nil || old == nil {
					continue
				}
				if l.Ranges == nil {
					l.Ranges = old.Ranges
				}
				if l.RequiredState == nil {
					l.RequiredState = old.RequiredState
				}
				if l.TimelineLimit == nil {
					l.TimelineLimit = old.TimelineLimit
				}
				if l.Filters == nil {
					l.Filters = old.Filters
				}
			}
		}
		if subs == nil {
			subs = prev.subs
		}
	}
	for _, l := range lists {
		if l != nil && (len(l.Ranges) > 10 || len(l.RequiredState) > ssMaxStateReqs) {
			return nil, nil, ext, errInvalidParam("too many ranges or required_state entries")
		}
	}
	for _, c := range subs {
		if len(c.RequiredState) > ssMaxStateReqs {
			return nil, nil, ext, errInvalidParam("too many required_state entries")
		}
	}
	if e := req.Extensions; e != nil {
		set := func(t *ssToggle, v *bool) {
			if t != nil && t.Enabled != nil {
				*v = *t.Enabled
			}
		}
		if e.ToDevice != nil {
			if e.ToDevice.Enabled != nil {
				ext.toDevice = *e.ToDevice.Enabled
			}
			if e.ToDevice.Limit > 0 {
				ext.toDeviceLimit = min(e.ToDevice.Limit, 1000)
			}
		}
		set(e.E2EE, &ext.e2ee)
		set(e.AccountData, &ext.accountData)
		set(e.Receipts, &ext.receipts)
		set(e.Typing, &ext.typing)
	}
	if ext.toDeviceLimit == 0 {
		ext.toDeviceLimit = 100
	}
	return lists, subs, ext, nil
}

// memberRooms returns the rooms uid is joined to or invited to.
func (s *Server) memberRooms(uid string) map[string]bool {
	out := map[string]bool{}
	rows, err := s.db.Query("SELECT room_id FROM memberships WHERE user_id = ? AND membership IN ('join', 'invite')", uid)
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

// ---- building a response ----

// ssCand is a room that can show up in the user's lists. Filter fields are
// looked up the first time a filter needs them.
type ssCand struct {
	id, membership string
	mstream, bump  int64

	looked    bool
	encrypted bool
	roomType  *string
	name      string
	tags      map[string]bool
}

func (s *Server) lookCand(c *ssCand) {
	if c.looked {
		return
	}
	c.looked = true
	c.encrypted = stateString(s.db, c.id, "m.room.encryption", "", "algorithm") != ""
	var t sql.NullString
	s.db.QueryRow(`SELECT json_extract(e.content, '$.type') FROM room_state s JOIN events e ON e.event_id = s.event_id
		WHERE s.room_id = ? AND s.type = 'm.room.create' AND s.state_key = ''`, c.id).Scan(&t)
	if t.Valid {
		c.roomType = &t.String
	}
	c.name = stateString(s.db, c.id, "m.room.name", "", "name")
}

// ssCfg is the merged room config of every list and subscription that
// selected a room.
type ssCfg struct {
	req   map[[2]string]bool
	limit int
}

func (c *ssCfg) merge(rc ssRoomConfig) {
	if c.req == nil {
		c.req = map[[2]string]bool{}
	}
	for _, r := range rc.RequiredState {
		if len(c.req) < 2*ssMaxStateReqs {
			c.req[r] = true
		}
	}
	limit := 10
	if rc.TimelineLimit != nil {
		limit = min(max(*rc.TimelineLimit, 0), ssMaxLimit)
	}
	c.limit = max(c.limit, limit)
}

func (c *ssCfg) key() string {
	parts := make([]string, 0, len(c.req))
	for r := range c.req {
		parts = append(parts, r[0]+"\x00"+r[1])
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x01")
}

func (c *ssCfg) lazy() bool {
	return c.req[[2]string{"m.room.member", "$LAZY"}]
}

func (c *ssCfg) wants(typ, key, uid string, senders map[string]bool) bool {
	for r := range c.req {
		if r[0] != "*" && r[0] != typ {
			continue
		}
		switch r[1] {
		case "*", key:
			return true
		case "$ME":
			if key == uid {
				return true
			}
		case "$LAZY":
			if typ == "m.room.member" && senders[key] {
				return true
			}
		}
	}
	return false
}

func (s *Server) buildSliding(sess *Session, lists map[string]*ssList, subs map[string]ssRoomConfig, ext ssExt,
	toDeviceSince string, prev *ssSnap, cur int64) (map[string]any, *ssSnap, bool, error) {
	uid := sess.UserID
	var since int64
	prevRooms := map[string]ssSent{}
	if prev != nil {
		since, prevRooms = prev.stream, prev.rooms
	}

	rows, err := s.db.Query("SELECT room_id, membership, stream FROM memberships WHERE user_id = ?", uid)
	if err != nil {
		return nil, nil, false, err
	}
	var cands []*ssCand
	for rows.Next() {
		c := &ssCand{}
		rows.Scan(&c.id, &c.membership, &c.mstream)
		if c.mstream > cur {
			continue // picked up next time
		}
		switch c.membership {
		case "join", "invite":
		case "leave", "ban":
			// only to tell the client it's gone
			if _, known := prevRooms[c.id]; !known || c.mstream <= since {
				continue
			}
		default:
			continue
		}
		cands = append(cands, c)
	}
	rows.Close()
	byID := map[string]*ssCand{}
	for _, c := range cands {
		byID[c.id] = c
		c.bump = c.mstream
		if c.membership == "join" {
			var b sql.NullInt64
			s.db.QueryRow(`SELECT stream FROM events WHERE room_id = ? AND hidden = 0 AND stream <= ?
				AND type IN (`+bumpTypes+`) ORDER BY stream DESC LIMIT 1`, c.id, cur).Scan(&b)
			if b.Int64 > c.bump {
				c.bump = b.Int64
			}
		}
	}
	dms := s.directRooms(uid)

	snap := &ssSnap{stream: cur, rooms: make(map[string]ssSent, len(prevRooms)), counts: map[string]int{},
		lists: lists, subs: subs, ext: ext}
	for id, st := range prevRooms {
		if byID[id] != nil {
			snap.rooms[id] = st
		}
	}

	has := false
	selected := map[string]*ssCfg{}
	pick := func(id string, rc ssRoomConfig) {
		if selected[id] == nil {
			selected[id] = &ssCfg{}
		}
		selected[id].merge(rc)
	}
	listsOut := map[string]any{}
	names := make([]string, 0, len(lists))
	for n := range lists {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		l := lists[name]
		if l == nil {
			continue
		}
		var matched []*ssCand
		for _, c := range cands {
			if s.ssMatch(uid, c, l.Filters, dms) {
				matched = append(matched, c)
			}
		}
		sort.Slice(matched, func(i, j int) bool {
			if matched[i].bump != matched[j].bump {
				return matched[i].bump > matched[j].bump
			}
			return matched[i].id < matched[j].id
		})
		listsOut[name] = map[string]any{"count": len(matched)}
		snap.counts[name] = len(matched)
		if old, ok := prev.countOf(name); !ok || old != len(matched) {
			has = true
		}
		for _, rg := range l.Ranges {
			for i := max(rg[0], 0); i <= rg[1] && i < int64(len(matched)); i++ {
				pick(matched[i].id, l.ssRoomConfig)
			}
		}
	}
	for id, rc := range subs {
		if byID[id] != nil {
			pick(id, rc)
		}
	}

	// rooms nothing happened in since the last response can be skipped
	// without looking (unless the change log doesn't reach back that far)
	touched := s.touchedRooms(since, cur)

	ids := make([]string, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	roomsOut := map[string]any{}
	initial := map[string][]*Event{} // rooms sent in full, with their timelines
	for _, id := range ids {
		c, cfg, sent := byID[id], selected[id], snap.rooms[id]
		if prev != nil && touched != nil && !touched[id] && sent.upTo == since && sent.membership == c.membership &&
			sent.state == cfg.key() {
			sent.upTo = cur
			snap.rooms[id] = sent
			continue
		}
		room, evs, newSent, ok, err := s.ssRoom(sess, c, cfg, sent, since, cur, dms)
		if err != nil {
			return nil, nil, false, err
		}
		snap.rooms[id] = newSent
		if ok {
			roomsOut[id] = room
			has = true
			if room["initial"] == true {
				initial[id] = evs
			}
		}
	}

	extOut, extHas, err := s.ssExtensions(sess, ext, toDeviceSince, prev, snap, initial, cur)
	if err != nil {
		return nil, nil, false, err
	}
	return map[string]any{"lists": listsOut, "rooms": roomsOut, "extensions": extOut}, snap, has || extHas, nil
}

func (p *ssSnap) countOf(name string) (int, bool) {
	if p == nil {
		return 0, false
	}
	n, ok := p.counts[name]
	return n, ok
}

// touchedRooms lists the rooms with changes in (after, upTo], or nil if the
// change log doesn't go back that far.
func (s *Server) touchedRooms(after, upTo int64) map[string]bool {
	s.clogMu.Lock()
	defer s.clogMu.Unlock()
	if after < s.clogStart {
		return nil
	}
	out := map[string]bool{}
	i := sort.Search(len(s.clog), func(i int) bool { return s.clog[i].pos > after })
	for ; i < len(s.clog) && s.clog[i].pos <= upTo; i++ {
		if c := s.clog[i]; c.room != "" {
			out[c.room] = true
		}
	}
	return out
}

// directRooms returns the rooms the user's m.direct account data lists.
func (s *Server) directRooms(uid string) map[string]bool {
	out := map[string]bool{}
	var raw string
	if s.db.QueryRow("SELECT content FROM account_data WHERE user_id = ? AND room_id = '' AND type = 'm.direct'", uid).Scan(&raw) != nil {
		return out
	}
	var m map[string][]string
	json.Unmarshal([]byte(raw), &m)
	for _, rooms := range m {
		for _, r := range rooms {
			out[r] = true
		}
	}
	return out
}

func (s *Server) ssMatch(uid string, c *ssCand, f *ssFilters, dms map[string]bool) bool {
	if f == nil {
		return true
	}
	if f.IsInvite != nil && *f.IsInvite != (c.membership == "invite") {
		return false
	}
	if f.IsDM != nil && *f.IsDM != s.ssIsDM(uid, c, dms) {
		return false
	}
	need := f.IsEncrypted != nil || f.RoomTypes != nil || f.NotRoomTypes != nil || f.RoomNameLike != ""
	if need {
		s.lookCand(c)
	}
	if f.IsEncrypted != nil && *f.IsEncrypted != c.encrypted {
		return false
	}
	typeIn := func(list []*string) bool {
		for _, t := range list {
			if (t == nil && c.roomType == nil) || (t != nil && c.roomType != nil && *t == *c.roomType) {
				return true
			}
		}
		return false
	}
	if f.RoomTypes != nil && !typeIn(f.RoomTypes) {
		return false
	}
	if len(f.NotRoomTypes) > 0 && typeIn(f.NotRoomTypes) {
		return false
	}
	if f.RoomNameLike != "" && !strings.Contains(strings.ToLower(c.name), strings.ToLower(f.RoomNameLike)) {
		return false
	}
	if len(f.Tags) > 0 || len(f.NotTags) > 0 {
		if c.tags == nil {
			c.tags = map[string]bool{}
			var raw string
			s.db.QueryRow("SELECT content FROM account_data WHERE user_id = ? AND room_id = ? AND type = 'm.tag'",
				uid, c.id).Scan(&raw)
			var t struct {
				Tags map[string]json.RawMessage `json:"tags"`
			}
			json.Unmarshal([]byte(raw), &t)
			for k := range t.Tags {
				c.tags[k] = true
			}
		}
		anyTag := func(list []string) bool {
			for _, t := range list {
				if c.tags[t] {
					return true
				}
			}
			return false
		}
		if len(f.Tags) > 0 && !anyTag(f.Tags) {
			return false
		}
		if anyTag(f.NotTags) {
			return false
		}
	}
	if len(f.Spaces) > 0 {
		found := false
		for _, sp := range f.Spaces {
			var x int
			if s.db.QueryRow(`SELECT 1 FROM room_state s JOIN events e ON e.event_id = s.event_id
				WHERE s.room_id = ? AND s.type = 'm.space.child' AND s.state_key = ?
				AND json_extract(e.content, '$.via') IS NOT NULL`, sp, c.id).Scan(&x) == nil {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (s *Server) ssIsDM(uid string, c *ssCand, dms map[string]bool) bool {
	if dms[c.id] {
		return true
	}
	if c.membership == "invite" {
		// not in m.direct until accepted; the invite says whether it's a DM
		var d sql.NullBool
		s.db.QueryRow(`SELECT json_extract(e.content, '$.is_direct') FROM room_state s JOIN events e ON e.event_id = s.event_id
			WHERE s.room_id = ? AND s.type = 'm.room.member' AND s.state_key = ?`, c.id, uid).Scan(&d)
		if !d.Valid { // invited from another server
			s.db.QueryRow(`SELECT json_extract(e.content, '$.is_direct') FROM remote_invites r JOIN events e ON e.event_id = r.event_id
				WHERE r.room_id = ? AND r.user_id = ?`, c.id, uid).Scan(&d)
		}
		return d.Bool
	}
	return false
}

// ssRoom builds one room's entry; ok is false when there's nothing new.
func (s *Server) ssRoom(sess *Session, c *ssCand, cfg *ssCfg, sent ssSent, since, cur int64, dms map[string]bool) (map[string]any, []*Event, ssSent, bool, error) {
	uid := sess.UserID
	stateKey := cfg.key()
	if c.membership == "invite" {
		if sent.membership == "invite" && sent.upTo >= c.mstream {
			sent.upTo = cur
			return nil, nil, sent, false, nil
		}
		// stripped events only: clients (matrix-rust-sdk) treat ones with an
		// event_id as full events and lose the invite's details
		stripped := s.strippedState(c.id, uid)
		for i, e := range stripped {
			if m, ok := e.(map[string]any); ok {
				stripped[i] = map[string]any{"type": m["type"], "state_key": m["state_key"], "content": m["content"], "sender": m["sender"]}
			}
		}
		out := map[string]any{"initial": true, "bump_stamp": c.bump, "invite_state": stripped,
			"notification_count": 0, "highlight_count": 0}
		// no is_dm here (like Synapse): clients read is_direct from the invite
		return out, nil, ssSent{upTo: cur, membership: "invite", state: stateKey, bump: c.bump}, true, nil
	}

	// joined now (first time on this connection, or after an invite or a
	// leave): the whole room. Joined before: what's new. Left: up to the leave.
	initial := c.membership == "join" && sent.membership != "join"
	upper, lower := cur, sent.upTo
	if c.membership != "join" {
		upper = c.mstream
		if sent.membership != "join" {
			lower = c.mstream - 1 // only the leave itself
		}
	}
	if initial {
		lower = 0
	}
	lower = min(lower, upper)
	evs, err := queryEvents(s.db, "SELECT "+evCols+` FROM events WHERE room_id = ? AND hidden = 0 AND stream > ? AND stream <= ?
		ORDER BY stream DESC LIMIT ?`, c.id, lower, upper, cfg.limit+1)
	if err != nil {
		return nil, nil, sent, false, err
	}
	limited := len(evs) > cfg.limit
	if limited {
		evs = evs[:cfg.limit]
	}
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	var notif, highlight int
	if c.membership == "join" {
		notif, highlight = s.unreadCounts(s.db, c.id, uid, joinStream(s.db, c.id, uid, cur), cur)
	}
	fullState := initial || stateKey != sent.state
	newSent := ssSent{upTo: upper, membership: c.membership, notif: notif, highlight: highlight, state: stateKey, bump: c.bump}
	if !initial && len(evs) == 0 && !fullState && notif == sent.notif && highlight == sent.highlight &&
		c.membership == sent.membership && c.bump == sent.bump {
		return nil, nil, newSent, false, nil
	}

	// required_state: all of it the first time (or when the client asks for
	// different state), afterwards only what changed
	senders := map[string]bool{} // for $LAZY: senders, and whoever member events are about
	for _, e := range evs {
		senders[e.Sender] = true
		if e.Type == "m.room.member" && e.StateKey != nil {
			senders[*e.StateKey] = true
		}
	}
	query, args := "SELECT type, state_key, event_id FROM room_state WHERE room_id = ? AND stream <= ?", []any{c.id, upper}
	if !fullState {
		query += " AND stream > ?"
		args = append(args, sent.upTo)
	}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, nil, sent, false, err
	}
	var ids []string
	seen := map[string]bool{}
	for rows.Next() {
		var typ, key, id string
		rows.Scan(&typ, &key, &id)
		if cfg.wants(typ, key, uid, senders) && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	rows.Close()
	if !fullState && cfg.lazy() {
		// members of new senders, even if their member event didn't change
		for u := range senders {
			var id string
			if s.db.QueryRow("SELECT event_id FROM room_state WHERE room_id = ? AND type = 'm.room.member' AND state_key = ? AND stream <= ?",
				c.id, u, upper).Scan(&id) == nil && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	state, err := eventsByID(s.db, ids)
	if err != nil {
		return nil, nil, sent, false, err
	}

	s.bundle(evs, uid)
	prevBatch := tok(upper)
	if len(evs) > 0 {
		prevBatch = tok(evs[0].Stream - 1)
	}
	// live: what happened since the client's last response
	live := 0
	for _, e := range evs {
		if since > 0 && e.Stream > since {
			live++
		}
	}
	out := map[string]any{
		"timeline":       renderEvents(evs, uid, sess.DeviceID, false),
		"limited":        limited,
		"prev_batch":     prevBatch,
		"required_state": renderEvents(state, uid, sess.DeviceID, false),
		"num_live":       live,
	}
	if initial {
		out["initial"] = true
	}
	if initial || c.bump != sent.bump {
		out["bump_stamp"] = c.bump
	}
	out["notification_count"], out["highlight_count"] = notif, highlight
	if c.membership != "join" {
		return out, evs, newSent, true, nil // after leaving, nothing about the room as it is now
	}
	var joined, invited int
	s.db.QueryRow(`SELECT COALESCE(SUM(membership = 'join'), 0), COALESCE(SUM(membership = 'invite'), 0)
		FROM memberships WHERE room_id = ?`, c.id).Scan(&joined, &invited)
	out["joined_count"], out["invited_count"] = joined, invited
	if name := stateString(s.db, c.id, "m.room.name", "", "name"); name != "" {
		out["name"] = name
	} else if heroes := s.heroes(c.id, uid); len(heroes) > 0 {
		out["heroes"] = heroes
	}
	if avatar := stateString(s.db, c.id, "m.room.avatar", "", "url"); avatar != "" {
		out["avatar"] = avatar
	}
	if s.ssIsDM(uid, c, dms) {
		out["is_dm"] = true
	}
	return out, evs, newSent, true, nil
}

// heroes are the members a client names an unnamed room after.
func (s *Server) heroes(roomID, uid string) []any {
	rows, err := s.db.Query(`SELECT m.user_id, json_extract(e.content, '$.displayname'), json_extract(e.content, '$.avatar_url')
		FROM memberships m JOIN room_state s ON s.room_id = m.room_id AND s.type = 'm.room.member' AND s.state_key = m.user_id
		JOIN events e ON e.event_id = s.event_id
		WHERE m.room_id = ? AND m.user_id != ? AND m.membership IN ('join', 'invite') ORDER BY m.stream LIMIT 5`, roomID, uid)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []any
	for rows.Next() {
		var u string
		var name, avatar sql.NullString
		rows.Scan(&u, &name, &avatar)
		h := map[string]any{"user_id": u}
		if name.String != "" {
			h["displayname"] = name.String
		}
		if avatar.String != "" {
			h["avatar_url"] = avatar.String
		}
		out = append(out, h)
	}
	return out
}

func eventsByID(q querier, ids []string) ([]*Event, error) {
	var out []*Event
	for len(ids) > 0 {
		n := min(len(ids), 500)
		args := make([]any, n)
		for i := range n {
			args[i] = ids[i]
		}
		evs, err := queryEvents(q, "SELECT "+evCols+" FROM events WHERE event_id IN (?"+strings.Repeat(",?", n-1)+") ORDER BY stream", args...)
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
		ids = ids[n:]
	}
	return out, nil
}

// ssExtensions fills in to-device messages, E2EE counts, account data,
// receipts and typing. Room data is only sent for rooms the client knows.
func (s *Server) ssExtensions(sess *Session, ext ssExt, toDeviceSince string, prev, snap *ssSnap,
	initial map[string][]*Event, cur int64) (map[string]any, bool, error) {
	uid, dev := sess.UserID, sess.DeviceID
	out := map[string]any{}
	has := false
	var since int64
	if prev != nil {
		since = prev.stream
	}
	joined := func(id string) bool { return snap.rooms[id].membership == "join" }

	if ext.toDevice {
		from, _ := strconv.ParseInt(toDeviceSince, 10, 64)
		if from > 0 {
			// the client has these
			var x int
			if s.db.QueryRow("SELECT 1 FROM to_device WHERE user_id = ? AND device_id = ? AND stream <= ? LIMIT 1",
				uid, dev, from).Scan(&x) == nil {
				if err := s.write(func(tx *sql.Tx) error {
					_, err := tx.Exec("DELETE FROM to_device WHERE user_id = ? AND device_id = ? AND stream <= ?", uid, dev, from)
					return err
				}); err != nil {
					return nil, false, err
				}
			}
		}
		rows, err := s.db.Query(`SELECT stream, sender, type, content FROM to_device WHERE user_id = ? AND device_id = ?
			AND stream > ? AND stream <= ? ORDER BY stream LIMIT ?`, uid, dev, from, cur, ext.toDeviceLimit)
		if err != nil {
			return nil, false, err
		}
		evs := []any{}
		var last int64
		for rows.Next() {
			var sender, typ, content string
			rows.Scan(&last, &sender, &typ, &content)
			evs = append(evs, map[string]any{"sender": sender, "type": typ, "content": json.RawMessage(content)})
		}
		rows.Close()
		next := max(cur, from)
		if len(evs) == ext.toDeviceLimit {
			next = last // more to come
		}
		if len(evs) > 0 {
			has = true
		}
		snap.toDeviceNext = strconv.FormatInt(next, 10)
		out["to_device"] = map[string]any{"next_batch": snap.toDeviceNext, "events": evs}
	}

	if ext.e2ee {
		changed, left := []string{}, []string{}
		if prev != nil {
			changed, left = s.deviceListChanges(uid, since, cur)
			if len(changed)+len(left) > 0 {
				has = true
			}
		} else {
			// a new connection (e.g. after a restart) can't know what changed
			// since the last one: have the client re-check everyone's devices
			for u := range s.sharedUsers(uid) {
				changed = append(changed, u)
			}
			sort.Strings(changed)
		}
		otk, fallback := s.keyCounts(uid, dev)
		snap.otk = otk
		if prev != nil && !sameCounts(prev.otk, otk) {
			has = true
		}
		out["e2ee"] = map[string]any{
			"device_lists":                     map[string]any{"changed": changed, "left": left},
			"device_one_time_keys_count":       otk,
			"device_unused_fallback_key_types": fallback,
		}
	}

	if ext.accountData {
		global, err := s.accountDataSince(uid, "", since, cur)
		if err != nil {
			return nil, false, err
		}
		rooms := map[string]any{}
		for id := range initial {
			if evs, _ := s.accountDataSince(uid, id, 0, cur); len(evs) > 0 {
				rooms[id] = evs
			}
		}
		if prev != nil {
			rows, err := s.db.Query(`SELECT room_id, type, content FROM account_data WHERE user_id = ? AND room_id != ''
				AND stream > ? AND stream <= ?`, uid, since, cur)
			if err != nil {
				return nil, false, err
			}
			for rows.Next() {
				var id, t, c string
				rows.Scan(&id, &t, &c)
				if _, known := snap.rooms[id]; known && initial[id] == nil {
					list, _ := rooms[id].([]any)
					rooms[id] = append(list, map[string]any{"type": t, "content": json.RawMessage(c)})
				}
			}
			rows.Close()
		}
		if len(global)+len(rooms) > 0 {
			has = true
		}
		out["account_data"] = map[string]any{"global": global, "rooms": rooms}
	}

	if ext.receipts {
		content := map[string]map[string]map[string]map[string]any{} // room -> event -> type -> user
		add := func(room, user, typ, ev string, ts int64) {
			if typ == "m.read.private" && user != uid {
				return
			}
			if content[room] == nil {
				content[room] = map[string]map[string]map[string]any{}
			}
			if content[room][ev] == nil {
				content[room][ev] = map[string]map[string]any{}
			}
			if content[room][ev][typ] == nil {
				content[room][ev][typ] = map[string]any{}
			}
			content[room][ev][typ][user] = map[string]any{"ts": ts}
		}
		for id, evs := range initial {
			if !joined(id) {
				continue
			}
			args := []any{id, uid}
			for _, e := range evs {
				args = append(args, e.EventID)
			}
			rows, err := s.db.Query(`SELECT user_id, type, event_id, ts FROM receipts WHERE room_id = ?
				AND (user_id = ? OR event_id IN (''`+strings.Repeat(",?", len(evs))+`))`, args...)
			if err != nil {
				return nil, false, err
			}
			for rows.Next() {
				var u, t, e string
				var ts int64
				rows.Scan(&u, &t, &e, &ts)
				add(id, u, t, e, ts)
			}
			rows.Close()
		}
		if prev != nil {
			rows, err := s.db.Query("SELECT room_id, user_id, type, event_id, ts FROM receipts WHERE stream > ? AND stream <= ?", since, cur)
			if err != nil {
				return nil, false, err
			}
			for rows.Next() {
				var id, u, t, e string
				var ts int64
				rows.Scan(&id, &u, &t, &e, &ts)
				if joined(id) && initial[id] == nil {
					add(id, u, t, e, ts)
				}
			}
			rows.Close()
		}
		rooms := map[string]any{}
		for id, c := range content {
			rooms[id] = map[string]any{"type": "m.receipt", "content": c}
		}
		if len(rooms) > 0 {
			has = true
		}
		out["receipts"] = map[string]any{"rooms": rooms}
	}

	if ext.typing {
		rooms := map[string]any{}
		s.tmu.Lock()
		for id := range snap.rooms {
			if !joined(id) {
				continue
			}
			tp := s.typingPos[id]
			if (initial[id] != nil && len(s.typing[id]) > 0) || (initial[id] == nil && prev != nil && tp > since && tp <= cur) {
				users := []string{}
				for u := range s.typing[id] {
					users = append(users, u)
				}
				sort.Strings(users)
				rooms[id] = map[string]any{"type": "m.typing", "content": map[string]any{"user_ids": users}}
			}
		}
		s.tmu.Unlock()
		if len(rooms) > 0 {
			has = true
		}
		out["typing"] = map[string]any{"rooms": rooms}
	}
	return out, has, nil
}

func sameCounts(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
