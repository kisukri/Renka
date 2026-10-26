package server

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  user_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL, displayname TEXT, avatar_url TEXT,
  is_admin INTEGER NOT NULL DEFAULT 0, created_ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
  user_id TEXT NOT NULL, device_id TEXT NOT NULL, display_name TEXT, access_token TEXT NOT NULL UNIQUE,
  last_seen_ts INTEGER, last_seen_ip TEXT, PRIMARY KEY (user_id, device_id));
CREATE TABLE IF NOT EXISTS rooms (
  room_id TEXT PRIMARY KEY, version TEXT NOT NULL, creator TEXT NOT NULL,
  published INTEGER NOT NULL DEFAULT 0, created_ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS events (
  stream INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, room_id TEXT NOT NULL, type TEXT NOT NULL,
  state_key TEXT, sender TEXT NOT NULL, content TEXT NOT NULL, origin_ts INTEGER NOT NULL,
  prev_content TEXT, redacted_because TEXT, txn_device TEXT, txn_id TEXT,
  rel_event_id TEXT, rel_type TEXT);
CREATE INDEX IF NOT EXISTS events_room ON events (room_id, stream);
CREATE INDEX IF NOT EXISTS events_rel ON events (rel_event_id, rel_type) WHERE rel_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_state ON events (room_id, type, state_key, stream) WHERE state_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS room_state (
  room_id TEXT NOT NULL, type TEXT NOT NULL, state_key TEXT NOT NULL, event_id TEXT NOT NULL,
  stream INTEGER NOT NULL, PRIMARY KEY (room_id, type, state_key));
CREATE INDEX IF NOT EXISTS room_state_stream ON room_state (room_id, stream);
CREATE TABLE IF NOT EXISTS memberships (
  room_id TEXT NOT NULL, user_id TEXT NOT NULL, membership TEXT NOT NULL, stream INTEGER NOT NULL,
  PRIMARY KEY (room_id, user_id));
CREATE INDEX IF NOT EXISTS memberships_user ON memberships (user_id);
CREATE TABLE IF NOT EXISTS aliases (alias TEXT PRIMARY KEY, room_id TEXT NOT NULL, creator TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS account_data (
  user_id TEXT NOT NULL, room_id TEXT NOT NULL, type TEXT NOT NULL, content TEXT NOT NULL,
  stream INTEGER NOT NULL, PRIMARY KEY (user_id, room_id, type));
CREATE TABLE IF NOT EXISTS filters (id INTEGER PRIMARY KEY, user_id TEXT NOT NULL, filter TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS txns (
  user_id TEXT NOT NULL, device_id TEXT NOT NULL, txn_id TEXT NOT NULL, event_id TEXT NOT NULL,
  PRIMARY KEY (user_id, device_id, txn_id));
CREATE TABLE IF NOT EXISTS receipts (
  room_id TEXT NOT NULL, user_id TEXT NOT NULL, type TEXT NOT NULL, event_id TEXT NOT NULL,
  ts INTEGER NOT NULL, stream INTEGER NOT NULL, PRIMARY KEY (room_id, user_id, type));
CREATE TABLE IF NOT EXISTS device_keys (
  user_id TEXT NOT NULL, device_id TEXT NOT NULL, keys TEXT NOT NULL, PRIMARY KEY (user_id, device_id));
CREATE TABLE IF NOT EXISTS one_time_keys (
  user_id TEXT NOT NULL, device_id TEXT NOT NULL, key_id TEXT NOT NULL, algorithm TEXT NOT NULL,
  key TEXT NOT NULL, PRIMARY KEY (user_id, device_id, key_id));
CREATE TABLE IF NOT EXISTS fallback_keys (
  user_id TEXT NOT NULL, device_id TEXT NOT NULL, algorithm TEXT NOT NULL, key_id TEXT NOT NULL,
  key TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (user_id, device_id, algorithm));
CREATE TABLE IF NOT EXISTS cross_signing (
  user_id TEXT NOT NULL, key_type TEXT NOT NULL, keys TEXT NOT NULL, PRIMARY KEY (user_id, key_type));
CREATE TABLE IF NOT EXISTS to_device (
  stream INTEGER PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL, sender TEXT NOT NULL,
  type TEXT NOT NULL, content TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS to_device_target ON to_device (user_id, device_id, stream);
CREATE TABLE IF NOT EXISTS device_list_changes (stream INTEGER PRIMARY KEY, user_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS backup_versions (
  version INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, algorithm TEXT NOT NULL,
  auth_data TEXT NOT NULL, etag INTEGER NOT NULL DEFAULT 0, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS backup_keys (
  user_id TEXT NOT NULL, version INTEGER NOT NULL, room_id TEXT NOT NULL, session_id TEXT NOT NULL,
  data TEXT NOT NULL, PRIMARY KEY (user_id, version, room_id, session_id));
CREATE TABLE IF NOT EXISTS media (
  media_id TEXT PRIMARY KEY, content_type TEXT NOT NULL, filename TEXT, size INTEGER NOT NULL,
  uploader TEXT NOT NULL, created_ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS media_uploader ON media (uploader);
CREATE TABLE IF NOT EXISTS pushers (
  user_id TEXT NOT NULL, device_id TEXT NOT NULL, app_id TEXT NOT NULL, pushkey TEXT NOT NULL, kind TEXT NOT NULL,
  app_display_name TEXT NOT NULL DEFAULT '', device_display_name TEXT NOT NULL DEFAULT '',
  profile_tag TEXT NOT NULL DEFAULT '', lang TEXT NOT NULL DEFAULT '', data TEXT NOT NULL, ts INTEGER NOT NULL,
  PRIMARY KEY (user_id, app_id, pushkey));
CREATE INDEX IF NOT EXISTS pushers_key ON pushers (app_id, pushkey);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS remote_invites (
  room_id TEXT NOT NULL, user_id TEXT NOT NULL, event_id TEXT NOT NULL, room_version TEXT NOT NULL,
  invite_state TEXT NOT NULL, PRIMARY KEY (room_id, user_id));
CREATE TABLE IF NOT EXISTS remote_media (
  server TEXT NOT NULL, media_id TEXT NOT NULL, content_type TEXT NOT NULL, filename TEXT NOT NULL,
  size INTEGER NOT NULL, fetched_ts INTEGER NOT NULL, last_used INTEGER NOT NULL, PRIMARY KEY (server, media_id));
CREATE TABLE IF NOT EXISTS fed_edus (id INTEGER PRIMARY KEY, dest TEXT NOT NULL, edu TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS fed_edus_dest ON fed_edus (dest, id);
CREATE TABLE IF NOT EXISTS remote_signatures (
  user_id TEXT NOT NULL, key_id TEXT NOT NULL, signer TEXT NOT NULL, sigs TEXT NOT NULL,
  PRIMARY KEY (user_id, key_id, signer));
CREATE TABLE IF NOT EXISTS fed_destinations (
  server TEXT PRIMARY KEY, last_stream INTEGER NOT NULL, retry_at INTEGER NOT NULL, backoff INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS state_groups (
  id INTEGER PRIMARY KEY, room_id TEXT NOT NULL, prev INTEGER, delta TEXT NOT NULL, chain INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS room_extremities (
  room_id TEXT NOT NULL, event_id TEXT NOT NULL, depth INTEGER NOT NULL, PRIMARY KEY (room_id, event_id));
`

type Server struct {
	cfg *Config
	db  *sql.DB

	wmu       sync.Mutex   // serializes all writes
	pos       atomic.Int64 // last allocated stream position
	committed atomic.Int64 // last stream position visible to readers

	nmu      sync.Mutex
	notifyCh chan struct{} // closed (and replaced) whenever new data is committed

	tmu       sync.Mutex
	typing    map[string]map[string]int64 // room -> user -> expiry (ms)
	typingPos map[string]int64            // room -> stream position of last change

	// prepared once: it runs on every authenticated request
	stmtAuth *sql.Stmt

	pending        []change   // changes made by the write in progress (guarded by wmu)
	pendingEvents  []*Event   // events stored by it, for push notifications
	pendingReaders []string   // users who sent read receipts in it (badge updates)
	pendingEDUs    bool       // it queued EDUs for other servers
	clogMu         sync.Mutex // guards clog / clogStart
	clog           []change   // recent committed changes, in stream order
	clogStart      int64      // clog covers every position after this one

	limiter     *limiter      // failed password / token attempts per IP
	acctLimiter *limiter      // failed password attempts per account
	regLimiter  *limiter      // new accounts per IP
	thumbSem    chan struct{} // limits concurrent thumbnail generation (memory)

	// push notifications (push.go)
	pushQ          chan pushJob
	pushSem        chan struct{}
	pushClient     *http.Client
	pushMu         sync.Mutex
	lastBadge      map[string]int // app\x00pushkey -> unread count last sent
	pushDropLogged time.Time

	// federation (federation.go)
	fedKey             signingKey
	fedMu              sync.Mutex
	fedRoutes          map[string]fedRoute
	fedKeys            map[string]*keySet // other servers' signing keys (fedkeys.go)
	fedClient          *http.Client
	fedWellKnownClient *http.Client
	fedLookupSRV       func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	fedWellKnown       func(ctx context.Context, host string) (string, error)
	fedGetKeys         func(ctx context.Context, server string, out *map[string]any) error
	fedTxns            txnSeen        // recent incoming transactions (fedserver.go)
	fedOut             *fedOut        // outgoing transactions (fedout.go)
	fedRefuseTxns      atomic.Bool    // tests: answer incoming transactions with 503
	toDeviceSeen       seenIDs        // incoming to-device message IDs (fede2ee.go)
	remoteKeys         remoteKeyCache // other servers' device keys
	mediaFetch         mediaFetches   // remote media downloads in progress (fedmedia.go)

	// admin commands (admin.go)
	adminRoomID         atomic.Value // string
	adminQ              chan *Event
	adminLn             net.Listener
	started             time.Time
	passwordRedactDelay time.Duration
}

type querier interface {
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
	Exec(query string, args ...any) (sql.Result, error)
}

func newServer(cfg *Config) (*Server, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.Database), 0o750); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(cfg.MediaDir, "thumbs"), 0o750); err != nil {
		return nil, err
	}
	// _txlock=immediate: take the write lock at BEGIN. With deferred
	// transactions a read-then-write tx got SQLITE_BUSY right away (no
	// busy_timeout wait) and we saw random 500s under load.
	dsn := cfg.Database + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)" +
		"&_pragma=synchronous(NORMAL)&_pragma=cache_size(-4000)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		return nil, err
	}
	if err := buildStateGroups(db); err != nil {
		return nil, fmt.Errorf("state groups: %w", err)
	}
	stmtAuth, err := db.Prepare(authSQL)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, db: db,
		notifyCh:    make(chan struct{}),
		typing:      map[string]map[string]int64{},
		typingPos:   map[string]int64{},
		stmtAuth:    stmtAuth,
		limiter:     newLimiter(10, 10*time.Minute),
		acctLimiter: newLimiter(30, 10*time.Minute),
		regLimiter:  newLimiter(20, 10*time.Minute),
		thumbSem:    make(chan struct{}, 1),
	}
	var max int64
	err = db.QueryRow(`SELECT MAX(m) FROM (
		SELECT COALESCE(MAX(stream),0) m FROM events UNION ALL
		SELECT COALESCE(MAX(stream),0) FROM account_data UNION ALL
		SELECT COALESCE(MAX(stream),0) FROM receipts UNION ALL
		SELECT COALESCE(MAX(stream),0) FROM to_device UNION ALL
		SELECT COALESCE(MAX(stream),0) FROM device_list_changes UNION ALL
		SELECT COALESCE(MAX(v),0) FROM meta WHERE k='stream')`).Scan(&max)
	if err != nil {
		return nil, err
	}
	s.pos.Store(max)
	s.committed.Store(max)
	s.clogStart = max
	s.started = time.Now()
	s.passwordRedactDelay = 10 * time.Minute
	dummyHash() // build now, so the first unknown-user login isn't slower than the rest
	if cfg.Push {
		s.startPusher()
	}
	if cfg.Federation {
		if err := s.startFederation(); err != nil {
			return nil, fmt.Errorf("federation: %w", err)
		}
	}
	go s.typingReaper()
	go s.txnReaper()
	return s, nil
}

// txnReaper trims the txn dedup table. Clients only retry within seconds,
// so the newest ~100k rows are plenty.
func (s *Server) txnReaper() {
	for range time.Tick(time.Hour) {
		s.write(func(tx *sql.Tx) error {
			_, err := tx.Exec("DELETE FROM txns WHERE rowid <= (SELECT MAX(rowid) - 100000 FROM txns)")
			return err
		})
	}
}

// write runs fn in a transaction. New stream positions show up in /sync
// only after the commit.
func (s *Server) write(fn func(tx *sql.Tx) error) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	start := s.committed.Load()
	s.resetPending()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	// Don't leak the connection on panic (the pool is only 4 wide).
	// Roll back, then re-panic so net/http logs it.
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			s.pos.Store(start)
			s.resetPending()
			panic(r)
		}
	}()
	if err := fn(tx); err != nil {
		tx.Rollback()
		s.pos.Store(start)
		return err
	}
	if s.pos.Load() != start {
		if _, err := tx.Exec("INSERT OR REPLACE INTO meta (k, v) VALUES ('stream', ?)", s.pos.Load()); err != nil {
			tx.Rollback()
			s.pos.Store(start)
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		s.pos.Store(start)
		return err
	}
	if p := s.pos.Load(); p != start {
		s.publish(s.pending) // before committed moves, so waiters never miss an entry
		s.committed.Store(p)
		s.notify()
		// only committed events are pushed; a rolled-back one never is
		s.enqueuePush(s.pendingEvents, s.pendingReaders)
		s.enqueueAdmin(s.pendingEvents)
	}
	if len(s.pendingEvents) > 0 || s.pendingEDUs {
		s.kickSender()
	}
	return nil
}

// resetPending clears what the current write has collected. Called under wmu.
func (s *Server) resetPending() {
	s.pending = s.pending[:0]
	s.pendingEvents = nil
	s.pendingReaders = nil
	s.pendingEDUs = false
}

// next allocates a stream position. Use nextFor instead, or no /sync wakes up.
func (s *Server) next() int64 { return s.pos.Add(1) }

// ---- change log ----
//
// Each stream position remembers what it touched, so a waiting /sync only
// rebuilds when something it can see changed.

// change is what one stream position touched.
type change struct {
	pos  int64
	room string // a room event, receipt or typing change
	user string // account data / to-device for this user, or the target of a membership change
	dev  string // this user's devices or keys changed
}

const changeLogSize = 8192

// nextFor allocates a stream position and logs what it touched. Inside write() only.
func (s *Server) nextFor(c change) int64 {
	c.pos = s.next()
	s.pending = append(s.pending, c)
	return c.pos
}

// publish appends a committed write's changes, keeping the log bounded.
func (s *Server) publish(cs []change) {
	if len(cs) == 0 {
		return
	}
	s.clogMu.Lock()
	defer s.clogMu.Unlock()
	s.clog = append(s.clog, cs...)
	if len(s.clog) > 2*changeLogSize {
		drop := len(s.clog) - changeLogSize
		s.clogStart = s.clog[drop-1].pos
		s.clog = append([]change(nil), s.clog[drop:]...)
	}
}

// touches reports whether anything in (after, upTo] concerns uid. Says yes
// if the log doesn't go back that far.
func (s *Server) touches(uid string, rooms, shared map[string]bool, after, upTo int64) bool {
	if upTo <= after {
		return false
	}
	s.clogMu.Lock()
	defer s.clogMu.Unlock()
	if after < s.clogStart {
		return true
	}
	i := sort.Search(len(s.clog), func(i int) bool { return s.clog[i].pos > after })
	for ; i < len(s.clog) && s.clog[i].pos <= upTo; i++ {
		c := s.clog[i]
		if (c.room != "" && rooms[c.room]) || c.user == uid || (c.dev != "" && shared[c.dev]) {
			return true
		}
	}
	return false
}

func (s *Server) notify() {
	s.nmu.Lock()
	close(s.notifyCh)
	s.notifyCh = make(chan struct{})
	s.nmu.Unlock()
}

func (s *Server) waitCh() chan struct{} {
	s.nmu.Lock()
	defer s.nmu.Unlock()
	return s.notifyCh
}

// landingPage is served at "/" so you can see the server is up.
// 連歌 (renka): linked verse, people taking turns adding lines.
const landingPage = `renka wa ikiteimasu.
(連歌は生きています — renka is alive)

kimi ga ikku, boku ga tsugu — you add a line, I add the next.

a matrix homeserver, not a web page.
point a matrix client here: __BASE__
`

func (s *Server) hRoot(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte(strings.ReplaceAll(landingPage, "__BASE__", s.cfg.PublicBaseURL)))
	return nil, nil
}

func (s *Server) isLocal(id string) bool {
	_, server, ok := splitID(id)
	return ok && server == s.cfg.ServerName
}

// ---- HTTP plumbing ----

type Session struct {
	UserID   string
	DeviceID string
	Admin    bool
}

// authSQL looks up an access token; it runs on every authenticated request.
const authSQL = `SELECT d.user_id, d.device_id, u.is_admin FROM devices d
	JOIN users u ON u.user_id = d.user_id WHERE d.access_token = ? AND u.deactivated = 0`

// handler returns a JSON-able response, or (nil, nil) if it wrote the response itself.
type handler func(w http.ResponseWriter, r *http.Request, sess *Session) (any, error)

func (s *Server) wrap(h handler, needAuth bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sess *Session
		token := ""
		if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
			token = strings.TrimPrefix(a, "Bearer ")
		} else {
			token = r.URL.Query().Get("access_token")
		}
		if token != "" {
			var u Session
			var admin int
			err := s.stmtAuth.QueryRow(token).Scan(&u.UserID, &u.DeviceID, &admin)
			if err == nil {
				u.Admin = admin == 1
				sess = &u
			} else if needAuth {
				writeErr(w, &apiError{Status: 401, Code: "M_UNKNOWN_TOKEN", Msg: "unknown or expired access token",
					Extra: map[string]any{"soft_logout": false}})
				return
			}
		}
		if needAuth && sess == nil {
			writeErr(w, errf(401, "M_MISSING_TOKEN", "missing access token"))
			return
		}
		resp, err := h(w, r, sess)
		if err != nil {
			writeErr(w, err)
			return
		}
		if resp != nil {
			writeJSON(w, 200, resp)
		}
	}
}

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// Only trust X-Forwarded-For from a local proxy, otherwise clients
	// could fake it to get around the login limiter.
	if s.cfg.TrustProxy {
		if peer := net.ParseIP(host); peer != nil && (peer.IsLoopback() || peer.IsPrivate()) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				// the proxy appends the address it saw, so the last entry is the real client
				if c := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(c) != nil {
					return c
				}
			}
		}
	}
	return host
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authorization, Date")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	A := func(pattern string, h handler) { mux.HandleFunc(pattern, s.wrap(h, true)) }
	O := func(pattern string, h handler) { mux.HandleFunc(pattern, s.wrap(h, false)) }
	const c = "/_matrix/client/v3"
	const c1 = "/_matrix/client/v1"

	O("GET /{$}", s.hRoot)
	O("GET /.well-known/matrix/client", s.hWellKnown)
	if s.cfg.Federation {
		O("GET /.well-known/matrix/server", s.hWellKnownServer)
		O("GET /_matrix/key/v2/server", s.hServerKeys)
		O("GET /_matrix/key/v2/server/{keyId}", s.hServerKeys)
		O("GET /_matrix/federation/v1/version", s.hFedVersion)
		mux.HandleFunc("GET /_matrix/federation/v1/query/profile", s.wrapFed(s.hFedQueryProfile))
		mux.HandleFunc("GET /_matrix/federation/v1/query/directory", s.wrapFed(s.hFedQueryDirectory))
		F := func(pattern string, h fedHandler) { mux.HandleFunc(pattern, s.wrapFed(h)) }
		F("PUT /_matrix/federation/v1/send/{txnId}", s.hFedSend)
		F("GET /_matrix/federation/v1/event/{eventId}", s.hFedEvent)
		F("GET /_matrix/federation/v1/state/{roomId}", s.hFedState)
		F("GET /_matrix/federation/v1/state_ids/{roomId}", s.hFedStateIDs)
		F("GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}", s.hFedEventAuth)
		F("POST /_matrix/federation/v1/get_missing_events/{roomId}", s.hFedMissingEvents)
		F("GET /_matrix/federation/v1/backfill/{roomId}", s.hFedBackfill)
		F("GET /_matrix/federation/v1/make_join/{roomId}/{userId}", s.hFedMakeMembership("join"))
		F("PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}", s.hFedSendMembership("join"))
		F("GET /_matrix/federation/v1/make_leave/{roomId}/{userId}", s.hFedMakeMembership("leave"))
		F("PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}", s.hFedSendMembership("leave"))
		F("PUT /_matrix/federation/v2/invite/{roomId}/{eventId}", s.hFedInvite)
		F("GET /_matrix/federation/v1/user/devices/{userId}", s.hFedUserDevices)
		F("GET /_matrix/federation/v1/media/download/{mediaId}", s.hFedMediaDownload)
		F("GET /_matrix/federation/v1/media/thumbnail/{mediaId}", s.hFedMediaThumbnail)
		F("POST /_matrix/federation/v1/user/keys/query", s.hFedKeysQuery)
		F("POST /_matrix/federation/v1/user/keys/claim", s.hFedKeysClaim)
	}
	O("GET /_matrix/client/versions", s.hVersions)

	// accounts & sessions
	O("GET "+c+"/login", s.hLoginFlows)
	O("POST "+c+"/login", s.hLogin)
	O("POST "+c+"/register", s.hRegister)
	O("GET "+c+"/register/available", s.hRegisterAvailable)
	O("GET "+c1+"/register/m.login.registration_token/validity", s.hTokenValidity)
	A("POST "+c+"/logout", s.hLogout)
	A("POST "+c+"/logout/all", s.hLogoutAll)
	A("GET "+c+"/account/whoami", s.hWhoami)
	A("POST "+c+"/account/password", s.hChangePassword)
	A("GET "+c+"/account/3pid", func(http.ResponseWriter, *http.Request, *Session) (any, error) {
		return map[string]any{"threepids": []any{}}, nil
	})
	A("GET "+c+"/devices", s.hDevices)
	A("GET "+c+"/devices/{deviceId}", s.hDevice)
	A("PUT "+c+"/devices/{deviceId}", s.hUpdateDevice)
	A("DELETE "+c+"/devices/{deviceId}", s.hDeleteDevice)
	A("POST "+c+"/delete_devices", s.hDeleteDevices)
	A("GET "+c+"/capabilities", s.hCapabilities)

	// rooms
	A("POST "+c+"/createRoom", s.hCreateRoom)
	A("GET "+c+"/joined_rooms", s.hJoinedRooms)
	A("POST "+c+"/join/{roomIdOrAlias}", s.hJoin)
	A("POST "+c+"/rooms/{roomId}/join", s.hJoin)
	A("POST "+c+"/rooms/{roomId}/invite", s.hInvite)
	A("POST "+c+"/rooms/{roomId}/leave", s.hLeave)
	A("POST "+c+"/rooms/{roomId}/forget", func(http.ResponseWriter, *http.Request, *Session) (any, error) {
		return map[string]any{}, nil
	})
	A("POST "+c+"/rooms/{roomId}/kick", s.hKick)
	A("POST "+c+"/rooms/{roomId}/ban", s.hBan)
	A("POST "+c+"/rooms/{roomId}/unban", s.hUnban)
	A("PUT "+c+"/rooms/{roomId}/send/{type}/{txnId}", s.hSend)
	A("PUT "+c+"/rooms/{roomId}/state/{type}", s.hPutState)
	A("PUT "+c+"/rooms/{roomId}/state/{type}/{stateKey...}", s.hPutState)
	A("GET "+c+"/rooms/{roomId}/state", s.hGetAllState)
	A("GET "+c+"/rooms/{roomId}/state/{type}", s.hGetState)
	A("GET "+c+"/rooms/{roomId}/state/{type}/{stateKey...}", s.hGetState)
	A("GET "+c+"/rooms/{roomId}/event/{eventId}", s.hGetEvent)
	A("GET "+c+"/rooms/{roomId}/context/{eventId}", s.hContext)
	A("GET "+c+"/rooms/{roomId}/messages", s.hMessages)
	A("GET "+c+"/rooms/{roomId}/members", s.hMembers)
	A("GET "+c+"/rooms/{roomId}/joined_members", s.hJoinedMembers)
	A("PUT "+c+"/rooms/{roomId}/redact/{eventId}/{txnId}", s.hRedact)
	A("GET "+c+"/rooms/{roomId}/aliases", s.hRoomAliases)
	A("GET "+c1+"/rooms/{roomId}/relations/{eventId}", s.hRelations)
	A("GET "+c1+"/rooms/{roomId}/relations/{eventId}/{relType}", s.hRelations)
	A("GET "+c1+"/rooms/{roomId}/relations/{eventId}/{relType}/{eventType}", s.hRelations)
	A("GET "+c1+"/rooms/{roomId}/threads", s.hThreads)
	A("PUT "+c+"/rooms/{roomId}/typing/{userId}", s.hTyping)
	A("POST "+c+"/rooms/{roomId}/receipt/{receiptType}/{eventId}", s.hReceipt)
	A("POST "+c+"/rooms/{roomId}/read_markers", s.hReadMarkers)
	A("PUT "+c+"/directory/room/{alias}", s.hPutAlias)
	O("GET "+c+"/directory/room/{alias}", s.hGetAlias)
	A("DELETE "+c+"/directory/room/{alias}", s.hDeleteAlias)
	O("GET "+c+"/directory/list/room/{roomId}", s.hGetVisibility)
	A("PUT "+c+"/directory/list/room/{roomId}", s.hPutVisibility)
	O("GET "+c+"/publicRooms", s.hPublicRooms)
	A("POST "+c+"/publicRooms", s.hPublicRooms)

	// sync
	A("GET "+c+"/sync", s.hSync)
	A("POST "+c+"/user/{userId}/filter", s.hPostFilter)
	A("GET "+c+"/user/{userId}/filter/{filterId}", s.hGetFilter)

	// profile, account data, misc
	O("GET "+c+"/profile/{userId}", s.hProfile)
	O("GET "+c+"/profile/{userId}/{field}", s.hProfileField)
	A("PUT "+c+"/profile/{userId}/{field}", s.hSetProfileField)
	A("GET "+c+"/user/{userId}/account_data/{type}", s.hGetAccountData)
	A("PUT "+c+"/user/{userId}/account_data/{type}", s.hPutAccountData)
	A("GET "+c+"/user/{userId}/rooms/{roomId}/account_data/{type}", s.hGetAccountData)
	A("PUT "+c+"/user/{userId}/rooms/{roomId}/account_data/{type}", s.hPutAccountData)
	A("POST "+c+"/user_directory/search", s.hUserSearch)
	A("GET "+c+"/pushrules/{$}", s.hGetPushRules)
	A("GET "+c+"/pushrules/global/{$}", s.hGetPushRules)
	A("GET "+c+"/pushrules/global/{kind}/{ruleId}", s.hPushRule)
	A("PUT "+c+"/pushrules/global/{kind}/{ruleId}", s.hPushRule)
	A("DELETE "+c+"/pushrules/global/{kind}/{ruleId}", s.hPushRule)
	A("GET "+c+"/pushrules/global/{kind}/{ruleId}/{attr}", s.hPushRule)
	A("PUT "+c+"/pushrules/global/{kind}/{ruleId}/{attr}", s.hPushRule)
	A("GET "+c+"/pushers", s.hGetPushers)
	A("POST "+c+"/pushers/set", s.hSetPusher)
	A("GET "+c+"/notifications", func(http.ResponseWriter, *http.Request, *Session) (any, error) {
		return map[string]any{"notifications": []any{}}, nil
	})
	A("GET "+c+"/presence/{userId}/status", func(http.ResponseWriter, *http.Request, *Session) (any, error) {
		return map[string]any{"presence": "offline"}, nil
	})
	A("PUT "+c+"/presence/{userId}/status", func(http.ResponseWriter, *http.Request, *Session) (any, error) {
		return map[string]any{}, nil
	})
	A("GET "+c+"/voip/turnServer", func(http.ResponseWriter, *http.Request, *Session) (any, error) {
		return map[string]any{}, nil
	})
	A("GET "+c+"/thirdparty/protocols", func(http.ResponseWriter, *http.Request, *Session) (any, error) {
		return map[string]any{}, nil
	})

	// end-to-end encryption
	A("POST "+c+"/keys/upload", s.hKeysUpload)
	A("POST "+c+"/keys/query", s.hKeysQuery)
	A("POST "+c+"/keys/claim", s.hKeysClaim)
	A("GET "+c+"/keys/changes", s.hKeysChanges)
	A("POST "+c+"/keys/device_signing/upload", s.hCrossSigningUpload)
	A("POST "+c+"/keys/signatures/upload", s.hSignaturesUpload)
	A("PUT "+c+"/sendToDevice/{eventType}/{txnId}", s.hSendToDevice)
	A("GET "+c+"/room_keys/version", s.hBackupVersion)
	A("POST "+c+"/room_keys/version", s.hBackupCreate)
	A("GET "+c+"/room_keys/version/{version}", s.hBackupVersion)
	A("PUT "+c+"/room_keys/version/{version}", s.hBackupUpdate)
	A("DELETE "+c+"/room_keys/version/{version}", s.hBackupDelete)
	for _, p := range []string{"/room_keys/keys", "/room_keys/keys/{roomId}", "/room_keys/keys/{roomId}/{sessionId}"} {
		A("GET "+c+p, s.hBackupKeys)
		A("PUT "+c+p, s.hBackupKeys)
		A("DELETE "+c+p, s.hBackupKeys)
	}

	// media
	A("POST /_matrix/media/v3/upload", s.hUpload)
	O("GET /_matrix/media/v3/config", s.hMediaConfig)
	A("GET "+c1+"/media/config", s.hMediaConfig)
	O("GET /_matrix/media/v3/download/{serverName}/{mediaId}", s.hDownload)
	O("GET /_matrix/media/v3/download/{serverName}/{mediaId}/{fileName}", s.hDownload)
	A("GET "+c1+"/media/download/{serverName}/{mediaId}", s.hDownload)
	A("GET "+c1+"/media/download/{serverName}/{mediaId}/{fileName}", s.hDownload)
	O("GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}", s.hThumbnail)
	A("GET "+c1+"/media/thumbnail/{serverName}/{mediaId}", s.hThumbnail)
	empty := func(http.ResponseWriter, *http.Request, *Session) (any, error) { return map[string]any{}, nil }
	A("GET /_matrix/media/v3/preview_url", empty)
	A("GET "+c1+"/media/preview_url", empty)

	O("/", func(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
		return nil, errf(404, "M_UNRECOGNIZED", "unrecognized request")
	})
	return cors(mux)
}
