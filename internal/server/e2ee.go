package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// E2EE: we only store public keys, relay to-device messages and keep the
// (encrypted) key backup. No plaintext here.

func (s *Server) otkCounts(uid, device string) map[string]int {
	out := map[string]int{}
	rows, err := s.db.Query("SELECT algorithm, COUNT(*) FROM one_time_keys WHERE user_id = ? AND device_id = ? GROUP BY algorithm", uid, device)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var a string
		var n int
		rows.Scan(&a, &n)
		out[a] = n
	}
	return out
}

func (s *Server) hKeysUpload(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		DeviceKeys   map[string]any             `json:"device_keys"`
		OneTimeKeys  map[string]json.RawMessage `json:"one_time_keys"`
		FallbackKeys map[string]json.RawMessage `json:"fallback_keys"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if req.DeviceKeys != nil {
		if req.DeviceKeys["user_id"] != sess.UserID || req.DeviceKeys["device_id"] != sess.DeviceID {
			return nil, errInvalidParam("device_keys user_id/device_id do not match this device")
		}
	}
	err := s.write(func(tx *sql.Tx) error {
		if req.DeviceKeys != nil {
			b, _ := json.Marshal(req.DeviceKeys)
			var old string
			tx.QueryRow("SELECT keys FROM device_keys WHERE user_id = ? AND device_id = ?", sess.UserID, sess.DeviceID).Scan(&old)
			if old != string(b) {
				if _, err := tx.Exec("INSERT OR REPLACE INTO device_keys (user_id, device_id, keys) VALUES (?,?,?)",
					sess.UserID, sess.DeviceID, string(b)); err != nil {
					return err
				}
				if err := s.markDeviceListChange(tx, sess.UserID); err != nil {
					return err
				}
			}
		}
		for kid, key := range req.OneTimeKeys {
			algo, _, _ := strings.Cut(kid, ":")
			if _, err := tx.Exec(`INSERT OR IGNORE INTO one_time_keys (user_id, device_id, key_id, algorithm, key)
				VALUES (?,?,?,?,?)`, sess.UserID, sess.DeviceID, kid, algo, string(key)); err != nil {
				return err
			}
		}
		for kid, key := range req.FallbackKeys {
			algo, _, _ := strings.Cut(kid, ":")
			if _, err := tx.Exec(`INSERT OR REPLACE INTO fallback_keys (user_id, device_id, algorithm, key_id, key, used)
				VALUES (?,?,?,?,?,0)`, sess.UserID, sess.DeviceID, algo, kid, string(key)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"one_time_key_counts": s.otkCounts(sess.UserID, sess.DeviceID)}, nil
}

func (s *Server) crossSigningKey(uid, typ string) json.RawMessage {
	var k string
	if s.db.QueryRow("SELECT keys FROM cross_signing WHERE user_id = ? AND key_type = ?", uid, typ).Scan(&k) != nil {
		return nil
	}
	return json.RawMessage(k)
}

func (s *Server) hKeysQuery(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		DeviceKeys map[string][]string `json:"device_keys"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	devKeys := map[string]any{}
	master, selfSigning, userSigning := map[string]any{}, map[string]any{}, map[string]any{}
	failures := map[string]any{}
	remote := map[string][]string{}
	for uid, want := range req.DeviceKeys {
		if !s.isLocal(uid) {
			if s.cfg.Federation {
				remote[uid] = want
			} else {
				failures[domainOf(uid)] = map[string]any{"error": "federation is disabled on this server"}
			}
			continue
		}
		wantSet := map[string]bool{}
		for _, d := range want {
			wantSet[d] = true
		}
		rows, err := s.db.Query(`SELECT k.device_id, k.keys, d.display_name FROM device_keys k
			LEFT JOIN devices d ON d.user_id = k.user_id AND d.device_id = k.device_id WHERE k.user_id = ?`, uid)
		if err != nil {
			return nil, err
		}
		devs := map[string]any{}
		for rows.Next() {
			var id, keys string
			var name sql.NullString
			rows.Scan(&id, &keys, &name)
			if len(wantSet) > 0 && !wantSet[id] {
				continue
			}
			var obj map[string]any
			if json.Unmarshal([]byte(keys), &obj) != nil || obj == nil {
				continue // corrupt row: skip rather than crash
			}
			if name.Valid {
				obj["unsigned"] = map[string]any{"device_display_name": name.String}
			}
			devs[id] = obj
		}
		rows.Close()
		devKeys[uid] = devs
		if k := s.crossSigningKey(uid, "master"); k != nil {
			master[uid] = filterSignatures(k, uid, sess.UserID)
		}
		if k := s.crossSigningKey(uid, "self_signing"); k != nil {
			selfSigning[uid] = k
		}
		if uid == sess.UserID {
			if k := s.crossSigningKey(uid, "user_signing"); k != nil {
				userSigning[uid] = k
			}
		}
	}
	if len(remote) > 0 {
		s.queryRemoteKeys(r.Context(), sess.UserID, remote, devKeys, master, selfSigning, failures)
	}
	return map[string]any{"device_keys": devKeys, "master_keys": master, "self_signing_keys": selfSigning,
		"user_signing_keys": userSigning, "failures": failures}, nil
}

func (s *Server) hKeysClaim(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		OneTimeKeys map[string]map[string]string `json:"one_time_keys"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	local, remote := map[string]map[string]string{}, map[string]map[string]string{}
	for uid, devs := range req.OneTimeKeys {
		if s.isLocal(uid) {
			local[uid] = devs
		} else if s.cfg.Federation {
			remote[uid] = devs
		}
	}
	out, err := s.claimLocalKeys(local)
	if err != nil {
		return nil, err
	}
	failures := map[string]any{}
	if len(remote) > 0 {
		s.claimRemoteKeys(r.Context(), remote, out, failures)
	}
	return map[string]any{"one_time_keys": out, "failures": failures}, nil
}

func (s *Server) hKeysChanges(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	from, ok1 := parseToken(r.URL.Query().Get("from"))
	to, ok2 := parseToken(r.URL.Query().Get("to"))
	if !ok1 {
		return nil, errInvalidParam("invalid from token")
	}
	if !ok2 {
		to = s.committed.Load()
	}
	changed, left := s.deviceListChanges(sess.UserID, from, to)
	return map[string]any{"changed": changed, "left": left}, nil
}

func (s *Server) hCrossSigningUpload(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		Master      json.RawMessage `json:"master_key"`
		SelfSigning json.RawMessage `json:"self_signing_key"`
		UserSigning json.RawMessage `json:"user_signing_key"`
		Auth        *uiaAuth        `json:"auth"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	// Replacing existing cross-signing keys needs the password; the first upload doesn't.
	if s.crossSigningKey(sess.UserID, "master") != nil {
		if err := s.requirePassword(r, sess.UserID, req.Auth); err != nil {
			return nil, err
		}
	}
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		for typ, k := range map[string]json.RawMessage{"master": req.Master, "self_signing": req.SelfSigning, "user_signing": req.UserSigning} {
			if len(k) == 0 || string(k) == "null" {
				continue
			}
			var chk struct {
				UserID string `json:"user_id"`
			}
			json.Unmarshal(k, &chk)
			if chk.UserID != sess.UserID {
				return errInvalidParam("cross-signing key user_id mismatch")
			}
			if _, err := tx.Exec("INSERT OR REPLACE INTO cross_signing (user_id, key_type, keys) VALUES (?,?,?)",
				sess.UserID, typ, string(k)); err != nil {
				return err
			}
		}
		if err := s.announceSigningKeys(tx, sess.UserID); err != nil {
			return err
		}
		return s.markDeviceListChange(tx, sess.UserID)
	})
}

// ownSignatures returns obj["signatures"][signer], or nil.
func ownSignatures(obj map[string]any, signer string) map[string]any {
	all, _ := obj["signatures"].(map[string]any)
	mine, _ := all[signer].(map[string]any)
	out := map[string]any{}
	for kid, sig := range mine {
		if str, ok := sig.(string); ok && str != "" && len(kid) < 256 {
			out[kid] = str
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// mergeSignatures adds signer's signatures, leaving everyone else's alone.
func mergeSignatures(stored, signer string, sigs map[string]any) (string, bool) {
	var obj map[string]any
	if json.Unmarshal([]byte(stored), &obj) != nil || obj == nil {
		return "", false
	}
	all, _ := obj["signatures"].(map[string]any)
	if all == nil {
		all = map[string]any{}
	}
	mine, _ := all[signer].(map[string]any)
	if mine == nil {
		mine = map[string]any{}
	}
	for kid, sig := range sigs {
		mine[kid] = sig
	}
	all[signer] = mine
	obj["signatures"] = all
	b, err := json.Marshal(obj)
	return string(b), err == nil
}

// filterSignatures keeps only signatures by keep, so a master key doesn't
// show who else verified that user.
func filterSignatures(raw json.RawMessage, keep ...string) json.RawMessage {
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return raw
	}
	all, _ := obj["signatures"].(map[string]any)
	if all == nil {
		return raw
	}
	out := map[string]any{}
	for _, k := range keep {
		if v, ok := all[k]; ok {
			out[k] = v
		}
	}
	obj["signatures"] = out
	b, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return b
}

// crossSigningKeyByID finds uid's cross-signing key whose public key is keyID.
func crossSigningKeyByID(q querier, uid, keyID string) (typ, stored string, found bool) {
	rows, err := q.Query("SELECT key_type, keys FROM cross_signing WHERE user_id = ?", uid)
	if err != nil {
		return "", "", false
	}
	defer rows.Close()
	for rows.Next() {
		var t, k string
		if rows.Scan(&t, &k) != nil {
			continue
		}
		var parsed struct {
			Keys map[string]string `json:"keys"`
		}
		json.Unmarshal([]byte(k), &parsed)
		if _, ok := parsed.Keys["ed25519:"+keyID]; ok {
			return t, k, true
		}
	}
	return "", "", false
}

// hSignaturesUpload only takes the uploader's own signatures. Your own keys:
// anything. Someone else's: only their master key.
func (s *Server) hSignaturesUpload(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req map[string]map[string]map[string]any
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	failures := map[string]any{}
	fail := func(uid, keyID, code, msg string) {
		m, _ := failures[uid].(map[string]any)
		if m == nil {
			m = map[string]any{}
			failures[uid] = m
		}
		m[keyID] = map[string]any{"errcode": code, "error": msg}
	}
	err := s.write(func(tx *sql.Tx) error {
		changed := false
		for uid, keys := range req {
			for keyID, obj := range keys {
				sigs := ownSignatures(obj, sess.UserID)
				if sigs == nil {
					fail(uid, keyID, "M_INVALID_SIGNATURE", "no signature by the uploading user")
					continue
				}
				var stored string
				if uid == sess.UserID && tx.QueryRow("SELECT keys FROM device_keys WHERE user_id = ? AND device_id = ?",
					uid, keyID).Scan(&stored) == nil {
					merged, ok := mergeSignatures(stored, sess.UserID, sigs)
					if !ok {
						fail(uid, keyID, "M_INVALID_PARAM", "stored key is not valid JSON")
						continue
					}
					if _, err := tx.Exec("UPDATE device_keys SET keys = ? WHERE user_id = ? AND device_id = ?",
						merged, uid, keyID); err != nil {
						return err
					}
					changed = true
					continue
				}
				if !s.isLocal(uid) {
					// remote user: keep the signature locally, only the signer sees it
					b, _ := json.Marshal(sigs)
					if _, err := tx.Exec(`INSERT OR REPLACE INTO remote_signatures (user_id, key_id, signer, sigs) VALUES (?,?,?,?)`,
						uid, "ed25519:"+keyID, sess.UserID, string(b)); err != nil {
						return err
					}
					continue
				}
				typ, stored, found := crossSigningKeyByID(tx, uid, keyID)
				if !found {
					fail(uid, keyID, "M_NOT_FOUND", "unknown key")
					continue
				}
				if uid != sess.UserID && typ != "master" {
					fail(uid, keyID, "M_FORBIDDEN", "you may only sign another user's master key")
					continue
				}
				merged, ok := mergeSignatures(stored, sess.UserID, sigs)
				if !ok {
					fail(uid, keyID, "M_INVALID_PARAM", "stored key is not valid JSON")
					continue
				}
				if _, err := tx.Exec("UPDATE cross_signing SET keys = ? WHERE user_id = ? AND key_type = ?",
					merged, uid, typ); err != nil {
					return err
				}
				changed = true
			}
		}
		if !changed {
			return nil
		}
		// only your own keys change what others see
		return s.markDeviceListChange(tx, sess.UserID)
	})
	return map[string]any{"failures": failures}, err
}

func (s *Server) hSendToDevice(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		Messages map[string]map[string]json.RawMessage `json:"messages"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	typ, txn := r.PathValue("eventType"), "td:"+r.PathValue("txnId")
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		if checkTxn(tx, sess, txn) != "" {
			return nil
		}
		if err := s.queueToDevice(tx, sess.UserID, typ, req.Messages); err != nil {
			return err
		}
		for uid, devs := range req.Messages {
			if !s.isLocal(uid) {
				continue
			}
			for dev, content := range devs {
				if len(content) == 0 || content[0] != '{' {
					continue // to-device content must be an object
				}
				// skip unknown devices, nobody would ever fetch it
				var targets []string
				var x int
				if dev != "*" && tx.QueryRow("SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?", uid, dev).Scan(&x) == nil {
					targets = []string{dev}
				}
				if dev == "*" {
					rows, err := tx.Query("SELECT device_id FROM devices WHERE user_id = ?", uid)
					if err != nil {
						return err
					}
					for rows.Next() {
						var d string
						rows.Scan(&d)
						targets = append(targets, d)
					}
					rows.Close()
				}
				for _, d := range targets {
					if _, err := tx.Exec("INSERT INTO to_device (stream, user_id, device_id, sender, type, content) VALUES (?,?,?,?,?,?)",
						s.nextFor(change{user: uid}), uid, d, sess.UserID, typ, string(content)); err != nil {
						return err
					}
				}
			}
		}
		return saveTxn(tx, sess, txn, "-")
	})
}

// ---- server-side key backup (the data is encrypted by the client) ----

func (s *Server) currentBackup(uid string) (int64, error) {
	var v int64
	err := s.db.QueryRow("SELECT version FROM backup_versions WHERE user_id = ? AND deleted = 0 ORDER BY version DESC LIMIT 1", uid).Scan(&v)
	return v, err
}

func (s *Server) hBackupCreate(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var req struct {
		Algorithm string          `json:"algorithm"`
		AuthData  json.RawMessage `json:"auth_data"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	if req.Algorithm == "" || len(req.AuthData) == 0 {
		return nil, errBadJSON("algorithm and auth_data are required")
	}
	var v int64
	err := s.write(func(tx *sql.Tx) error {
		res, err := tx.Exec("INSERT INTO backup_versions (user_id, algorithm, auth_data) VALUES (?,?,?)", sess.UserID, req.Algorithm, string(req.AuthData))
		if err != nil {
			return err
		}
		v, err = res.LastInsertId()
		return err
	})
	return map[string]any{"version": strconv.FormatInt(v, 10)}, err
}

func (s *Server) backupInfo(uid string, v int64) (map[string]any, error) {
	var algo, auth string
	var etag int64
	if s.db.QueryRow("SELECT algorithm, auth_data, etag FROM backup_versions WHERE user_id = ? AND version = ? AND deleted = 0",
		uid, v).Scan(&algo, &auth, &etag) != nil {
		return nil, errNotFound("unknown backup version")
	}
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM backup_keys WHERE user_id = ? AND version = ?", uid, v).Scan(&count)
	return map[string]any{"algorithm": algo, "auth_data": json.RawMessage(auth), "version": strconv.FormatInt(v, 10),
		"count": count, "etag": strconv.FormatInt(etag, 10)}, nil
}

func (s *Server) hBackupVersion(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	var v int64
	if p := r.PathValue("version"); p != "" {
		v, _ = strconv.ParseInt(p, 10, 64)
	} else {
		var err error
		if v, err = s.currentBackup(sess.UserID); err != nil {
			return nil, errNotFound("no current backup version")
		}
	}
	return s.backupInfo(sess.UserID, v)
}

func (s *Server) hBackupUpdate(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	v, _ := strconv.ParseInt(r.PathValue("version"), 10, 64)
	var req struct {
		Algorithm string          `json:"algorithm"`
		AuthData  json.RawMessage `json:"auth_data"`
	}
	if err := readJSON(r, &req); err != nil {
		return nil, err
	}
	var n int64
	err := s.write(func(tx *sql.Tx) error {
		res, err := tx.Exec("UPDATE backup_versions SET auth_data = ? WHERE user_id = ? AND version = ? AND deleted = 0 AND algorithm = ?",
			string(req.AuthData), sess.UserID, v, req.Algorithm)
		if err != nil {
			return err
		}
		n, _ = res.RowsAffected()
		return nil
	})
	if err == nil && n == 0 {
		return nil, errNotFound("unknown backup version")
	}
	return map[string]any{}, err
}

func (s *Server) hBackupDelete(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	v, _ := strconv.ParseInt(r.PathValue("version"), 10, 64)
	return map[string]any{}, s.write(func(tx *sql.Tx) error {
		if _, err := tx.Exec("UPDATE backup_versions SET deleted = 1 WHERE user_id = ? AND version = ?", sess.UserID, v); err != nil {
			return err
		}
		_, err := tx.Exec("DELETE FROM backup_keys WHERE user_id = ? AND version = ?", sess.UserID, v)
		return err
	})
}

type keyBackupData struct {
	FirstMessageIndex int64 `json:"first_message_index"`
	ForwardedCount    int64 `json:"forwarded_count"`
	IsVerified        bool  `json:"is_verified"`
}

// betterKey reports whether the new session key should replace the old one.
func betterKey(oldRaw, newRaw string) bool {
	var o, n keyBackupData
	json.Unmarshal([]byte(oldRaw), &o)
	json.Unmarshal([]byte(newRaw), &n)
	if o.IsVerified != n.IsVerified {
		return n.IsVerified
	}
	if o.FirstMessageIndex != n.FirstMessageIndex {
		return n.FirstMessageIndex < o.FirstMessageIndex
	}
	return n.ForwardedCount < o.ForwardedCount
}

func (s *Server) hBackupKeys(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	uid := sess.UserID
	v, err := strconv.ParseInt(r.URL.Query().Get("version"), 10, 64)
	if err != nil {
		return nil, errInvalidParam("version is required")
	}
	roomID, sessionID := r.PathValue("roomId"), r.PathValue("sessionId")
	if _, err := s.backupInfo(uid, v); err != nil {
		return nil, err
	}
	where := "user_id = ? AND version = ?"
	args := []any{uid, v}
	if roomID != "" {
		where += " AND room_id = ?"
		args = append(args, roomID)
	}
	if sessionID != "" {
		where += " AND session_id = ?"
		args = append(args, sessionID)
	}

	switch r.Method {
	case http.MethodGet:
		rows, err := s.db.Query("SELECT room_id, session_id, data FROM backup_keys WHERE "+where, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		rooms := map[string]map[string]json.RawMessage{}
		for rows.Next() {
			var rid, sid, data string
			rows.Scan(&rid, &sid, &data)
			if rooms[rid] == nil {
				rooms[rid] = map[string]json.RawMessage{}
			}
			rooms[rid][sid] = json.RawMessage(data)
		}
		if sessionID != "" {
			d, ok := rooms[roomID][sessionID]
			if !ok {
				return nil, errNotFound("key not found")
			}
			return d, nil
		}
		if roomID != "" {
			sessions := rooms[roomID]
			if sessions == nil {
				sessions = map[string]json.RawMessage{}
			}
			return map[string]any{"sessions": sessions}, nil
		}
		out := map[string]any{}
		for rid, ss := range rooms {
			out[rid] = map[string]any{"sessions": ss}
		}
		return map[string]any{"rooms": out}, nil

	case http.MethodDelete:
		err := s.write(func(tx *sql.Tx) error {
			if _, err := tx.Exec("DELETE FROM backup_keys WHERE "+where, args...); err != nil {
				return err
			}
			_, err := tx.Exec("UPDATE backup_versions SET etag = etag + 1 WHERE version = ?", v)
			return err
		})
		if err != nil {
			return nil, err
		}
	default: // PUT
		if cur, _ := s.currentBackup(uid); cur != v {
			return nil, &apiError{Status: 403, Code: "M_WRONG_ROOM_KEYS_VERSION", Msg: "not the current backup version",
				Extra: map[string]any{"current_version": strconv.FormatInt(cur, 10)}}
		}
		// normalise all three request shapes into room -> session -> data
		in := map[string]map[string]json.RawMessage{}
		switch {
		case sessionID != "":
			var d json.RawMessage
			if err := readJSON(r, &d); err != nil {
				return nil, err
			}
			in[roomID] = map[string]json.RawMessage{sessionID: d}
		case roomID != "":
			var body struct {
				Sessions map[string]json.RawMessage `json:"sessions"`
			}
			if err := readJSON(r, &body); err != nil {
				return nil, err
			}
			in[roomID] = body.Sessions
		default:
			var body struct {
				Rooms map[string]struct {
					Sessions map[string]json.RawMessage `json:"sessions"`
				} `json:"rooms"`
			}
			if err := readJSON(r, &body); err != nil {
				return nil, err
			}
			for rid, rr := range body.Rooms {
				in[rid] = rr.Sessions
			}
		}
		err := s.write(func(tx *sql.Tx) error {
			for rid, ss := range in {
				for sid, d := range ss {
					var old string
					if tx.QueryRow("SELECT data FROM backup_keys WHERE user_id = ? AND version = ? AND room_id = ? AND session_id = ?",
						uid, v, rid, sid).Scan(&old) == nil && !betterKey(old, string(d)) {
						continue
					}
					if _, err := tx.Exec("INSERT OR REPLACE INTO backup_keys (user_id, version, room_id, session_id, data) VALUES (?,?,?,?,?)",
						uid, v, rid, sid, string(d)); err != nil {
						return err
					}
				}
			}
			_, err := tx.Exec("UPDATE backup_versions SET etag = etag + 1 WHERE version = ?", v)
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	info, err := s.backupInfo(uid, v)
	if err != nil {
		return nil, err
	}
	return map[string]any{"etag": info["etag"], "count": info["count"]}, nil
}
