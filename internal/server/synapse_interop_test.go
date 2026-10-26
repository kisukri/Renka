package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSynapseInterop shares rooms with a real Synapse in both directions.
// It needs a running Synapse with TLS federation (see test/synapse_interop.md):
//
//	RENKA_SYNAPSE=http://127.0.0.1:8048 RENKA_SYNAPSE_NAME=127.0.0.1:8448 \
//	RENKA_TLS_DIR=/path/with/ca.crt,renka.crt,renka.key go test -run SynapseInterop -v .
func TestSynapseInterop(t *testing.T) {
	synURL, synName, tlsDir := os.Getenv("RENKA_SYNAPSE"), os.Getenv("RENKA_SYNAPSE_NAME"), os.Getenv("RENKA_TLS_DIR")
	if synURL == "" {
		t.Skip("set RENKA_SYNAPSE to run against a real Synapse")
	}
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(filepath.Join(tlsDir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(ca)
	cert, err := tls.LoadX509KeyPair(filepath.Join(tlsDir, "renka.crt"), filepath.Join(tlsDir, "renka.key"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:8449")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := &Config{ServerName: "127.0.0.1:8449", PublicBaseURL: "https://127.0.0.1:8449",
		Database: filepath.Join(dir, "t.db"), MediaDir: filepath.Join(dir, "m"), MaxUploadBytes: 1 << 20,
		Registration: true, Federation: true, FederationAllowPrivate: true}
	s, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	tr := newFedTransport(true, &tls.Config{RootCAs: pool})
	s.fedClient = &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	h := s.routes()
	hs := httptest.NewUnstartedServer(h)
	hs.Listener.Close()
	hs.Listener = ln
	hs.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	hs.StartTLS()
	defer hs.Close()

	aid, at := addUser(t, s, "alice")
	alice := fedUser{s, h, aid, at}
	sam := synapseUser(t, synURL, "sam"+strings.ToLower(randString(6)))

	for _, ver := range []string{"10", "11"} {
		t.Run("synapse room v"+ver, func(t *testing.T) {
			_, res := sam.call(t, "POST", "/createRoom", map[string]any{"preset": "public_chat", "room_version": ver, "name": "syn " + ver})
			room := res["room_id"].(string)
			m0 := sam.send(t, room, "before alice")
			if code, res := alice.do(t, "POST", "/_matrix/client/v3/join/"+room+"?server_name="+url.QueryEscape(synName), map[string]any{}); code != 200 {
				t.Fatalf("renka joining a Synapse room: %d %v", code, res)
			}
			m1 := sam.send(t, room, "hello renka")
			waitFor(t, "Synapse message on renka", func() bool { return hasEvent(s, m1) })
			ma := alice.send(t, room, "hello synapse")
			waitFor(t, "renka message on Synapse", func() bool { return sam.hasEvent(room, ma) })
			sam.call(t, "PUT", "/rooms/"+room+"/state/m.room.topic/", map[string]any{"topic": "from synapse"})
			waitFor(t, "topic on renka", func() bool { return topicOf(s, room) == "from synapse" })
			compareWithSynapse(t, s, sam, room)
			// history from before alice joined, backfilled from Synapse
			_, hist := alice.do(t, "GET", "/_matrix/client/v3/rooms/"+room+"/messages?dir=b&limit=50", nil)
			if !strings.Contains(mustJSON(hist["chunk"]), m0) {
				t.Errorf("message from before the join not backfilled from Synapse")
			}
			if _, res := sam.call(t, "POST", "/rooms/"+room+"/kick", map[string]any{"user_id": aid}); res["errcode"] != nil {
				t.Fatal(res)
			}
			waitFor(t, "kick on renka", func() bool { m, _ := getMembership(s.db, room, aid); return m == "leave" })
		})
		t.Run("fork with synapse v"+ver, func(t *testing.T) {
			_, res := sam.call(t, "POST", "/createRoom", map[string]any{"preset": "public_chat", "room_version": ver,
				"power_level_content_override": map[string]any{"users": map[string]any{sam.id: 100, aid: 50}}})
			room := res["room_id"].(string)
			if code, res := alice.do(t, "POST", "/_matrix/client/v3/join/"+room+"?server_name="+url.QueryEscape(synName), map[string]any{}); code != 200 {
				t.Fatalf("join: %d %v", code, res)
			}
			// cut the link both ways, then change things on each side
			s.fedRefuseTxns.Store(true)
			pauseTo(s, synName)
			sam.call(t, "PUT", "/rooms/"+url.PathEscape(room)+"/state/m.room.power_levels/", map[string]any{"users": map[string]any{sam.id: 100}})
			if code, res := alice.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/state/m.room.topic/", map[string]any{"topic": "alice in the fork"}); code != 200 {
				t.Fatalf("alice's topic: %d %v", code, res)
			}
			ms := sam.send(t, room, "during the split")
			s.fedRefuseTxns.Store(false)
			resumeTo(s, synName)
			waitFor(t, "Synapse's events on renka", func() bool { return hasEvent(s, ms) })
			// both resolve the fork the same way: the demotion wins
			compareWithSynapse(t, s, sam, room)
			if topicOf(s, room) == "alice in the fork" {
				t.Error("alice's topic survived her demotion")
			}
		})
		t.Run("encryption with synapse v"+ver, func(t *testing.T) {
			_, res := sam.call(t, "POST", "/createRoom", map[string]any{"preset": "public_chat", "room_version": ver})
			room := res["room_id"].(string)
			if code, res := alice.do(t, "POST", "/_matrix/client/v3/join/"+room+"?server_name="+url.QueryEscape(synName), map[string]any{}); code != 200 {
				t.Fatalf("join: %d %v", code, res)
			}
			adev := deviceOf(s, aid)
			uploadKeys(t, alice, adev)
			otk := func(n string) map[string]any {
				return map[string]any{"key": n, "signatures": map[string]any{sam.id: map[string]any{"ed25519:" + sam.device: "sig"}}}
			}
			sam.call(t, "POST", "/keys/upload", map[string]any{
				"device_keys": map[string]any{"user_id": sam.id, "device_id": sam.device, "algorithms": []string{"m.olm.v1.curve25519-aes-sha2"},
					"keys":       map[string]any{"curve25519:" + sam.device: "samcurve" + ver, "ed25519:" + sam.device: "samed" + ver},
					"signatures": map[string]any{sam.id: map[string]any{"ed25519:" + sam.device: "sig"}}},
				"one_time_keys": map[string]any{"signed_curve25519:S" + ver + "A": otk("s1"), "signed_curve25519:S" + ver + "B": otk("s2")}})

			// renka asks Synapse
			_, q := alice.do(t, "POST", "/_matrix/client/v3/keys/query", map[string]any{"device_keys": map[string]any{sam.id: []string{}}})
			if d, _ := q["device_keys"].(map[string]any)[sam.id].(map[string]any); d[sam.device] == nil {
				t.Fatalf("Synapse user's keys via renka: %v", q)
			}
			_, c := alice.do(t, "POST", "/_matrix/client/v3/keys/claim", map[string]any{"one_time_keys": map[string]any{sam.id: map[string]any{sam.device: "signed_curve25519"}}})
			if got, _ := c["one_time_keys"].(map[string]any)[sam.id].(map[string]any); len(got) != 1 {
				t.Fatalf("claiming a Synapse user's key: %v", c)
			}
			// Synapse asks renka
			_, q = sam.call(t, "POST", "/keys/query", map[string]any{"device_keys": map[string]any{aid: []string{}}})
			if d, _ := q["device_keys"].(map[string]any)[aid].(map[string]any); d[adev] == nil {
				t.Fatalf("renka user's keys via Synapse: %v", q)
			}
			_, c = sam.call(t, "POST", "/keys/claim", map[string]any{"one_time_keys": map[string]any{aid: map[string]any{adev: "signed_curve25519"}}})
			if got, _ := c["one_time_keys"].(map[string]any)[aid].(map[string]any); len(got) != 1 {
				t.Fatalf("Synapse claiming a renka user's key: %v", c)
			}
			// to-device both ways
			alice.do(t, "PUT", "/_matrix/client/v3/sendToDevice/m.room.encrypted/r"+ver, map[string]any{
				"messages": map[string]any{sam.id: map[string]any{sam.device: map[string]any{"ciphertext": "to-sam-" + ver}}}})
			waitFor(t, "to-device on Synapse", func() bool {
				f := url.QueryEscape(`{"room":{"timeline":{"limit":` + strconv.Itoa(1+int(time.Now().UnixNano()%1000)) + `}}}`)
				_, sy := sam.call(t, "GET", "/sync?timeout=0&filter="+f, nil)
				td, _ := sy["to_device"].(map[string]any)
				evs, _ := td["events"].([]any)
				for _, e := range evs {
					if c, _ := e.(map[string]any)["content"].(map[string]any); c["ciphertext"] == "to-sam-"+ver {
						return true
					}
				}
				return false
			})
			sam.call(t, "PUT", "/sendToDevice/m.room.encrypted/s"+ver, map[string]any{
				"messages": map[string]any{aid: map[string]any{adev: map[string]any{"ciphertext": "to-alice-" + ver}}}})
			waitFor(t, "to-device on renka", func() bool {
				var n int
				s.db.QueryRow("SELECT COUNT(*) FROM to_device WHERE user_id = ? AND content LIKE ?", aid, "%to-alice-"+ver+"%").Scan(&n)
				return n == 1
			})
			// Synapse user's devices change: renka's client is told
			_, sy := alice.do(t, "GET", "/_matrix/client/v3/sync", nil)
			since := sy["next_batch"].(string)
			sam.call(t, "PUT", "/devices/"+url.PathEscape(sam.device), map[string]any{"display_name": "renamed"})
			sam.call(t, "POST", "/keys/upload", map[string]any{
				"device_keys": map[string]any{"user_id": sam.id, "device_id": sam.device, "algorithms": []string{"m.olm.v1.curve25519-aes-sha2"},
					"keys":       map[string]any{"curve25519:" + sam.device: "samcurve2-" + ver, "ed25519:" + sam.device: "samed" + ver},
					"signatures": map[string]any{sam.id: map[string]any{"ed25519:" + sam.device: "sig2"}}}})
			// and the other way: Synapse re-fetches the list from renka
			f0 := url.QueryEscape(`{"room":{"timeline":{"limit":7}}}`)
			_, sy0 := sam.call(t, "GET", "/sync?timeout=0&filter="+f0, nil)
			samSince := sy0["next_batch"].(string)
			alice.do(t, "POST", "/_matrix/client/v3/keys/upload", map[string]any{"device_keys": map[string]any{"user_id": aid, "device_id": adev,
				"algorithms": []string{"m.olm.v1.curve25519-aes-sha2"}, "keys": map[string]any{"curve25519:" + adev: "alice-new-" + ver, "ed25519:" + adev: "ed-" + adev},
				"signatures": map[string]any{aid: map[string]any{"ed25519:" + adev: "sig3"}}}})
			waitFor(t, "device list change from renka", func() bool {
				_, sy := sam.call(t, "GET", "/sync?timeout=0&since="+url.QueryEscape(samSince)+"&filter="+f0, nil)
				dl, _ := sy["device_lists"].(map[string]any)
				ch, _ := dl["changed"].([]any)
				for _, u := range ch {
					if u == aid {
						return true
					}
				}
				return false
			})
			waitFor(t, "Synapse serving renka user's new keys", func() bool {
				_, q := sam.call(t, "POST", "/keys/query", map[string]any{"device_keys": map[string]any{aid: []string{}}})
				d, _ := q["device_keys"].(map[string]any)[aid].(map[string]any)
				k, _ := d[adev].(map[string]any)
				keys, _ := k["keys"].(map[string]any)
				return keys["curve25519:"+adev] == "alice-new-"+ver
			})
			waitFor(t, "device list change from Synapse", func() bool {
				_, sy := alice.do(t, "GET", "/_matrix/client/v3/sync?timeout=0&since="+since, nil)
				dl, _ := sy["device_lists"].(map[string]any)
				ch, _ := dl["changed"].([]any)
				for _, u := range ch {
					if u == sam.id {
						return true
					}
				}
				return false
			})
		})
		t.Run("media with synapse v"+ver, func(t *testing.T) {
			data := []byte("fake-ogg-voice-" + ver + strings.Repeat("x", 5000))
			// renka -> Synapse
			mine := upload(t, alice, "audio/ogg", data)
			req, _ := http.NewRequest("GET", sam.base+"/_matrix/client/v1/media/download/"+mine, nil)
			req.Header.Set("Authorization", "Bearer "+sam.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !bytes.Equal(got, data) {
				t.Fatalf("Synapse fetching renka media: %d %d bytes %s", resp.StatusCode, len(got), got[:min(len(got), 200)])
			}
			// Synapse -> renka
			req, _ = http.NewRequest("POST", sam.base+"/_matrix/media/v3/upload?filename=v.ogg", bytes.NewReader(data))
			req.Header.Set("Authorization", "Bearer "+sam.token)
			req.Header.Set("Content-Type", "audio/ogg")
			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			var up struct {
				URI string `json:"content_uri"`
			}
			json.NewDecoder(resp.Body).Decode(&up)
			resp.Body.Close()
			code, ct, body := get(alice, "/_matrix/client/v1/media/download/"+strings.TrimPrefix(up.URI, "mxc://"), true)
			if code != 200 || ct != "audio/ogg" || !bytes.Equal(body, data) {
				t.Fatalf("renka fetching Synapse media: %d %s %d bytes", code, ct, len(body))
			}
			// a thumbnail of a renka image, as Synapse asks for it
			img := image.NewRGBA(image.Rect(0, 0, 640, 480))
			var pngData bytes.Buffer
			png.Encode(&pngData, img)
			pic := upload(t, alice, "image/png", pngData.Bytes())
			req, _ = http.NewRequest("GET", sam.base+"/_matrix/client/v1/media/thumbnail/"+pic+"?width=96&height=96&method=crop", nil)
			req.Header.Set("Authorization", "Bearer "+sam.token)
			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			th, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if cfg, _, err := image.DecodeConfig(bytes.NewReader(th)); resp.StatusCode != 200 || err != nil || cfg.Width > 640 {
				t.Errorf("Synapse thumbnail of renka image: %d %v", resp.StatusCode, err)
			}
		})
		t.Run("renka room v"+ver, func(t *testing.T) {
			code, res := alice.do(t, "POST", "/_matrix/client/v3/createRoom", map[string]any{"preset": "private_chat", "room_version": ver,
				"name": "renka " + ver, "invite": []string{sam.id}})
			if code != 200 {
				t.Fatal(code, res)
			}
			room := res["room_id"].(string)
			waitFor(t, "invite on Synapse", func() bool { return sam.invited(room) })
			if _, res := sam.call(t, "POST", "/join/"+url.PathEscape(room), map[string]any{}); res["errcode"] != nil {
				t.Fatalf("Synapse joining a renka room: %v", res)
			}
			ms := sam.send(t, room, "hi from synapse")
			waitFor(t, "Synapse message on renka", func() bool { return hasEvent(s, ms) })
			ma := alice.send(t, room, "hi from renka")
			waitFor(t, "renka message on Synapse", func() bool { return sam.hasEvent(room, ma) })
			alice.do(t, "PUT", "/_matrix/client/v3/rooms/"+room+"/state/m.room.topic/", map[string]any{"topic": "from renka"})
			waitFor(t, "topic on Synapse", func() bool {
				_, st := sam.call(t, "GET", "/rooms/"+room+"/state/m.room.topic/", nil)
				return st["topic"] == "from renka"
			})
			// Synapse can't do what its power doesn't allow, and renka agrees
			_, r := sam.call(t, "PUT", "/rooms/"+room+"/state/m.room.name/", map[string]any{"name": "sam's"})
			if r["errcode"] == nil {
				t.Errorf("Synapse let sam rename the room")
			}
			compareWithSynapse(t, s, sam, room)
		})
	}
}

type synUser struct {
	base, id, token, device string
}

func synapseUser(t *testing.T, base, name string) synUser {
	t.Helper()
	u := synUser{base: base}
	_, res := u.call(t, "POST", "/register", map[string]any{"username": name, "password": "pw-123456-xyz"})
	session, _ := res["session"].(string)
	_, res = u.call(t, "POST", "/register", map[string]any{"username": name, "password": "pw-123456-xyz",
		"auth": map[string]any{"type": "m.login.dummy", "session": session}})
	tok, _ := res["access_token"].(string)
	if tok == "" {
		t.Fatalf("Synapse registration: %v", res)
	}
	u.id, u.token = res["user_id"].(string), tok
	u.device, _ = res["device_id"].(string)
	return u
}

func (u synUser) call(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, u.base+"/_matrix/client/v3"+path, rd)
	if u.token != "" {
		req.Header.Set("Authorization", "Bearer "+u.token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (u synUser) send(t *testing.T, room, body string) string {
	t.Helper()
	_, res := u.call(t, "PUT", "/rooms/"+url.PathEscape(room)+"/send/m.room.message/"+randString(8), map[string]any{"msgtype": "m.text", "body": body})
	id, _ := res["event_id"].(string)
	if id == "" {
		t.Fatalf("Synapse send: %v", res)
	}
	return id
}

func (u synUser) hasEvent(room, id string) bool {
	_, res := u.call(&testing.T{}, "GET", "/rooms/"+url.PathEscape(room)+"/event/"+url.PathEscape(id), nil)
	return res["event_id"] == id
}

func (u synUser) invited(room string) bool {
	// a distinct filter each time: Synapse caches identical sync requests
	f := url.QueryEscape(`{"room":{"timeline":{"limit":` + strconv.Itoa(1+int(time.Now().UnixNano()%1000)) + `}}}`)
	_, res := u.call(&testing.T{}, "GET", "/sync?timeout=0&filter="+f, nil)
	rooms, _ := res["rooms"].(map[string]any)
	inv, _ := rooms["invite"].(map[string]any)
	_, ok := inv[room]
	return ok
}

// compareWithSynapse checks both servers hold the same current state.
func compareWithSynapse(t *testing.T, s *Server, u synUser, room string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		req, _ := http.NewRequest("GET", u.base+"/_matrix/client/v3/rooms/"+url.PathEscape(room)+"/state", nil)
		req.Header.Set("Authorization", "Bearer "+u.token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var evs []map[string]any
		json.NewDecoder(resp.Body).Decode(&evs)
		resp.Body.Close()
		var theirs, ours []string
		for _, e := range evs {
			theirs = append(theirs, e["event_id"].(string))
		}
		st, _ := loadStateGroup(s.db, currentStateGroup(s.db, room))
		for _, id := range st {
			ours = append(ours, id)
		}
		sort.Strings(theirs)
		sort.Strings(ours)
		if strings.Join(theirs, ",") == strings.Join(ours, ",") {
			t.Logf("same state on both servers: %d events", len(ours))
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("state differs:\nSynapse %v\nrenka   %v", theirs, ours)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
