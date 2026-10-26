package server

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func upload(t *testing.T, u fedUser, ctype string, data []byte) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/_matrix/media/v3/upload?filename=f", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+u.token)
	req.Header.Set("Content-Type", ctype)
	w := httptest.NewRecorder()
	u.h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		URI string `json:"content_uri"`
	}
	mustDecode(t, w.Body.Bytes(), &out)
	return strings.TrimPrefix(out.URI, "mxc://")
}

func mustDecode(t *testing.T, b []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func get(u fedUser, path string, auth bool) (int, string, []byte) {
	req := httptest.NewRequest("GET", path, nil)
	if auth {
		req.Header.Set("Authorization", "Bearer "+u.token)
	}
	w := httptest.NewRecorder()
	u.h.ServeHTTP(w, req)
	b, _ := io.ReadAll(w.Body)
	return w.Code, w.Header().Get("Content-Type"), b
}

func TestMediaAcrossServers(t *testing.T) {
	a, b, ha, hb := fedPair(t)
	aid, at := addUser(t, a, "alice")
	bid, bt := addUser(t, b, "bob")
	alice, bob := fedUser{a, ha, aid, at}, fedUser{b, hb, bid, bt}

	img := image.NewRGBA(image.Rect(0, 0, 900, 700))
	for x := 0; x < 900; x++ {
		img.Set(x, x%700, color.RGBA{200, 10, 10, 255})
	}
	var pngData bytes.Buffer
	png.Encode(&pngData, img)
	mxc := upload(t, alice, "image/png", pngData.Bytes())
	voice := upload(t, alice, "audio/ogg", []byte("OggS fake voice message"))

	// bob's client asks his own server, which fetches from alice's
	code, ct, body := get(bob, "/_matrix/client/v1/media/download/"+mxc, true)
	if code != 200 || ct != "image/png" || !bytes.Equal(body, pngData.Bytes()) {
		t.Fatalf("remote image: %d %s %d bytes", code, ct, len(body))
	}
	code, ct, body = get(bob, "/_matrix/client/v1/media/download/"+voice, true)
	if code != 200 || ct != "audio/ogg" || string(body) != "OggS fake voice message" {
		t.Fatalf("remote voice: %d %s %q", code, ct, body)
	}
	code, ct, body = get(bob, "/_matrix/client/v1/media/thumbnail/"+mxc+"?width=96&height=96&method=crop", true)
	if code != 200 || ct != "image/png" || len(body) == 0 || len(body) >= pngData.Len() {
		t.Fatalf("remote thumbnail: %d %s %d bytes", code, ct, len(body))
	}
	if cfg, _, err := image.DecodeConfig(bytes.NewReader(body)); err != nil || cfg.Width != 96 {
		t.Errorf("thumbnail size: %v %v", cfg, err)
	}
	// cached now: served even when alice's server isn't asked again
	var n int
	b.db.QueryRow("SELECT COUNT(*) FROM remote_media").Scan(&n)
	if n != 2 {
		t.Errorf("%d cached remote files, want 2", n)
	}
	// a logged-out request may not make us fetch from other servers
	otherID := upload(t, alice, "image/png", pngData.Bytes())
	if code, _, _ := get(bob, "/_matrix/media/v3/download/"+otherID, false); code != 404 {
		t.Errorf("unauthenticated remote fetch: %d", code)
	}
	// missing media is a 404, not a hang
	if code, _, _ := get(bob, "/_matrix/client/v1/media/download/"+a.cfg.ServerName+"/nope123", true); code != 404 {
		t.Errorf("missing remote media: %d", code)
	}
	// the federation endpoint needs a signed request
	if code, _, _ := get(alice, "/_matrix/federation/v1/media/download/"+strings.Split(mxc, "/")[1], false); code != 401 {
		t.Errorf("unsigned federation media request: %d", code)
	}
}
