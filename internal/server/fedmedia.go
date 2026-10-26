package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Media across servers. Other servers fetch ours with
// /_matrix/federation/v1/media/{download,thumbnail}; we fetch theirs the
// same way (old servers: the legacy /_matrix/media/v3 path) and keep a copy,
// trimmed oldest-first to remote_media_cache_mb.

type mediaFetches struct {
	mu      sync.Mutex
	running map[string]*mediaFetch
}

type mediaFetch struct {
	done chan struct{}
	m    *mediaInfo
	err  error
}

func remoteKey(server, id string) string {
	h := sha256.Sum256([]byte(server + "/" + id))
	return "r" + hex.EncodeToString(h[:16])
}

// remoteMedia returns another server's media from the cache, fetching it
// first if allowed.
func (s *Server) remoteMedia(ctx context.Context, server, id string, mayFetch bool) (*mediaInfo, error) {
	if !validHostPort(server) {
		return nil, errNotFound("media not found")
	}
	if m := s.cachedRemote(server, id); m != nil {
		return m, nil
	}
	if !mayFetch || !s.cfg.Federation {
		return nil, errNotFound("media not found")
	}
	k := server + "/" + id
	s.mediaFetch.mu.Lock()
	if s.mediaFetch.running == nil {
		s.mediaFetch.running = map[string]*mediaFetch{}
	}
	f, busy := s.mediaFetch.running[k]
	if !busy {
		f = &mediaFetch{done: make(chan struct{})}
		s.mediaFetch.running[k] = f
	}
	s.mediaFetch.mu.Unlock()
	if !busy {
		// not tied to this request: a client giving up shouldn't waste the download
		f.m, f.err = s.fetchRemoteMedia(context.Background(), server, id)
		s.mediaFetch.mu.Lock()
		delete(s.mediaFetch.running, k)
		s.mediaFetch.mu.Unlock()
		close(f.done)
	}
	select {
	case <-f.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if f.err != nil {
		log.Printf("federation: media %s: %v", k, f.err)
		var ae *apiError
		if errors.As(f.err, &ae) {
			return nil, f.err
		}
		return nil, errf(502, "M_UNKNOWN", "couldn't fetch the file from %s", server)
	}
	return f.m, nil
}

func (s *Server) cachedRemote(server, id string) *mediaInfo {
	m := &mediaInfo{id: id, key: remoteKey(server, id)}
	m.path = filepath.Join(s.cfg.MediaDir, "remote", m.key)
	var used int64
	if s.db.QueryRow("SELECT content_type, filename, size, last_used FROM remote_media WHERE server = ? AND media_id = ?",
		server, id).Scan(&m.ctype, &m.filename, &m.size, &used) != nil {
		return nil
	}
	if _, err := os.Stat(m.path); err != nil {
		return nil
	}
	if now := nowMS(); now-used > 24*3600*1000 {
		s.db.Exec("UPDATE remote_media SET last_used = ? WHERE server = ? AND media_id = ?", now, server, id)
	}
	return m
}

func (s *Server) fetchRemoteMedia(ctx context.Context, server, id string) (*mediaInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	ctype, filename, body, closeFn, err := s.openRemoteMedia(ctx, server, id)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	dir := filepath.Join(s.cfg.MediaDir, "remote")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, "tmp-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(body, s.cfg.MaxUploadBytes+1))
	tmp.Close()
	if err != nil {
		return nil, err
	}
	if n > s.cfg.MaxUploadBytes {
		return nil, errf(413, "M_TOO_LARGE", "the file is larger than this server allows")
	}
	key := remoteKey(server, id)
	if err := os.Rename(tmp.Name(), filepath.Join(dir, key)); err != nil {
		return nil, err
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	if len(filename) > 255 {
		filename = ""
	}
	now := nowMS()
	if _, err := s.db.Exec(`INSERT OR REPLACE INTO remote_media (server, media_id, content_type, filename, size, fetched_ts, last_used)
		VALUES (?,?,?,?,?,?,?)`, server, id, ctype, filename, n, now, now); err != nil {
		return nil, err
	}
	s.trimRemoteCache()
	return &mediaInfo{id: id, ctype: ctype, filename: filename, size: n, path: filepath.Join(dir, key), key: key}, nil
}

// openRemoteMedia starts downloading: the federation endpoint first, then
// the legacy one for servers that don't have it.
func (s *Server) openRemoteMedia(ctx context.Context, server, id string) (ctype, filename string, body io.Reader, closeFn func(), err error) {
	resp, cancel, err := s.fedDo(ctx, "GET", server, "/_matrix/federation/v1/media/download/"+pathEscape(id)+"?timeout_ms=20000", nil, 3*time.Minute)
	if err != nil {
		return "", "", nil, nil, err
	}
	closeAll := func() { resp.Body.Close(); cancel() }
	if resp.StatusCode == 200 {
		ctype, filename, body, err = s.readMultipartMedia(ctx, resp)
		if err != nil {
			closeAll()
			return "", "", nil, nil, err
		}
		return ctype, filename, body, closeAll, nil
	}
	var e struct {
		Code string `json:"errcode"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e)
	closeAll()
	if resp.StatusCode == 404 && e.Code == "M_NOT_FOUND" {
		return "", "", nil, nil, errNotFound("media not found")
	}
	if resp.StatusCode == 404 || resp.StatusCode == 400 || resp.StatusCode == 405 || resp.StatusCode == 501 {
		// legacy path (servers from before Matrix 1.11)
		uri := "/_matrix/media/v3/download/" + pathEscape(server) + "/" + pathEscape(id) + "?allow_remote=false"
		resp, cancel, err = s.fedDo(ctx, "GET", server, uri, nil, 3*time.Minute)
		if err != nil {
			return "", "", nil, nil, err
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			cancel()
			return "", "", nil, nil, errNotFound("media not found")
		}
		_, params, _ := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
		return resp.Header.Get("Content-Type"), params["filename"], resp.Body, func() { resp.Body.Close(); cancel() }, nil
	}
	return "", "", nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
}

// readMultipartMedia reads a federation media answer: a JSON part, then the
// file itself or a Location to fetch it from.
func (s *Server) readMultipartMedia(ctx context.Context, resp *http.Response) (string, string, io.Reader, error) {
	mt, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mt, "multipart/") || params["boundary"] == "" {
		return "", "", nil, errors.New("not a multipart answer")
	}
	mr := multipart.NewReader(resp.Body, params["boundary"])
	meta, err := mr.NextPart()
	if err != nil {
		return "", "", nil, err
	}
	io.Copy(io.Discard, io.LimitReader(meta, 64<<10))
	part, err := mr.NextPart()
	if err != nil {
		return "", "", nil, err
	}
	if loc := part.Header.Get("Location"); loc != "" {
		u, err := url.Parse(loc)
		if err != nil || u.Scheme != "https" {
			return "", "", nil, errors.New("bad media redirect")
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", loc, nil)
		r2, err := s.fedWellKnownClient.Do(req) // public addresses only, https redirects only
		if err != nil {
			return "", "", nil, err
		}
		if r2.StatusCode != 200 {
			r2.Body.Close()
			return "", "", nil, fmt.Errorf("media redirect: HTTP %d", r2.StatusCode)
		}
		_, p, _ := mime.ParseMediaType(r2.Header.Get("Content-Disposition"))
		go func() { <-ctx.Done(); r2.Body.Close() }()
		return r2.Header.Get("Content-Type"), p["filename"], r2.Body, nil
	}
	_, p, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
	return part.Header.Get("Content-Type"), p["filename"], part, nil
}

// trimRemoteCache deletes the least recently used remote files over the cap.
func (s *Server) trimRemoteCache() {
	limit := s.cfg.RemoteMediaCacheBytes
	if limit <= 0 {
		return
	}
	var total int64
	s.db.QueryRow("SELECT COALESCE(SUM(size), 0) FROM remote_media").Scan(&total)
	if total <= limit {
		return
	}
	rows, err := s.db.Query("SELECT server, media_id, size FROM remote_media ORDER BY last_used")
	if err != nil {
		return
	}
	type victim struct {
		server, id string
		size       int64
	}
	var drop []victim
	for rows.Next() && total > limit*9/10 {
		var v victim
		rows.Scan(&v.server, &v.id, &v.size)
		drop = append(drop, v)
		total -= v.size
	}
	rows.Close()
	for _, v := range drop {
		key := remoteKey(v.server, v.id)
		os.Remove(filepath.Join(s.cfg.MediaDir, "remote", key))
		if thumbs, _ := filepath.Glob(filepath.Join(s.cfg.MediaDir, "thumbs", key+"-*")); thumbs != nil {
			for _, t := range thumbs {
				os.Remove(t)
			}
		}
		s.db.Exec("DELETE FROM remote_media WHERE server = ? AND media_id = ?", v.server, v.id)
	}
}

// ---- serving our media to other servers ----

func (s *Server) hFedMediaDownload(w http.ResponseWriter, r *http.Request, origin string, _ []byte) (any, error) {
	m, err := s.localMedia(r.PathValue("mediaId"))
	if err != nil {
		return nil, err
	}
	f, err := os.Open(m.path)
	if err != nil {
		return nil, errNotFound("media not found")
	}
	defer f.Close()
	writeMediaMultipart(w, m.ctype, m.filename, f)
	return nil, nil
}

func (s *Server) hFedMediaThumbnail(w http.ResponseWriter, r *http.Request, origin string, _ []byte) (any, error) {
	m, err := s.localMedia(r.PathValue("mediaId"))
	if err != nil {
		return nil, err
	}
	data, ctype := s.thumbnailFor(m, r.URL.Query())
	if data == nil {
		f, err := os.Open(m.path)
		if err != nil {
			return nil, errNotFound("media not found")
		}
		defer f.Close()
		writeMediaMultipart(w, m.ctype, "", f)
		return nil, nil
	}
	writeMediaMultipart(w, ctype, "", strings.NewReader(string(data)))
	return nil, nil
}

// writeMediaMultipart writes the federation media format: an empty JSON
// object, then the file.
func writeMediaMultipart(w http.ResponseWriter, ctype, filename string, body io.Reader) {
	mw := multipart.NewWriter(w)
	w.Header().Set("Content-Type", "multipart/mixed; boundary="+mw.Boundary())
	w.WriteHeader(200)
	jp, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/json"}})
	jp.Write([]byte("{}"))
	h := textproto.MIMEHeader{"Content-Type": {ctype}}
	if filename != "" {
		h.Set("Content-Disposition", "inline; filename*=utf-8''"+url.PathEscape(filename))
	}
	fp, _ := mw.CreatePart(h)
	io.Copy(fp, body)
	mw.Close()
}
