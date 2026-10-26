package server

import (
	"bytes"
	"database/sql"
	"fmt"
	"image"
	"image/draw"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "image/gif"
)

var mediaIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (s *Server) hMediaConfig(w http.ResponseWriter, r *http.Request, _ *Session) (any, error) {
	return map[string]any{"m.upload.size": s.cfg.MaxUploadBytes}, nil
}

func (s *Server) hUpload(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	if r.ContentLength > s.cfg.MaxUploadBytes {
		return nil, errf(413, "M_TOO_LARGE", "file too large")
	}
	quota := s.cfg.MediaQuotaBytes
	if sess.Admin {
		quota = 0
	}
	// early check; the real one is in the tx
	if quota > 0 && s.mediaUsed(s.db, sess.UserID)+max(r.ContentLength, 0) > quota {
		return nil, quotaFull(quota)
	}
	ctype := r.Header.Get("Content-Type")
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	filename := r.URL.Query().Get("filename")
	id := randString(24)
	tmp, err := os.CreateTemp(s.cfg.MediaDir, "upload-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	n, err := io.Copy(tmp, io.LimitReader(r.Body, s.cfg.MaxUploadBytes+1))
	tmp.Close()
	if err != nil {
		return nil, errf(400, "M_UNKNOWN", "upload failed")
	}
	if n > s.cfg.MaxUploadBytes {
		return nil, errf(413, "M_TOO_LARGE", "file too large")
	}
	final := filepath.Join(s.cfg.MediaDir, id)
	if err := os.Rename(tmp.Name(), final); err != nil {
		return nil, err
	}
	err = s.write(func(tx *sql.Tx) error {
		// inside the write lock, so two uploads at once can't both squeeze in
		if quota > 0 && s.mediaUsed(tx, sess.UserID)+n > quota {
			return quotaFull(quota)
		}
		_, err := tx.Exec("INSERT INTO media (media_id, content_type, filename, size, uploader, created_ts) VALUES (?,?,?,?,?,?)",
			id, ctype, nullStr(filename), n, sess.UserID, nowMS())
		return err
	})
	if err != nil {
		os.Remove(final)
		return nil, err
	}
	return map[string]any{"content_uri": "mxc://" + s.cfg.ServerName + "/" + id}, nil
}

func (s *Server) mediaUsed(q querier, uid string) int64 {
	var used int64
	q.QueryRow("SELECT COALESCE(SUM(size), 0) FROM media WHERE uploader = ?", uid).Scan(&used)
	return used
}

func quotaFull(quota int64) error {
	return errf(413, "M_TOO_LARGE", "your media storage quota (%d MB) is full; ask the server admin to raise media_quota_mb", quota>>20)
}

type mediaInfo struct {
	id, ctype, filename string
	size                int64
	path                string // the file on disk
	key                 string // unique name for its thumbnails
}

// lookupMedia finds the media in the URL: ours, or another server's (fetched
// and cached; only for logged-in users, like Synapse).
func (s *Server) lookupMedia(r *http.Request, sess *Session) (*mediaInfo, error) {
	server, id := r.PathValue("serverName"), r.PathValue("mediaId")
	if !mediaIDRe.MatchString(id) {
		return nil, errNotFound("media not found")
	}
	if server == s.cfg.ServerName {
		return s.localMedia(id)
	}
	return s.remoteMedia(r.Context(), server, id, sess != nil)
}

func (s *Server) localMedia(id string) (*mediaInfo, error) {
	if !mediaIDRe.MatchString(id) {
		return nil, errNotFound("media not found")
	}
	m := &mediaInfo{id: id, path: filepath.Join(s.cfg.MediaDir, id), key: id}
	var fn sql.NullString
	if s.db.QueryRow("SELECT content_type, filename, size FROM media WHERE media_id = ?", id).Scan(&m.ctype, &fn, &m.size) != nil {
		return nil, errNotFound("media not found")
	}
	m.filename = fn.String
	return m, nil
}

// inlineSafe lists content types that are safe to display inline in a browser.
func inlineSafe(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch ct {
	case "image/jpeg", "image/png", "image/gif", "image/webp", "image/apng", "image/avif",
		"video/mp4", "video/webm", "video/ogg", "audio/mpeg", "audio/ogg", "audio/wav", "audio/webm",
		"audio/mp4", "audio/aac", "audio/flac", "text/plain":
		return true
	}
	return false
}

func mediaHeaders(w http.ResponseWriter, ctype, filename string) {
	h := w.Header()
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'; script-src 'none'; plugin-types application/pdf; style-src 'unsafe-inline'; media-src 'self'; object-src 'self';")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
	h.Set("Cache-Control", "private, max-age=31536000, immutable")
	disp := "attachment"
	if inlineSafe(ctype) {
		disp = "inline"
	} else {
		ctype = "application/octet-stream"
	}
	h.Set("Content-Type", ctype)
	if filename != "" {
		disp += "; filename*=utf-8''" + url.PathEscape(filename)
	}
	h.Set("Content-Disposition", disp)
}

func (s *Server) hDownload(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	m, err := s.lookupMedia(r, sess)
	if err != nil {
		return nil, err
	}
	return s.serveMedia(w, r, m)
}

func (s *Server) serveMedia(w http.ResponseWriter, r *http.Request, m *mediaInfo) (any, error) {
	f, err := os.Open(m.path)
	if err != nil {
		return nil, errNotFound("media not found")
	}
	defer f.Close()
	name := m.filename
	if fn := r.PathValue("fileName"); fn != "" {
		name = fn
	}
	mediaHeaders(w, m.ctype, name)
	http.ServeContent(w, r, "", fileModTime(f), f)
	return nil, nil
}

func (s *Server) hThumbnail(w http.ResponseWriter, r *http.Request, sess *Session) (any, error) {
	m, err := s.lookupMedia(r, sess)
	if err != nil {
		return nil, err
	}
	data, outType := s.thumbnailFor(m, r.URL.Query())
	if data == nil {
		return s.serveMedia(w, r, m) // not an image we scale, or too big/small: the original
	}
	mediaHeaders(w, outType, "")
	w.Write(data)
	return nil, nil
}

// thumbnailFor returns a (cached) thumbnail of m, or nil to use the original.
func (s *Server) thumbnailFor(m *mediaInfo, q url.Values) ([]byte, string) {
	crop := q.Get("method") == "crop"
	// fixed sizes only, or anyone could fill the disk with variants
	tw, th := pickThumbSize(atoiDefault(q.Get("width"), 320), atoiDefault(q.Get("height"), 240), crop)
	ct := strings.ToLower(m.ctype)
	if ct != "image/jpeg" && ct != "image/png" {
		return nil, ""
	}
	method := "scale"
	if crop {
		method = "crop"
	}
	cache := filepath.Join(s.cfg.MediaDir, "thumbs", fmt.Sprintf("%s-%dx%d-%s", m.key, tw, th, method))
	outType := "image/jpeg"
	if ct == "image/png" {
		outType = "image/png"
	}
	if data, err := os.ReadFile(cache); err == nil {
		return data, outType
	}
	data, err := s.makeThumbnail(m.path, tw, th, crop, outType)
	if err != nil || data == nil {
		return nil, ""
	}
	writeFileAtomic(cache, data)
	return data, outType
}

type thumbSize struct {
	w, h int
	crop bool
}

// thumbSizes are the only thumbnails ever generated (like Synapse's defaults).
var thumbSizes = []thumbSize{
	{32, 32, true}, {96, 96, true}, {320, 320, true},
	{96, 96, false}, {320, 240, false}, {640, 480, false}, {800, 600, false}, {1280, 960, false},
}

// pickThumbSize returns the smallest size covering w x h (or the largest).
func pickThumbSize(w, h int, crop bool) (int, int) {
	var best, largest *thumbSize
	for i := range thumbSizes {
		t := &thumbSizes[i]
		if t.crop != crop {
			continue
		}
		if largest == nil || t.w*t.h > largest.w*largest.h {
			largest = t
		}
		if t.w >= w && t.h >= h && (best == nil || t.w*t.h < best.w*best.h) {
			best = t
		}
	}
	if best == nil {
		best = largest
	}
	return best.w, best.h
}

// writeFileAtomic: temp file + rename.
func writeFileAtomic(path string, data []byte) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), path) != nil {
		os.Remove(tmp.Name())
	}
}

// makeThumbnail returns nil if the image is already small enough.
func (s *Server) makeThumbnail(path string, tw, th int, crop bool, outType string) ([]byte, error) {
	s.thumbSem <- struct{}{} // one at a time: decoding big images costs memory
	defer func() { <-s.thumbSem }()
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, _, err := image.DecodeConfig(f)
	if err != nil {
		return nil, err
	}
	if cfg.Width*cfg.Height > 16_000_000 || (cfg.Width <= tw && cfg.Height <= th) {
		return nil, nil
	}
	f.Seek(0, io.SeekStart)
	img, _, err := image.Decode(f)
	if err != nil {
		return nil, err
	}
	b := img.Bounds()
	sw, sh := b.Dx(), b.Dy()
	// pick the source rectangle (crop = fill the box and cut the overflow)
	srcRect := b
	var dw, dh int
	if crop {
		dw, dh = tw, th
		if sw*th > sh*tw { // source is wider than the target
			cw := sh * tw / th
			x0 := b.Min.X + (sw-cw)/2
			srcRect = image.Rect(x0, b.Min.Y, x0+cw, b.Max.Y)
		} else {
			ch := sw * th / tw
			y0 := b.Min.Y + (sh-ch)/2
			srcRect = image.Rect(b.Min.X, y0, b.Max.X, y0+ch)
		}
	} else {
		dw, dh = tw, sh*tw/sw
		if dh > th {
			dw, dh = sw*th/sh, th
		}
	}
	dw, dh = max(dw, 1), max(dh, 1)
	rgba := image.NewRGBA(image.Rect(0, 0, srcRect.Dx(), srcRect.Dy()))
	draw.Draw(rgba, rgba.Bounds(), img, srcRect.Min, draw.Src)
	img = nil
	dst := boxDownscale(rgba, dw, dh)
	var buf bytes.Buffer
	if outType == "image/png" {
		err = png.Encode(&buf, dst)
	} else {
		err = jpeg.Encode(&buf, dst, &jpeg.Options{Quality: 82})
	}
	return buf.Bytes(), err
}

// boxDownscale averages blocks of source pixels into each destination pixel.
func boxDownscale(src *image.RGBA, dw, dh int) *image.RGBA {
	sw, sh := src.Bounds().Dx(), src.Bounds().Dy()
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < dh; y++ {
		y0, y1 := y*sh/dh, max((y+1)*sh/dh, y*sh/dh+1)
		for x := 0; x < dw; x++ {
			x0, x1 := x*sw/dw, max((x+1)*sw/dw, x*sw/dw+1)
			var r, g, b, a, n uint64
			for sy := y0; sy < y1; sy++ {
				row := src.Pix[sy*src.Stride:]
				for sx := x0; sx < x1; sx++ {
					p := row[sx*4 : sx*4+4]
					r += uint64(p[0])
					g += uint64(p[1])
					b += uint64(p[2])
					a += uint64(p[3])
					n++
				}
			}
			o := dst.Pix[y*dst.Stride+x*4:]
			o[0], o[1], o[2], o[3] = uint8(r/n), uint8(g/n), uint8(b/n), uint8(a/n)
		}
	}
	return dst
}

func fileModTime(f *os.File) time.Time {
	st, err := f.Stat()
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}
