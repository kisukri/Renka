package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// randString returns a cryptographically random alphanumeric string.
func randString(n int) string {
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		rand.Read(buf)
		for _, b := range buf {
			if b < 248 { // discard bytes >= 248 (62*4) to avoid modulo bias
				out = append(out, alnum[int(b)%62])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out)
}

func nowMS() int64 { return time.Now().UnixMilli() }

func sp(s string) *string { return &s }

// apiError is a Matrix-style error: {"errcode": "...", "error": "..."}.
type apiError struct {
	Status int
	Code   string
	Msg    string
	Extra  map[string]any
}

func (e *apiError) Error() string { return e.Code + ": " + e.Msg }

func errf(status int, code, format string, a ...any) *apiError {
	return &apiError{Status: status, Code: code, Msg: fmt.Sprintf(format, a...)}
}
func errForbidden(msg string) error    { return errf(403, "M_FORBIDDEN", "%s", msg) }
func errNotFound(msg string) error     { return errf(404, "M_NOT_FOUND", "%s", msg) }
func errBadJSON(msg string) error      { return errf(400, "M_BAD_JSON", "%s", msg) }
func errInvalidParam(msg string) error { return errf(400, "M_INVALID_PARAM", "%s", msg) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		body := map[string]any{"errcode": ae.Code, "error": ae.Msg}
		for k, v := range ae.Extra {
			body[k] = v
		}
		writeJSON(w, ae.Status, body)
		return
	}
	log.Printf("internal error: %v", err)
	writeJSON(w, 500, map[string]any{"errcode": "M_UNKNOWN", "error": "internal server error"})
}

// readJSON decodes the body (empty is fine). json.Number keeps big ints exact.
func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return errf(413, "M_TOO_LARGE", "request body too large")
		}
		return errBadJSON("invalid JSON body: " + err.Error())
	}
	return nil
}

// toInt reads a number or numeric string. Out-of-range floats give def
// (their int64 conversion differs between amd64 and arm64).
func toInt(v any, def int64) int64 {
	const limit = 1<<53 - 1
	inRange := func(n int64) bool { return n >= -limit && n <= limit }
	switch x := v.(type) {
	case float64:
		if x == math.Trunc(x) && x >= -limit && x <= limit {
			return int64(x)
		}
	case json.Number:
		if n, err := x.Int64(); err == nil && inRange(n) {
			return n
		}
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64); err == nil && inRange(n) {
			return n
		}
	case int64:
		if inRange(x) {
			return x
		}
	case int:
		if inRange(int64(x)) {
			return int64(x)
		}
	}
	return def
}

// splitID splits "@local:server" / "!id:server" / "#alias:server".
func splitID(id string) (local, server string, ok bool) {
	if len(id) < 4 {
		return "", "", false
	}
	i := strings.IndexByte(id, ':')
	if i < 2 || i == len(id)-1 {
		return "", "", false
	}
	return id[1:i], id[i+1:], true
}

func validLocalpart(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("._=-/+", c)) {
			return false
		}
	}
	return true
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// parseToken parses a stream token like "s123" (also accepts plain numbers).
func parseToken(t string) (int64, bool) {
	t = strings.TrimPrefix(t, "s")
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func tok(n int64) string { return "s" + strconv.FormatInt(n, 10) }

// parseHistoryToken also allows negative positions (backfilled history).
func parseHistoryToken(t string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimPrefix(t, "s"), 10, 64)
	return n, err == nil
}
