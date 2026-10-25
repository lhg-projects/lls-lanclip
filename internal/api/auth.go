// Package api implements the authenticated LAN HTTP face of the daemon.
//
// Desktop<->desktop sync keeps the binary TLS protocol; constrained clients
// (Android: no background clipboard reads, no TLS exporter in JSSE) use this
// HTTP face instead. One group key authorizes both transports:
//
//	Authorization: LANCLIP hex(HMAC-SHA256(groupKey,
//	    ts "\n" METHOD "\n" PATH "\n" hex(sha256(body))))
//	X-Lanclip-Ts:  <unix millis>
//
// Loopback callers are exempt (local tooling/tests). LAN callers with a bad
// or stale signature get 401. Traffic should run over TLS in the long run;
// for now the HMAC guarantees integrity + authenticity, not confidentiality
// (same trust level as the pre-0.2 binary protocol).
package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

const (
	// AuthWindow bounds timestamp skew for LAN requests.
	AuthWindow = 2 * time.Minute

	maxBodyForSig = 64 << 20 // signature covers bodies up to 64MB
)

// Verifier checks LANCLIP HMAC authorization.
type Verifier struct {
	groupKey []byte
}

// NewVerifier builds a Verifier for the group key.
func NewVerifier(groupKey []byte) *Verifier { return &Verifier{groupKey: groupKey} }

// Sign produces the header values for a request (used by desktop's outbound
// HTTP client when pushing to Android peers).
func Sign(groupKey []byte, ts int64, method, path string, body []byte) (auth string) {
	m := hmac.New(sha256.New, groupKey)
	fmt.Fprintf(m, "%d\n%s\n%s\n%s", ts, method, path, hashHex(body))
	return "LANCLIP " + hex.EncodeToString(m.Sum(nil))
}

func hashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Middleware wraps next with HMAC auth; loopback is trusted.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLoopback(r.RemoteAddr) {
			next.ServeHTTP(w, r)
			return
		}
		if !v.check(r) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (v *Verifier) check(r *http.Request) bool {
	tsHeader := r.Header.Get("X-Lanclip-Ts")
	if tsHeader == "" {
		return false
	}
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().UnixMilli()
	if ts < now-AuthWindow.Milliseconds() || ts > now+AuthWindow.Milliseconds() {
		return false
	}
	var body []byte
	if r.Body != nil && r.ContentLength > 0 && r.ContentLength < maxBodyForSig {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxBodyForSig))
		if err != nil {
			return false
		}
		r.Body = io.NopCloser(newByteReader(b))
		body = b
	}
	want := Sign(v.groupKey, ts, r.Method, r.URL.Path, body)
	got := r.Header.Get("Authorization")
	return hmac.Equal([]byte(want), []byte(got))
}

func nowMilli() int64 { return time.Now().UnixMilli() }

func isLoopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type byteReader struct {
	b []byte
	i int
}

func newByteReader(b []byte) *byteReader { return &byteReader{b: b} }

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
