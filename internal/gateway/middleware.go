package gateway

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phigate/phigate/internal/types"
)

type ctxKey int

const (
	ctxTenant ctxKey = iota
	ctxRequestID
)

// tenantOf returns the authenticated tenant label for a request.
func tenantOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxTenant).(string); ok {
		return v
	}
	return ""
}

// requestIDOf returns the generated request id.
func requestIDOf(r *http.Request) string {
	if v, ok := r.Context().Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

// withRequestID stamps every request with an id, echoed in the response and
// recorded in the audit log so an operator can join a user's report to the
// exact audit record.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			var b [8]byte
			if _, err := rand.Read(b[:]); err == nil {
				id = "req-" + hex.EncodeToString(b[:])
			}
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestID, id)))
	})
}

// authenticator checks client credentials.
//
// The gateway previously had none. Anyone able to reach the port could proxy
// requests using the enterprise's cloud API key — an open relay in front of a
// billed account — and could reach the debug endpoint that printed the
// plaintext of everything the gateway had just masked.
type authenticator struct {
	keys      map[string]string // key -> tenant
	anonymous bool
}

func newAuthenticator(keys map[string]string, anonymous bool) *authenticator {
	return &authenticator{keys: keys, anonymous: anonymous}
}

// Wrap enforces authentication on a handler.
func (a *authenticator) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(a.keys) == 0 && a.anonymous {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxTenant, "anonymous")))
			return
		}
		tenant, ok := a.authenticate(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="phigate"`)
			writeError(w, http.StatusUnauthorized,
				"missing or invalid credentials", "invalid_request_error", "invalid_api_key")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxTenant, tenant)))
	})
}

// authenticate accepts the credential in the places OpenAI clients put it.
func (a *authenticator) authenticate(r *http.Request) (string, bool) {
	candidates := []string{
		strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		r.Header.Get("api-key"), // Azure-style clients
		r.Header.Get("X-PhiGate-Key"),
	}
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		// Constant-time compare against each configured key so a timing
		// side-channel cannot be used to recover one.
		for key, tenant := range a.keys {
			if subtle.ConstantTimeCompare([]byte(c), []byte(key)) == 1 {
				return tenant, true
			}
		}
	}
	return "", false
}

// rateLimiter is a per-tenant token bucket.
//
// A gateway in front of a metered API needs this for a reason a normal service
// does not: a runaway client loop does not just degrade PhiGate, it spends real
// money on the enterprise's upstream account until someone notices the bill.
type rateLimiter struct {
	perMin int
	burst  int

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perMin, burst int) *rateLimiter {
	if perMin <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = perMin
	}
	return &rateLimiter{perMin: perMin, burst: burst, buckets: map[string]*bucket{}}
}

// Allow reports whether the tenant may make another request now.
func (l *rateLimiter) Allow(tenant string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[tenant]
	if !ok {
		b = &bucket{tokens: float64(l.burst), last: now}
		l.buckets[tenant] = b
	}
	refill := now.Sub(b.last).Minutes() * float64(l.perMin)
	b.tokens = minFloat(float64(l.burst), b.tokens+refill)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Wrap enforces the rate limit.
func (l *rateLimiter) Wrap(next http.Handler) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.Allow(tenantOf(r)) {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests,
				"rate limit exceeded for this API key", "rate_limit_error", "rate_limit_exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// clientIP resolves the caller's address, honouring a trusted proxy header when
// one is configured. It is only ever read from a header the operator explicitly
// named: trusting X-Forwarded-For unconditionally lets any client forge the
// value that lands in the audit log.
func clientIP(r *http.Request, trustedHeader string) string {
	if trustedHeader != "" {
		if v := r.Header.Get(trustedHeader); v != "" {
			if i := strings.IndexByte(v, ','); i > 0 {
				return strings.TrimSpace(v[:i])
			}
			return strings.TrimSpace(v)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// recoverPanic converts a handler panic into a 500 rather than tearing down the
// process, and never leaks the stack to the caller.
func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeError(w, http.StatusInternalServerError,
					"internal error", "api_error", "internal_error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// writeError emits an OpenAI-shaped error so client SDKs parse it normally.
//
// Internal error strings are deliberately not forwarded: the previous handler
// returned raw upstream errors to the caller, which disclosed backend URLs and
// provider messages to anyone who could trigger a failure.
func writeError(w http.ResponseWriter, code int, msg, typ, errCode string) {
	writeJSON(w, code, types.NewError(msg, typ, errCode))
}
