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

	"github.com/phigate/phigate/internal/config"
	"github.com/phigate/phigate/internal/oidc"
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
// It reads its credentials through now() rather than capturing them, so a key
// rotated by a reload takes effect on the next request instead of the next
// restart — which is the whole point of being able to rotate one.
type authenticator struct {
	now func() *runtimeState
}

func newAuthenticator(now func() *runtimeState) *authenticator {
	return &authenticator{now: now}
}

// Wrap enforces authentication on a handler.
func (a *authenticator) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := a.now()
		cfg := st.cfg
		if len(cfg.APIKeys) == 0 && !cfg.OIDC.Enabled() && cfg.AllowAnonymous {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxTenant, "anonymous")))
			return
		}
		tenant, why, ok := a.authenticate(r, cfg.APIKeys, st.oidc)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="phigate"`)
			// A token is reported on with its reason; a static key is not.
			// Telling a caller their token's audience is wrong saves an
			// integration a day and tells an attacker nothing they do not
			// already hold. Telling them a key was *nearly* right would be an
			// oracle, so key failures stay generic.
			msg := "missing or invalid credentials"
			if why != "" {
				msg += ": " + why
			}
			writeError(w, http.StatusUnauthorized, msg, "invalid_request_error", "invalid_api_key")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxTenant, tenant)))
	})
}

// authenticate accepts the credential in the places OpenAI clients put it, and
// returns the tenant it belongs to plus, for a token, why it was refused.
//
// Static keys are tried first and unchanged, so a deployment with no identity
// provider configured behaves exactly as it did. A credential only reaches
// token verification when it matched no key and has the shape of one, which
// keeps a static key out of a code path that does network I/O.
func (a *authenticator) authenticate(r *http.Request, keys map[string]string, v *oidc.Verifier) (tenant, why string, ok bool) {
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
		for key, tenant := range keys {
			if subtle.ConstantTimeCompare([]byte(c), []byte(key)) == 1 {
				return tenant, "", true
			}
		}
	}
	if v == nil {
		return "", "", false
	}
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if !oidc.LooksLikeJWT(c) {
			continue
		}
		claims, err := v.Verify(r.Context(), c)
		if err != nil {
			// Report the first token that was a token, rather than the last
			// header that was empty.
			return "", strings.TrimPrefix(err.Error(), "oidc: "), false
		}
		return claims.Tenant, "", true
	}
	return "", "", false
}

// rateLimiter is a per-tenant token bucket.
//
// A gateway in front of a metered API needs this for a reason a normal service
// does not: a runaway client loop does not just degrade PhiGate, it spends real
// money on the enterprise's upstream account until someone notices the bill.
type rateLimiter struct {
	// limits resolves a tenant's per-minute allowance and burst. It reads the
	// configuration rather than capturing two numbers, because a tenant may be
	// held to a tighter limit than the deployment's default.
	limits func(tenant string) (perMin, burst int)

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
	// perMin and burst are the limits this bucket was filled under, kept so a
	// reload that tightens a tenant's allowance takes effect on the bucket it
	// already has rather than only on tenants seen for the first time after.
	perMin int
	burst  int
}

// newRateLimiter returns a limiter reading its allowances through now, or nil
// when no tenant is limited at startup.
//
// A nil limiter allows everything, so the common unlimited deployment pays for
// no bookkeeping at all. The consequence is that a deployment which starts with
// no limits anywhere cannot gain one by reload alone; introducing the first
// limit needs a restart, which validate has no way to warn about and the
// configuration reference says plainly.
func newRateLimiter(now func() *runtimeState) *rateLimiter {
	if !anyLimit(now().cfg) {
		return nil
	}
	return &rateLimiter{
		limits: func(tenant string) (int, int) {
			return now().cfg.RateLimitFor(tenant)
		},
		buckets: map[string]*bucket{},
	}
}

// anyLimit reports whether any tenant is limited at all.
func anyLimit(cfg config.Config) bool {
	if cfg.RateLimitPerMin > 0 {
		return true
	}
	for _, t := range cfg.Tenants {
		if t.RateLimitPerMin > 0 {
			return true
		}
	}
	return false
}

// Allow reports whether the tenant may make another request now.
func (l *rateLimiter) Allow(tenant string) bool {
	if l == nil {
		return true
	}
	perMin, burst := l.limits(tenant)
	if perMin <= 0 {
		return true // this tenant is not limited
	}
	if burst <= 0 {
		burst = perMin
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[tenant]
	if !ok {
		b = &bucket{tokens: float64(burst), last: now, perMin: perMin, burst: burst}
		l.buckets[tenant] = b
	}
	if b.perMin != perMin || b.burst != burst {
		// The limits changed under us. Clamp to the new ceiling so a tightened
		// allowance cannot be outrun by a bucket filled under the old one.
		b.perMin, b.burst = perMin, burst
		b.tokens = minFloat(b.tokens, float64(burst))
	}
	refill := now.Sub(b.last).Minutes() * float64(b.perMin)
	b.tokens = minFloat(float64(b.burst), b.tokens+refill)
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
