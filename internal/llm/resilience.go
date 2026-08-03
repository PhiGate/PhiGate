package llm

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when the breaker is open for a backend.
var ErrCircuitOpen = errors.New("circuit breaker open")

// StatusError carries an upstream HTTP status so callers can distinguish a
// retryable 503 from a permanent 400.
type StatusError struct {
	Backend string
	Status  int
	Body    string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("%s backend status %d: %s", e.Backend, e.Status, e.Body)
}

// Retryable reports whether another attempt could plausibly succeed.
//
// The distinction matters more for a gateway than for an application: PhiGate
// sits in front of every request an enterprise makes, so retrying a 400 wastes
// the customer's quota on a request that can never succeed, while not retrying
// a 429 turns a provider hiccup into a visible outage.
func (e *StatusError) Retryable() bool {
	switch e.Status {
	case http.StatusTooManyRequests, http.StatusRequestTimeout,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return se.Retryable()
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false // the caller gave up; do not spend their budget again
	}
	// Transport-level failures (connection refused, reset, DNS) are worth one
	// more try: they are exactly what a rolling restart upstream looks like.
	return true
}

// breaker is a per-backend circuit breaker.
//
// Without one, a local Ollama that is down turns every request into a full
// timeout before falling back, so a backend failure becomes a latency incident
// for every caller. The breaker converts that into an immediate, cheap failure
// that the gateway can route around.
type breaker struct {
	threshold int
	cooldown  time.Duration

	mu       sync.Mutex
	failures int
	openedAt time.Time
}

func newBreaker(threshold int, cooldown time.Duration) *breaker {
	if threshold <= 0 {
		return nil
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &breaker{threshold: threshold, cooldown: cooldown}
}

// allow reports whether a call may proceed.
func (b *breaker) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failures < b.threshold {
		return true
	}
	if time.Since(b.openedAt) >= b.cooldown {
		// Half-open: let one request through to test recovery.
		b.failures = b.threshold - 1
		return true
	}
	return false
}

func (b *breaker) success() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.failures = 0
	b.mu.Unlock()
}

func (b *breaker) failure() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.failures++
	if b.failures >= b.threshold {
		b.openedAt = time.Now()
	}
	b.mu.Unlock()
}

// State reports the breaker state for the health and stats endpoints.
func (b *breaker) State() string {
	if b == nil {
		return "disabled"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failures >= b.threshold && time.Since(b.openedAt) < b.cooldown {
		return "open"
	}
	if b.failures > 0 {
		return "degraded"
	}
	return "closed"
}

// retry runs fn with exponential backoff and jitter, honouring ctx.
func retry(ctx context.Context, attempts int, fn func() error) error {
	if attempts < 1 {
		attempts = 1
	}
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if i == attempts-1 || !isRetryable(err) {
			return err
		}
		// Full jitter: base 200ms doubling, capped at 5s.
		base := math.Min(5000, 200*math.Pow(2, float64(i)))
		delay := time.Duration(rand.Int63n(int64(base))) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return err
}
