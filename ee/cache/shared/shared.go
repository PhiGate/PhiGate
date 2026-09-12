// SPDX-License-Identifier: BUSL-1.1

// Package shared adds a second cache tier that every replica can see.
//
// # What it is for
//
// The template cache is the largest single saving PhiGate makes: AIOps traffic
// is extraordinarily repetitive, Drain collapses thousands of log lines into
// one template, and a repeat occurrence then costs zero upstream tokens. The
// community edition holds that cache in process memory, which is the right
// default and has one consequence the chart's own comments admit: N replicas
// mean roughly 1/N of the achievable hit rate, because each pod has to learn
// the same templates separately and a rescheduled pod starts over.
//
// This package puts a shared tier behind the local one, so the second replica
// to see a template does not pay for it.
//
// # Why sharing this is safe, when sharing the session dictionary is not
//
// The two are opposite cases and the distinction is the whole design.
//
// The session dictionary maps <V1> back to the real value. It is memory-only
// on purpose, because a shared store would persist exactly the data the
// gateway exists to keep in, and no operational benefit justifies that.
//
// A cache entry is the answer as the model produced it, before hydration, with
// every placeholder still in place — and its key is a SHA-256 digest of the
// compressed text, which is the one operation that cannot be undone. The
// community cache is already shared across tenants in one process for this
// reason. Sharing it across processes crosses no boundary that was not already
// crossed; it only widens who can read masked text, and masked text is what
// the whole pipeline exists to produce.
//
// What does change is that the entries now live in a system PhiGate does not
// own. That system must be treated as part of the deployment — reachable only
// from the gateway, authenticated, and encrypted in transit — and the threat
// model says so.
package shared

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/phigate/phigate/internal/cache"
)

// Backend is the shared medium. It is an interface so the tier is testable
// without a server and so an operator who standardised on something other than
// Redis is not locked out.
type Backend interface {
	// Get returns the stored bytes, or ok=false when the key is absent. An
	// error means the backend could not answer, which is different from the
	// key being absent and is counted separately.
	Get(ctx context.Context, key string) (val []byte, ok bool, err error)
	// Set stores bytes under key for ttl.
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
	// Close releases the backend's resources.
	Close() error
}

// Options configure the tier.
type Options struct {
	// TTL is how long an entry lives in the shared backend. Zero uses the
	// local store's own TTL, reported through Stats.
	TTL time.Duration
	// Timeout bounds a single backend call. A shared cache must never be the
	// reason a request is slow, so this is short by default: the tier exists
	// to save an upstream call that costs far more than the timeout.
	Timeout time.Duration
	// Prefix namespaces keys, so one Redis can serve several deployments.
	Prefix string
}

// Store is the local cache with a shared tier behind it.
//
// It implements cache.Store, so the gateway installs it through SetCache and
// nothing on the request path learns which kind of store it is talking to.
type Store struct {
	local   cache.Store
	backend Backend
	opts    Options

	sharedHits   atomic.Int64
	sharedWrites atomic.Int64
	// backendErrors counts the times the shared tier could not answer. It is
	// not an error rate to alert on by itself — the gateway is still correct
	// while it climbs — but a tier that is silently doing nothing should be
	// visible rather than merely harmless.
	backendErrors atomic.Int64
}

var _ cache.Store = (*Store)(nil)

// New wraps local with a shared tier.
func New(local cache.Store, backend Backend, opts Options) *Store {
	if opts.Timeout <= 0 {
		opts.Timeout = 250 * time.Millisecond
	}
	if opts.TTL <= 0 {
		opts.TTL = time.Duration(local.Stats().TTLSeconds) * time.Second
	}
	return &Store{local: local, backend: backend, opts: opts}
}

// Get returns a cached answer, consulting the shared tier only on a local miss.
//
// Every failure here is a miss. A shared cache that can fail a request is a new
// single point of failure bolted onto a gateway whose whole job is to stay in
// the path of production traffic, and the worst outcome of treating an outage
// as a miss is the bill the community edition would have paid anyway.
func (s *Store) Get(key string) (cache.Entry, bool) {
	if e, ok := s.local.Get(key); ok {
		return e, true
	}
	if s.backend == nil {
		return cache.Entry{}, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.opts.Timeout)
	defer cancel()

	raw, ok, err := s.backend.Get(ctx, s.opts.Prefix+key)
	if err != nil {
		s.backendErrors.Add(1)
		return cache.Entry{}, false
	}
	if !ok {
		return cache.Entry{}, false
	}
	var e cache.Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		// A value this process cannot read is a version skew or a foreign
		// writer, not a reason to fail. Treat it as absent and let it expire.
		s.backendErrors.Add(1)
		return cache.Entry{}, false
	}

	// Promote, so the next hit on this replica costs nothing at all. This also
	// restores the entry's local age, which is what Stats reports on.
	s.local.Put(key, e)
	s.sharedHits.Add(1)
	return e, true
}

// Put writes through to both tiers.
//
// The shared write is best-effort and its failure is not returned: the answer
// is already in the local tier and already on its way to the caller, so the
// only thing a propagated error could achieve is turning a degraded cache into
// a failed request.
func (s *Store) Put(key string, e cache.Entry) {
	s.local.Put(key, e)
	if s.backend == nil {
		return
	}
	raw, err := json.Marshal(e)
	if err != nil {
		s.backendErrors.Add(1)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.Timeout)
	defer cancel()
	if err := s.backend.Set(ctx, s.opts.Prefix+key, raw, s.opts.TTL); err != nil {
		s.backendErrors.Add(1)
		return
	}
	s.sharedWrites.Add(1)
}

// Purge empties the local tier and deliberately leaves the shared one alone.
//
// Purge exists because a rule change alters what "compressed" means. That makes
// every existing entry unreachable rather than wrong: the key is a digest of
// the compressed text, so text compressed under new rules hashes to a new key
// and never collides with an old one. Local entries are dropped to reclaim the
// memory. Shared entries are left to expire, because flushing a store this
// process does not own — one that may serve other deployments, and that other
// replicas are reading from — to reclaim space that costs nothing is the wrong
// trade.
func (s *Store) Purge() { s.local.Purge() }

// Stats reports the local tier's figures plus what the shared tier contributed.
func (s *Store) Stats() cache.Stats {
	st := s.local.Stats()
	st.SharedTenantOK = true
	return st
}

// SharedStats is the tier's own accounting, for the operator endpoint.
type SharedStats struct {
	// Hits is how many answers came from another replica's work.
	Hits int64 `json:"shared_hits"`
	// Writes is how many were published for other replicas to use.
	Writes int64 `json:"shared_writes"`
	// Errors is how many backend calls could not be answered. Requests
	// succeeded through all of them; a climbing count means the tier is
	// present and doing nothing.
	Errors int64 `json:"shared_errors"`
}

// SharedStats returns the tier's counters.
func (s *Store) SharedStats() SharedStats {
	return SharedStats{
		Hits:   s.sharedHits.Load(),
		Writes: s.sharedWrites.Load(),
		Errors: s.backendErrors.Load(),
	}
}

// Close releases the backend.
func (s *Store) Close() error {
	if s.backend == nil {
		return nil
	}
	return s.backend.Close()
}
