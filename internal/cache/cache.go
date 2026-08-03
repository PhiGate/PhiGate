// Package cache stores answers keyed by the *compressed* prompt.
//
// This is PhiGate's largest cost lever and the one a generic LLM gateway cannot
// copy.
//
// AIOps traffic is extraordinarily repetitive: the same disk-full alert, the
// same connection-refused stack trace, thousands of times a day, differing only
// in the IP, the timestamp and the request id. A conventional cache keyed on the
// raw prompt never hits, because those varying values make every request unique.
//
// PhiGate has already replaced exactly those values with placeholders by the
// time the cache is consulted. Ten thousand distinct log lines collapse to one
// compressed template, so the second through ten-thousandth occurrence is a
// cache hit and costs zero upstream tokens. The compression pipeline is what
// makes the cache work, and the cache is what makes the compression pipeline
// pay for itself.
//
// # The security property that makes this safe
//
// The cache stores the answer *before hydration* — still full of <V1> and #REF1
// placeholders — and never the hydrated text. Two sessions that produce the same
// compressed prompt hold different dictionaries: session A's <V1> may be
// 10.0.0.5 and session B's 10.0.0.9. Storing hydrated text would serve A's real
// values to B. Storing the masked answer and hydrating per-session yields the
// correct answer for each and keeps the cache free of sensitive data entirely,
// which is also why it is safe to share across tenants.
package cache

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is a cached, still-masked answer.
type Entry struct {
	// Content is the answer as the model produced it, with placeholders intact.
	Content string
	// Model is the upstream model that produced it.
	Model string
	// Route records whether it came from the local or cloud backend.
	Route string
	// PromptTokens and CompletionTokens are the cost that was paid once, on
	// the miss, and is being avoided on every subsequent hit.
	PromptTokens     int
	CompletionTokens int

	stored time.Time
}

// Stats is a snapshot of cache effectiveness.
type Stats struct {
	Hits           int64   `json:"hits"`
	Misses         int64   `json:"misses"`
	Entries        int     `json:"entries"`
	Capacity       int     `json:"capacity"`
	HitRate        float64 `json:"hit_rate"`
	TokensAvoided  int64   `json:"tokens_avoided"`
	Evictions      int64   `json:"evictions"`
	TTLSeconds     int     `json:"ttl_seconds"`
	OldestAgeSecs  int     `json:"oldest_age_seconds"`
	Enabled        bool    `json:"enabled"`
	SharedTenantOK bool    `json:"shared_across_tenants"`
}

// Cache is a bounded, TTL'd, LRU store of masked answers.
type Cache struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	items map[string]*list.Element
	order *list.List

	hits, misses, evictions, tokensAvoided atomic.Int64
	enabled                                bool
}

type node struct {
	key string
	e   Entry
}

// New returns a Cache holding at most max entries for at most ttl each.
// A non-positive max disables the cache.
func New(ttl time.Duration, max int) *Cache {
	c := &Cache{
		ttl:     ttl,
		max:     max,
		items:   make(map[string]*list.Element),
		order:   list.New(),
		enabled: max > 0 && ttl > 0,
	}
	return c
}

// Key derives the cache key from everything that can change the answer.
//
// The compressed prompt is hashed rather than stored, so the cache holds no
// prompt text at all — not even masked text — which keeps a memory dump of the
// gateway free of customer payloads.
func Key(model string, compressedMessages []string, temperature *float64, maxTokens *int) string {
	h := sha256.New()
	h.Write([]byte(model))
	h.Write([]byte{0})
	for _, m := range compressedMessages {
		h.Write([]byte(m))
		h.Write([]byte{0})
	}
	if temperature != nil {
		h.Write([]byte("t=" + strconv.FormatFloat(*temperature, 'f', 4, 64)))
	}
	if maxTokens != nil {
		h.Write([]byte("m=" + strconv.Itoa(*maxTokens)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns a cached entry if one is present and unexpired.
func (c *Cache) Get(key string) (Entry, bool) {
	if !c.enabled {
		return Entry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		c.misses.Add(1)
		return Entry{}, false
	}
	n := el.Value.(*node)
	if time.Since(n.e.stored) > c.ttl {
		c.removeLocked(el)
		c.misses.Add(1)
		return Entry{}, false
	}
	c.order.MoveToFront(el)
	c.hits.Add(1)
	c.tokensAvoided.Add(int64(n.e.PromptTokens + n.e.CompletionTokens))
	return n.e, true
}

// Put stores an answer. Callers must pass the pre-hydration text; storing
// hydrated content would leak one session's values to another.
func (c *Cache) Put(key string, e Entry) {
	if !c.enabled || e.Content == "" {
		return
	}
	e.stored = time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		el.Value.(*node).e = e
		c.order.MoveToFront(el)
		return
	}
	el := c.order.PushFront(&node{key: key, e: e})
	c.items[key] = el
	for len(c.items) > c.max {
		if back := c.order.Back(); back != nil {
			c.removeLocked(back)
			c.evictions.Add(1)
			continue
		}
		break
	}
}

// Purge empties the cache. Exposed so an operator can clear it after changing
// the rule set, since a rule change alters what "compressed" means.
func (c *Cache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*list.Element)
	c.order.Init()
}

func (c *Cache) removeLocked(el *list.Element) {
	n := el.Value.(*node)
	c.order.Remove(el)
	delete(c.items, n.key)
}

// Stats returns a snapshot.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	entries := len(c.items)
	oldest := 0
	if back := c.order.Back(); back != nil {
		oldest = int(time.Since(back.Value.(*node).e.stored).Seconds())
	}
	c.mu.Unlock()

	h, m := c.hits.Load(), c.misses.Load()
	rate := 0.0
	if h+m > 0 {
		rate = float64(h) / float64(h+m)
	}
	return Stats{
		Hits: h, Misses: m, Entries: entries, Capacity: c.max,
		HitRate: rate, TokensAvoided: c.tokensAvoided.Load(),
		Evictions: c.evictions.Load(), TTLSeconds: int(c.ttl.Seconds()),
		OldestAgeSecs: oldest, Enabled: c.enabled, SharedTenantOK: true,
	}
}

// Keys returns the stored keys, sorted. Used by the admin dashboard; the keys
// are hashes and disclose nothing.
func (c *Cache) Keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.items))
	for k := range c.items {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
