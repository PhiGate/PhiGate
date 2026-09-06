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
// time the cache is consulted, so ten thousand distinct log lines collapse to
// one compressed template and occurrences two through ten thousand cost zero
// upstream tokens. The compression pipeline is what makes the cache work, and
// the cache is what makes the compression pipeline pay for itself.
//
// That collapse needs one more step than it looks, and the key is built on the
// payload's *shape* rather than on its compressed text. See Shape for the
// measurement that showed why: 4.5% against 50.5% on the corpus the README
// benchmarks with.
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
	"regexp"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phigate/phigate/internal/types"
)

// Store is the seam PhiGate's cache tiers plug into.
//
// The gateway depends on this interface rather than on the in-memory
// implementation below, so an alternative tier — a semantic index, or a shared
// store spanning several gateway nodes — can be substituted without the request
// path knowing which one it is talking to.
//
// Every implementation inherits one non-negotiable obligation from the package
// doc above: it stores answers *before* hydration. A tier that persists or
// shares hydrated text serves one session's real values to another.
type Store interface {
	// Get returns a cached entry if one is present and unexpired.
	Get(key string) (Entry, bool)
	// Put stores a pre-hydration answer.
	Put(key string, e Entry)
	// Purge empties the store. Callers use it when a rule change alters what
	// "compressed" means, which invalidates every key.
	Purge()
	// Stats returns a snapshot of effectiveness.
	Stats() Stats
}

// Probe is a cache lookup with the material a hash throws away.
//
// Key alone is enough for this package's exact-match store and is all it uses.
// A tier that matches on meaning rather than on bytes needs the compressed
// text, and Key is a SHA-256 digest of it — the one operation that cannot be
// undone. Probe carries both so such a tier is possible without the request
// path learning which kind of store it is talking to.
//
// Texts is the *compressed* text: masked, with <V1> and #REF1 in place of every
// value. Nothing here has ever held a raw value, and nothing that consumes a
// Probe may store one.
type Probe struct {
	Key         string
	Model       string
	Texts       []string
	Temperature *float64
	MaxTokens   *int
}

// ProbeStore is the optional half of the seam, implemented by a store that can
// use more than the key.
//
// It is separate from Store so the community edition keeps the property its
// package doc claims: the cache holds no prompt text at all, not even masked
// text, which keeps a memory dump of the gateway free of customer payloads.
// A tier that indexes meaning necessarily gives that up — an embedding is a
// lossy but not one-way representation of the text it was built from — and that
// is a trade to be made deliberately, in the tier's own documentation and
// threat model, not inherited by every implementation of Store.
type ProbeStore interface {
	Store
	// GetProbe returns a cached entry for the probe, exact matches first.
	GetProbe(p Probe) (Entry, bool)
}

// Entry is a cached, still-masked answer.
type Entry struct {
	// Content is the answer as the model produced it, with placeholders intact.
	Content string
	// ToolCalls are the calls the answer requested, arguments still masked.
	//
	// They are stored for the same reason Content is, and under the same
	// obligation: pre-hydration only. Omitting them did not merely lose cache
	// value — a tool-call answer has no Content, so a hit replayed it as an
	// empty message and the caller silently lost the call.
	ToolCalls []types.ToolCall
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

// Cache is a bounded, TTL'd, LRU store of masked answers, and the Store
// implementation the community edition ships with.
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

// Compile-time proof that the in-memory cache satisfies the seam.
var _ Store = (*Cache)(nil)

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

// placeholderRe matches the tokens the masker and the ref dictionary emit.
var placeholderRe = regexp.MustCompile(`<V\d+>|#REF\d+`)

// Shape renumbers a payload's placeholders in order of first appearance, and
// returns the mapping from the canonical token back to the original.
//
// # Why the cache cannot be keyed on the compressed text
//
// The session dictionary numbers a value the first time it is *ever* seen, and
// that numbering is what makes hydration work: <V7> has to mean one particular
// host for the whole conversation. The consequence is that the same log line,
// arriving an hour apart in a busy session, compresses to "<V7> failed" and
// "<V931> failed". Those are different strings, so they were different keys,
// and the cache missed on two payloads that are the same payload.
//
// Measured on the eight LogHub corpora the README benchmarks with, keying on
// the text gives a 4.5% hit rate; keying on the shape gives 50.5%. That is the
// difference between a cost lever and a rounding error, and it was invisible
// because nothing measured it.
//
// This is still exact matching. Two payloads share a key only if they are
// identical once their placeholders are renumbered, so the cache still cannot
// serve an answer to a different question — which is the property a semantic
// tier would trade away.
func Shape(texts []string) (canonical []string, toOriginal map[string]string) {
	seen := map[string]string{}      // original token -> canonical token
	toOriginal = map[string]string{} // canonical token -> original token
	canonical = make([]string, len(texts))

	for i, t := range texts {
		canonical[i] = placeholderRe.ReplaceAllStringFunc(t, func(m string) string {
			if c, ok := seen[m]; ok {
				return c
			}
			var c string
			if m[0] == '#' {
				c = "#REF" + strconv.Itoa(len(seen)+1)
			} else {
				c = "<V" + strconv.Itoa(len(seen)+1) + ">"
			}
			seen[m] = c
			toOriginal[c] = m
			return c
		})
	}
	return canonical, toOriginal
}

// Restore maps a canonical answer back into one payload's own numbering.
//
// An entry is stored in canonical form, so a hit has to be translated into the
// tokens the *requesting* session will hydrate. A canonical token with no entry
// in the mapping is left alone: the model can emit a placeholder that was not
// in its prompt, and inventing an original for it would hydrate a value the
// answer never referred to.
func Restore(text string, toOriginal map[string]string) string {
	if len(toOriginal) == 0 {
		return text
	}
	return placeholderRe.ReplaceAllStringFunc(text, func(m string) string {
		if orig, ok := toOriginal[m]; ok {
			return orig
		}
		return m
	})
}

// Key derives the cache key from everything that can change the answer.
//
// Callers pass the *canonical* compressed messages — see Shape.
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
	// An answer that is only tool calls has no Content, so emptiness alone does
	// not mean there is nothing worth storing.
	if !c.enabled || (e.Content == "" && len(e.ToolCalls) == 0) {
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
