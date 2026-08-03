package compressor

import (
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/phigate/phigate/internal/redact"
)

// TokenClass selects which token namespace a masked value lives in.
type TokenClass int

const (
	// ClassVar produces variable tokens like <V1>, <V2> for high-cardinality
	// values (IPs, UUIDs, timestamps, …) extracted by the Masker.
	ClassVar TokenClass = iota
	// ClassRef produces reference tokens like #REF1 for repetitive long
	// strings (e.g. Java/Go package paths) folded by the RefDict stage.
	ClassRef
)

// Dictionary is the single source of truth for every substitution performed by
// the compression pipeline. It is bidirectional so the gateway can re-hydrate
// the LLM's answer back into the operator-facing text.
//
// A Dictionary is ephemeral and in-memory: it lives only for the lifetime of a
// Session and is never persisted, which is what guarantees that no raw PII or
// credential is written to disk by the gateway.
type Dictionary struct {
	mu      sync.Mutex
	forward map[string]string          // original -> token  (dedupe: same value, same token)
	reverse map[string]string          // token    -> original (hydration)
	class   map[string]redact.Category // token    -> classification
	nVar    int
	nRef    int
}

// NewDictionary returns an empty Dictionary ready for use.
func NewDictionary() *Dictionary {
	return &Dictionary{
		forward: make(map[string]string),
		reverse: make(map[string]string),
		class:   make(map[string]redact.Category),
	}
}

// Mask returns a stable token for original, without a classification. It is
// retained for stages (RefDict) whose substitutions are structural rather than
// sensitive.
func (d *Dictionary) Mask(original string, c TokenClass) string {
	return d.MaskAs(original, c, redact.CategoryIdentifier)
}

// MaskAs returns a stable token for original and records its data
// classification. If this exact value has already been seen its existing token
// is returned, so identical values always collapse to the same token.
func (d *Dictionary) MaskAs(original string, c TokenClass, cat redact.Category) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	if tok, ok := d.forward[original]; ok {
		// Keep the strongest classification ever assigned to this value.
		if cat.Sensitivity() > d.class[tok].Sensitivity() {
			d.class[tok] = cat
		}
		return tok
	}

	var tok string
	switch c {
	case ClassRef:
		d.nRef++
		tok = refToken(d.nRef)
	default:
		d.nVar++
		tok = varToken(d.nVar)
	}

	d.forward[original] = tok
	d.reverse[tok] = original
	d.class[tok] = cat
	return tok
}

// Lookup returns the original value for a token, if known.
func (d *Dictionary) Lookup(token string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v, ok := d.reverse[token]
	return v, ok
}

// Len reports how many distinct values the dictionary holds.
func (d *Dictionary) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.reverse)
}

// HydrationReport describes what a hydration pass actually did. The gateway
// inspects it to detect dictionary enumeration — see HydrateReport.
type HydrationReport struct {
	// Distinct is the number of distinct tokens substituted.
	Distinct int
	// Total is the number of substitutions performed.
	Total int
	// MaxSensitivity is the highest classification among substituted tokens.
	MaxSensitivity redact.Sensitivity
}

// Hydrate replaces every known token in text with its original value.
func (d *Dictionary) Hydrate(text string) string {
	out, _ := d.HydrateReport(text)
	return out
}

// HydrateReport hydrates text and reports what was substituted.
//
// The report exists because hydration is the one place where PhiGate willingly
// re-inserts secrets into a string it did not author. A model — or an attacker
// who injected instructions into a log line the model then obeyed — can emit
// "<V1> <V2> <V3> …" to make the gateway paste back every value it was never
// shown. Counting substitutions is what lets the gateway notice that the answer
// consists mostly of dictionary references and refuse to serve it.
//
// Tokens are substituted longest-first so "<V1>" can never partially clobber
// "<V12>".
func (d *Dictionary) HydrateReport(text string) (string, HydrationReport) {
	d.mu.Lock()
	reverse := make(map[string]string, len(d.reverse))
	class := make(map[string]redact.Category, len(d.class))
	tokens := make([]string, 0, len(d.reverse))
	for k, v := range d.reverse {
		reverse[k] = v
		class[k] = d.class[k]
		tokens = append(tokens, k)
	}
	d.mu.Unlock()

	sort.Slice(tokens, func(i, j int) bool { return len(tokens[i]) > len(tokens[j]) })

	var rep HydrationReport
	for _, tok := range tokens {
		n := strings.Count(text, tok)
		if n == 0 {
			continue
		}
		rep.Distinct++
		rep.Total += n
		if sv := class[tok].Sensitivity(); sv > rep.MaxSensitivity {
			rep.MaxSensitivity = sv
		}
		text = strings.ReplaceAll(text, tok, reverse[tok])
	}
	return text, rep
}

// Entries returns a copy of the token->original map for inspection/debugging.
// It exposes raw sensitive values and must only ever be reachable from the
// debug endpoint, which is disabled by default.
func (d *Dictionary) Entries() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]string, len(d.reverse))
	for k, v := range d.reverse {
		out[k] = v
	}
	return out
}

// Classes returns the classification of each token, which is safe to log.
func (d *Dictionary) Classes() map[string]redact.Category {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]redact.Category, len(d.class))
	for k, v := range d.class {
		out[k] = v
	}
	return out
}

func varToken(n int) string { return "<V" + strconv.Itoa(n) + ">" }
func refToken(n int) string { return "#REF" + strconv.Itoa(n) }
