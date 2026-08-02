package compressor

import (
	"sort"
	"strings"
	"sync"
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
// A Dictionary is ephemeral and session-bound: it lives only in memory for the
// lifetime of a Session and is never persisted, which is what guarantees that
// no raw PII / credential ever crosses the gateway boundary.
type Dictionary struct {
	mu      sync.Mutex
	forward map[string]string // original -> token  (dedupe: same value, same token)
	reverse map[string]string // token    -> original (hydration)
	nVar    int
	nRef    int
}

// NewDictionary returns an empty Dictionary ready for use.
func NewDictionary() *Dictionary {
	return &Dictionary{
		forward: make(map[string]string),
		reverse: make(map[string]string),
	}
}

// Mask returns a stable token for original. If this exact original has already
// been seen (in any class), its existing token is returned so identical values
// always collapse to the same token. Otherwise the next sequential token in the
// requested class is allocated.
func (d *Dictionary) Mask(original string, c TokenClass) string {
	d.mu.Lock()
	defer d.mu.Unlock()

	if tok, ok := d.forward[original]; ok {
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
	return tok
}

// Lookup returns the original value for a token, if known.
func (d *Dictionary) Lookup(token string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v, ok := d.reverse[token]
	return v, ok
}

// Hydrate replaces every known token in text with its original value. Tokens
// are substituted longest-first so that "<V1>" can never partially clobber
// "<V12>".
func (d *Dictionary) Hydrate(text string) string {
	d.mu.Lock()
	tokens := make([]string, 0, len(d.reverse))
	for tok := range d.reverse {
		tokens = append(tokens, tok)
	}
	// Snapshot under lock, then release before doing string work.
	reverse := make(map[string]string, len(d.reverse))
	for k, v := range d.reverse {
		reverse[k] = v
	}
	d.mu.Unlock()

	sort.Slice(tokens, func(i, j int) bool {
		return len(tokens[i]) > len(tokens[j])
	})

	for _, tok := range tokens {
		text = strings.ReplaceAll(text, tok, reverse[tok])
	}
	return text
}

// Entries returns a copy of the token->original map for inspection/debugging.
func (d *Dictionary) Entries() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]string, len(d.reverse))
	for k, v := range d.reverse {
		out[k] = v
	}
	return out
}

func varToken(n int) string { return "<V" + itoa(n) + ">" }
func refToken(n int) string { return "#REF" + itoa(n) }

// itoa is a tiny strconv.Itoa shim kept local to avoid an import for one call
// site; it is only ever fed small positive ints.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
