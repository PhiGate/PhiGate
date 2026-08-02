package compressor

import (
	"crypto/rand"
	"encoding/hex"
)

// Session carries the per-request state for one compression/hydration round
// trip. Its Dictionary holds every substitution so the gateway can reverse them
// on the way back to the operator. Sessions are in-memory only and intended to
// be discarded once the response has been hydrated.
type Session struct {
	ID   string
	Dict *Dictionary

	// seen tracks token frequency so stages like RefDict can decide whether a
	// long string is "repetitive" (seen >= 2 times) within this session.
	seen map[string]int
}

// NewSession creates a fresh Session with an empty dictionary.
func NewSession() *Session {
	return &Session{
		ID:   newSessionID(),
		Dict: NewDictionary(),
		seen: make(map[string]int),
	}
}

// observe records that token s was encountered and returns the running count.
func (s *Session) observe(str string) int {
	s.seen[str]++
	return s.seen[str]
}

func newSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "sess-0"
	}
	return "sess-" + hex.EncodeToString(b[:])
}
