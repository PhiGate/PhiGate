package compressor

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/phigate/phigate/internal/redact"
)

// Session carries the state for one compression/hydration round trip. Its
// Dictionary holds every substitution so the gateway can reverse them on the way
// back to the operator.
//
// A Session may outlive a single request: the gateway keeps it alive for the
// duration of a conversation so that the same IP address is <V1> in every turn.
// Without that, a multi-turn chat re-masks the same values to different tokens
// and the model loses the thread. Sessions are in-memory only and expire.
type Session struct {
	ID   string
	Dict *Dictionary

	mu      sync.Mutex
	seen    map[string]int
	classes map[redact.Category]int
	rules   map[string]int
	touched time.Time
}

// NewSession creates a fresh Session with an empty dictionary.
func NewSession() *Session {
	return NewSessionWithID(newSessionID())
}

// NewSessionWithID creates a Session with a caller-chosen ID, used by the
// session store to key a conversation.
func NewSessionWithID(id string) *Session {
	return &Session{
		ID:      id,
		Dict:    NewDictionary(),
		seen:    make(map[string]int),
		classes: make(map[redact.Category]int),
		rules:   make(map[string]int),
		touched: time.Now(),
	}
}

// observe records that token s was encountered and returns the running count.
func (s *Session) observe(str string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen[str]++
	return s.seen[str]
}

// Note records a redaction finding's classification. The gateway's egress policy
// reads these counts to decide whether the payload may be sent to a cloud
// backend at all.
func (s *Session) Note(f redact.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.classes[f.Category]++
	s.rules[f.Rule]++
	s.touched = time.Now()
}

// Categories returns the count of findings per data classification.
func (s *Session) Categories() map[redact.Category]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[redact.Category]int, len(s.classes))
	for k, v := range s.classes {
		out[k] = v
	}
	return out
}

// FiredRules returns the names of the rules that matched, sorted, for audit
// records. Rule names are safe to log; the values they matched are not.
func (s *Session) FiredRules() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.rules))
	for k := range s.rules {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// MaxSensitivity reports the highest classification seen in this session. It is
// the single number the egress policy compares against its threshold.
func (s *Session) MaxSensitivity() redact.Sensitivity {
	s.mu.Lock()
	defer s.mu.Unlock()
	max := redact.SensitivityLow
	for cat, n := range s.classes {
		if n == 0 {
			continue
		}
		if sv := cat.Sensitivity(); sv > max {
			max = sv
		}
	}
	return max
}

// Touch marks the session as recently used, deferring its expiry.
func (s *Session) Touch() {
	s.mu.Lock()
	s.touched = time.Now()
	s.mu.Unlock()
}

// LastUsed reports when the session was last touched.
func (s *Session) LastUsed() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.touched
}

func newSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "sess-0"
	}
	return "sess-" + hex.EncodeToString(b[:])
}
