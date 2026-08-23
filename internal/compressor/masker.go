package compressor

import "github.com/phigate/phigate/internal/redact"

// Masker is the deterministic variable-extraction stage. It delegates detection
// to the redact engine and is responsible only for turning each detected span
// into a dictionary-backed <V*> token.
//
// The split matters: detection is the security guarantee and lives in
// internal/redact with its own leak-test corpus; this stage owns the token
// allocation and hydration bookkeeping. Because substitution goes through the
// Session dictionary, identical values always collapse to the same token and
// remain hydratable.
type Masker struct {
	engine redact.Detector
}

// NewMasker returns a Masker using the default redaction engine (all built-in
// rule packs, entropy detection on, no site-specific internal domains).
func NewMasker() *Masker {
	return &Masker{engine: redact.MustEngine(redact.Options{})}
}

// NewMaskerWith returns a Masker backed by a caller-supplied detector, which is
// how the gateway applies an enterprise's own rule packs and internal domains,
// and how an alternative detection backend is substituted.
func NewMaskerWith(e redact.Detector) *Masker { return &Masker{engine: e} }

// Name implements Stage.
func (m *Masker) Name() string { return "masker" }

// Process replaces every detected sensitive span with a session-stable <V*>
// token, and records each span's classification on the Session so the egress
// policy can later decide whether this payload may leave the building.
func (m *Masker) Process(input string, s *Session) (string, error) {
	out, findings := m.engine.Redact(input, func(f redact.Finding) string {
		return s.Dict.MaskAs(f.Text, ClassVar, f.Category)
	})
	for _, f := range findings {
		s.Note(f)
	}
	return out, nil
}
