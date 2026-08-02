package compressor

import "regexp"

// maskRule is one ordered regex substitution. Rules are applied most-specific
// first so that, e.g., a UUID or an IP embedded in a URL is consumed by the
// stronger rule before a weaker numeric rule can half-match it.
type maskRule struct {
	name string
	re   *regexp.Regexp
}

// Masker is the deterministic variable-extraction stage (task 1.1). It scans
// text for known sensitive/high-cardinality patterns and replaces each match
// with a dictionary-backed <V*> token. Because substitution goes through the
// Session dictionary, identical values always collapse to the same token and
// remain hydratable.
type Masker struct {
	rules []maskRule
}

// defaultMaskRules is the initial PhiGate rule set. Order matters: earlier
// rules win over later ones for overlapping spans.
var defaultMaskRules = []maskRule{
	// UUID v1-v5.
	{"uuid", regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)},
	// ISO-8601 timestamps: 2026-06-29T15:04:05(.123)?(Z|+09:00)?
	{"ts_iso", regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b`)},
	// Common syslog timestamp: "Jun 29 15:04:05".
	{"ts_syslog", regexp.MustCompile(`\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b`)},
	// Bearer / authorization tokens.
	{"bearer", regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._\-]+`)},
	// Email addresses.
	{"email", regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
	// URLs.
	{"url", regexp.MustCompile(`\bhttps?://[^\s"'<>]+`)},
	// MAC addresses.
	{"mac", regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b`)},
	// IPv6 (loose).
	{"ipv6", regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b`)},
	// IPv4, optionally with :port.
	{"ipv4", regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?\b`)},
	// Absolute unix file paths (at least two segments).
	{"path", regexp.MustCompile(`(?:/[A-Za-z0-9._\-]+){2,}/?`)},
	// Long hex blobs (hashes, opaque tokens).
	{"hex", regexp.MustCompile(`\b[0-9a-fA-F]{16,}\b`)},
	// Large standalone integers (ids, ports, counts >= 4 digits). Only a
	// leading boundary is required so values with a trailing unit (e.g.
	// "12345ms") still have their numeric part masked.
	{"int", regexp.MustCompile(`\b\d{4,}`)},
}

// NewMasker returns a Masker loaded with the default rule set.
func NewMasker() *Masker {
	return &Masker{rules: defaultMaskRules}
}

// Name implements Stage.
func (m *Masker) Name() string { return "masker" }

// Process applies every rule in order. Each match is replaced by a
// session-stable <V*> token from the dictionary.
func (m *Masker) Process(input string, s *Session) (string, error) {
	out := input
	for _, r := range m.rules {
		out = r.re.ReplaceAllStringFunc(out, func(match string) string {
			return s.Dict.Mask(match, ClassVar)
		})
	}
	return out, nil
}
