package compressor

import "regexp"

// RefDict folds repetitive long strings — typically fully-qualified package
// paths in stack traces (e.g. org.springframework.web.servlet.DispatcherServlet)
// — into compact #REF tokens. Unlike the Masker, which targets sensitive
// variables, RefDict targets verbose-but-structural identifiers that bloat
// token counts when a stack trace repeats the same package prefixes dozens of
// times.
//
// A candidate is folded only once it has been observed at least minOccurrences
// times within the session, so one-off identifiers are left untouched.
type RefDict struct {
	re             *regexp.Regexp
	minLen         int
	minOccurrences int
}

// dottedIdent matches Java/Go style dotted package paths with >= 3 segments.
var dottedIdent = regexp.MustCompile(`\b(?:[A-Za-z_][A-Za-z0-9_]*\.){2,}[A-Za-z_][A-Za-z0-9_]*\b`)

// NewRefDict returns a RefDict with default thresholds.
func NewRefDict() *RefDict {
	return &RefDict{
		re:             dottedIdent,
		minLen:         16,
		minOccurrences: 2,
	}
}

// Name implements Stage.
func (r *RefDict) Name() string { return "refdict" }

// Process runs a two-pass fold: the first pass counts candidate occurrences
// across the whole input via the session frequency map, the second pass
// rewrites only those that crossed the repetition threshold.
func (r *RefDict) Process(input string, s *Session) (string, error) {
	// Pass 1: tally candidate frequencies for this input.
	counts := make(map[string]int)
	for _, m := range r.re.FindAllString(input, -1) {
		if len(m) >= r.minLen {
			counts[m]++
		}
	}

	// Pass 2: replace only repeated, long candidates.
	out := r.re.ReplaceAllStringFunc(input, func(match string) string {
		if len(match) < r.minLen || counts[match] < r.minOccurrences {
			return match
		}
		s.observe(match)
		return s.Dict.Mask(match, ClassRef)
	})
	return out, nil
}
