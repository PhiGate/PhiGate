package compressor

import (
	"strconv"
	"strings"
)

// Drain is a simplified, dependency-free implementation of the Drain log
// parsing algorithm. It clusters near-identical log lines into a single
// template so that a burst of repeated errors compresses to one line before it
// is sent to an LLM.
//
// Simplifications vs. the published Drain3:
//   - The fixed-depth parse tree is collapsed to a (tokenCount, firstLiteralToken)
//     bucket key.
//   - Variable extraction itself is delegated to the Masker; Drain only marks
//     intra-cluster positional differences with the "<*>" wildcard.
//
// # Why the key skips placeholders
//
// The bucket key originally used the plain first token, on the reasoning that
// the Masker had already normalised variables. It had not: the Masker assigns a
// *distinct* token per distinct value, so three occurrences of the same error
// begin with <V1>, <V3>, <V4> — three different first tokens, three different
// buckets, and no clustering at all.
//
// Since almost every log line begins with a timestamp, that made this stage a
// no-op on real input, which is precisely the input it exists for. The key now
// skips placeholder tokens, and similar() treats any two placeholders as
// matching, so lines differing only in their masked values cluster as intended.
type Drain struct {
	// simThreshold is the fraction of matching positions required for a line to
	// join an existing cluster (0..1).
	simThreshold float64
}

// NewDrain returns a Drain with sensible defaults.
func NewDrain() *Drain { return &Drain{simThreshold: 0.5} }

// Name implements Stage.
func (d *Drain) Name() string { return "drain" }

type cluster struct {
	tokens []string // current template tokens, "<*>" for variable positions
	count  int
}

// Process clusters the input lines and returns one template line per cluster in
// first-seen order. Clusters seen more than once are annotated with " (xN)" so
// the downstream model knows the event was repeated.
func (d *Drain) Process(input string, s *Session) (string, error) {
	lines := strings.Split(input, "\n")

	// buckets maps (count|firstToken) -> indexes into clusters slice.
	buckets := make(map[string][]int)
	var clusters []*cluster

	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if strings.TrimSpace(trimmed) == "" {
			// Preserve blank lines as their own (degenerate) cluster so the
			// overall shape of the input is not destroyed.
			cl := &cluster{tokens: []string{""}, count: 1}
			clusters = append(clusters, cl)
			continue
		}
		tokens := strings.Fields(trimmed)
		key := bucketKey(tokens)

		matched := false
		for _, idx := range buckets[key] {
			cl := clusters[idx]
			if d.similar(cl.tokens, tokens) {
				mergeTemplate(cl.tokens, tokens)
				cl.count++
				matched = true
				break
			}
		}
		if !matched {
			cl := &cluster{tokens: append([]string(nil), tokens...), count: 1}
			clusters = append(clusters, cl)
			buckets[key] = append(buckets[key], len(clusters)-1)
		}
	}

	var b strings.Builder
	for i, cl := range clusters {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(strings.Join(cl.tokens, " "))
		if cl.count > 1 {
			b.WriteString(" (x")
			b.WriteString(strconv.Itoa(cl.count))
			b.WriteByte(')')
		}
	}
	return b.String(), nil
}

// similar reports whether candidate is close enough to the cluster template to
// merge. Token counts are guaranteed equal by the bucket key.
//
// Two placeholders count as matching whatever their numbers: <V1> and <V7> are
// both "a masked value in this position", which is exactly the equivalence
// clustering needs.
func (d *Drain) similar(template, candidate []string) bool {
	if len(template) != len(candidate) {
		return false
	}
	same := 0
	for i := range template {
		switch {
		case template[i] == "<*>",
			template[i] == candidate[i],
			isPlaceholder(template[i]) && isPlaceholder(candidate[i]):
			same++
		}
	}
	return float64(same)/float64(len(template)) >= d.simThreshold
}

// bucketKey groups lines by token count and their first literal token, skipping
// masked values. Falls back to "*" for a line made entirely of placeholders.
func bucketKey(tokens []string) string {
	first := "*"
	for _, t := range tokens {
		if !isPlaceholder(t) {
			first = t
			break
		}
	}
	return strconv.Itoa(len(tokens)) + "|" + first
}

// isPlaceholder reports whether tok is a substitution emitted by an earlier
// pipeline stage rather than literal text from the log.
func isPlaceholder(tok string) bool {
	switch tok {
	case "<*>", "<id>", "<str>", "<int>", "<type>":
		return true
	}
	if strings.HasPrefix(tok, "#REF") {
		return true
	}
	// <V12> and <V12>: — a placeholder possibly carrying trailing punctuation.
	if strings.HasPrefix(tok, "<V") {
		rest := tok[2:]
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		return i > 0 && i < len(rest) && rest[i] == '>'
	}
	return false
}

// mergeTemplate mutates template in place, replacing any position that differs
// from line with the "<*>" wildcard.
func mergeTemplate(template, line []string) {
	for i := range template {
		if template[i] != line[i] {
			template[i] = "<*>"
		}
	}
}
