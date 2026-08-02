package compressor

import (
	"strings"
)

// Drain is a simplified, dependency-free implementation of the Drain log
// parsing algorithm. It clusters near-identical log lines into a single
// template so that a burst of repeated errors compresses to one line before it
// is sent to an LLM.
//
// Simplifications vs. the published Drain3:
//   - The fixed-depth parse tree is collapsed to a single (tokenCount, firstToken)
//     bucket key, which is sufficient once the Masker has already normalised
//     high-cardinality variables to <V*> tokens.
//   - Variable extraction itself is delegated to the Masker; Drain only marks
//     intra-cluster positional differences with the "<*>" wildcard.
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
		key := itoa(len(tokens)) + "|" + tokens[0]

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
			b.WriteString(itoa(cl.count))
			b.WriteByte(')')
		}
	}
	return b.String(), nil
}

// similar reports whether candidate is close enough to the cluster template to
// merge. Token counts are guaranteed equal by the bucket key.
func (d *Drain) similar(template, candidate []string) bool {
	if len(template) != len(candidate) {
		return false
	}
	same := 0
	for i := range template {
		if template[i] == "<*>" || template[i] == candidate[i] {
			same++
		}
	}
	return float64(same)/float64(len(template)) >= d.simThreshold
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
