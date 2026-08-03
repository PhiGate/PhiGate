// Package redact implements PhiGate's sensitive-data detection engine.
//
// It is deliberately separated from the compression pipeline: redaction is the
// security-critical guarantee PhiGate sells ("no raw PII or credential crosses
// the gateway boundary"), so it gets its own package, its own rule packs, and
// its own leak-test corpus.
//
// The engine is *detection only*. It returns the spans it believes are
// sensitive; allocating placeholder tokens and recording them for hydration is
// the compressor's job. Keeping the two apart means the detector can be tested
// exhaustively against a corpus of known secrets without dragging in session or
// dictionary state.
//
// # Why a single pass
//
// The original implementation applied each regex in sequence over the output of
// the previous one. That corrupts overlapping matches: a low-priority "unix
// path" rule could eat the middle of an AWS secret key, leaving a *partially*
// masked value in the prompt. Partial masking is worse than none, because it
// looks safe.
//
// This engine instead collects candidate spans from every rule over the
// *original* text, then resolves overlaps by priority (highest wins), then by
// span length (longest wins). A value is therefore always classified by the
// most specific rule that recognises it, and is always masked in full.
package redact

import (
	"regexp"
	"sort"
	"strings"
)

// Category is the data classification assigned to a detected span. It is what
// the egress policy engine reasons about: an enterprise cares that "a credential
// was found", not that "rule aws_access_key_id matched".
type Category string

const (
	// CategorySecret covers credentials, API keys, private keys and tokens.
	// Leaking one is an incident, not a privacy concern.
	CategorySecret Category = "secret"
	// CategoryPII covers data identifying a natural person: My Number,
	// credit cards, phone numbers, addresses, emails.
	CategoryPII Category = "pii"
	// CategoryNetwork covers infrastructure topology: IPs, MACs, internal
	// hostnames, URLs.
	CategoryNetwork Category = "network"
	// CategoryIdentifier covers high-cardinality but low-sensitivity values:
	// UUIDs, request IDs, hashes, large integers.
	CategoryIdentifier Category = "identifier"
	// CategoryTemporal covers timestamps.
	CategoryTemporal Category = "temporal"
	// CategoryPath covers filesystem paths.
	CategoryPath Category = "path"
)

// Sensitivity ranks categories so policy can be expressed as a threshold
// ("anything at or above Confidential must stay local") instead of enumerating
// every category.
type Sensitivity int

const (
	// SensitivityLow is metadata whose exposure is not itself a risk.
	SensitivityLow Sensitivity = iota
	// SensitivityInternal is data that reveals internal structure.
	SensitivityInternal
	// SensitivityConfidential is personal data subject to privacy regulation.
	SensitivityConfidential
	// SensitivityRestricted is credential material.
	SensitivityRestricted
)

// String renders a Sensitivity for logs and audit records.
func (s Sensitivity) String() string {
	switch s {
	case SensitivityRestricted:
		return "restricted"
	case SensitivityConfidential:
		return "confidential"
	case SensitivityInternal:
		return "internal"
	default:
		return "low"
	}
}

// ParseSensitivity maps a config string to a Sensitivity, reporting whether the
// input was recognised.
func ParseSensitivity(s string) (Sensitivity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return SensitivityLow, true
	case "internal":
		return SensitivityInternal, true
	case "confidential":
		return SensitivityConfidential, true
	case "restricted":
		return SensitivityRestricted, true
	}
	return SensitivityLow, false
}

// Sensitivity maps a Category to its rank.
func (c Category) Sensitivity() Sensitivity {
	switch c {
	case CategorySecret:
		return SensitivityRestricted
	case CategoryPII:
		return SensitivityConfidential
	case CategoryNetwork, CategoryPath:
		return SensitivityInternal
	default:
		return SensitivityLow
	}
}

// Rule is one named detection pattern.
//
// Rules are data, not code: they are loaded from JSON rule packs so an
// enterprise can add its own employee-ID or internal-hostname formats without
// rebuilding the binary.
type Rule struct {
	// Name identifies the rule in audit records. It must be unique.
	Name string `json:"name"`
	// Category is the data classification applied to matches.
	Category Category `json:"category"`
	// Pattern is an RE2 regular expression. Go's regexp package does not
	// support lookaround or backreferences; patterns must be RE2-compatible.
	Pattern string `json:"pattern"`
	// Priority resolves overlaps: on an overlapping span the higher priority
	// wins. Credential rules sit above topology rules, which sit above the
	// generic high-cardinality rules.
	Priority int `json:"priority"`
	// Validator optionally names a checksum applied to the matched text.
	// A match failing its validator is discarded, which is what lets a broad
	// pattern like "twelve digits" be used safely for My Number.
	Validator string `json:"validator,omitempty"`
	// Group, when non-zero, narrows the redacted span to that capture group.
	// It is how "password=hunter2" masks only "hunter2" while still requiring
	// the "password=" context to match.
	Group int `json:"group,omitempty"`
	// Description documents the rule for operators reviewing a rule pack.
	Description string `json:"description,omitempty"`
	// Disabled allows a pack to ship a rule that is off by default.
	Disabled bool `json:"disabled,omitempty"`

	re *regexp.Regexp
}

// Pack is a named collection of rules, as stored in a JSON rule-pack file.
type Pack struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Rules       []Rule `json:"rules"`
}

// Finding is one detected sensitive span in the input.
type Finding struct {
	// Start and End are byte offsets into the text that was scanned.
	Start, End int
	// Text is the matched substring.
	Text string
	// Rule is the name of the rule that claimed the span.
	Rule string
	// Category is the classification of the matched data.
	Category Category
}

// Sensitivity reports the rank of the finding's category.
func (f Finding) Sensitivity() Sensitivity { return f.Category.Sensitivity() }

// Engine detects sensitive spans using a compiled set of rules plus an optional
// entropy detector for credentials no pattern anticipated.
type Engine struct {
	rules   []Rule
	byName  map[string]int // rule name -> priority, for overlap resolution
	entropy *EntropyDetector
}

// Options configures Engine construction.
type Options struct {
	// Packs selects which built-in packs to load. Empty means all of them.
	Packs []string
	// ExtraRules are appended after the built-in packs, so an enterprise's own
	// rules can be given a higher priority than anything shipped.
	ExtraRules []Rule
	// DisableRules names built-in rules to drop, for the rare case where a
	// shipped rule misfires on a customer's data.
	DisableRules []string
	// InternalDomains, when non-empty, synthesises a high-priority rule that
	// masks hostnames under those suffixes (e.g. "corp", "internal").
	InternalDomains []string
	// Entropy configures the fallback high-entropy detector. A nil value
	// installs the default detector; use DisableEntropy to turn it off.
	Entropy *EntropyDetector
	// DisableEntropy turns off entropy-based secret detection entirely.
	DisableEntropy bool
}

// NewEngine builds an Engine from the built-in rule packs and opts.
// It returns an error if any pattern fails to compile, so a malformed custom
// rule fails at startup rather than silently disabling protection.
func NewEngine(opts Options) (*Engine, error) {
	packs, err := LoadBuiltinPacks(opts.Packs...)
	if err != nil {
		return nil, err
	}

	disabled := make(map[string]bool, len(opts.DisableRules))
	for _, n := range opts.DisableRules {
		disabled[n] = true
	}

	var rules []Rule
	for _, p := range packs {
		for _, r := range p.Rules {
			if r.Disabled || disabled[r.Name] {
				continue
			}
			rules = append(rules, r)
		}
	}
	if d := internalDomainRule(opts.InternalDomains); d != nil {
		rules = append(rules, *d)
	}
	for _, r := range opts.ExtraRules {
		if r.Disabled || disabled[r.Name] {
			continue
		}
		rules = append(rules, r)
	}

	compiled := make([]Rule, 0, len(rules))
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if seen[r.Name] {
			return nil, &RuleError{Rule: r.Name, Err: errDuplicateRule}
		}
		seen[r.Name] = true
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, &RuleError{Rule: r.Name, Err: err}
		}
		if r.Validator != "" && validators[r.Validator] == nil {
			return nil, &RuleError{Rule: r.Name, Err: errUnknownValidator}
		}
		r.re = re
		compiled = append(compiled, r)
	}

	byName := make(map[string]int, len(compiled))
	for _, r := range compiled {
		byName[r.Name] = r.Priority
	}

	e := &Engine{rules: compiled, byName: byName}
	if !opts.DisableEntropy {
		e.entropy = opts.Entropy
		if e.entropy == nil {
			e.entropy = NewEntropyDetector()
		}
	}
	return e, nil
}

// MustEngine is NewEngine for package-level initialisation and tests.
func MustEngine(opts Options) *Engine {
	e, err := NewEngine(opts)
	if err != nil {
		panic(err)
	}
	return e
}

// Rules exposes the compiled rule set for introspection and the /rules endpoint.
func (e *Engine) Rules() []Rule { return e.rules }

// Detect returns the non-overlapping sensitive spans in text, ordered by
// position. Overlaps are resolved by rule priority, then by span length, so a
// value is always claimed by the most specific rule that recognises it.
func (e *Engine) Detect(text string) []Finding {
	var cands []Finding

	for _, r := range e.rules {
		for _, m := range r.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := m[0], m[1]
			// Group narrows the redacted span while keeping the surrounding
			// context in the match condition.
			if r.Group > 0 && 2*r.Group+1 < len(m) && m[2*r.Group] >= 0 {
				start, end = m[2*r.Group], m[2*r.Group+1]
			}
			if start >= end {
				continue
			}
			got := text[start:end]
			if v := validators[r.Validator]; v != nil && !v(got) {
				continue
			}
			cands = append(cands, Finding{
				Start: start, End: end, Text: got,
				Rule: r.Name, Category: r.Category,
			})
		}
	}

	if e.entropy != nil {
		cands = append(cands, e.entropy.detect(text)...)
	}

	return e.resolve(cands)
}

// Redact replaces every detected span using replace, which receives the finding
// and returns its placeholder. Replacement happens in a single left-to-right
// pass over the original text, so no substitution can ever corrupt another.
func (e *Engine) Redact(text string, replace func(Finding) string) (string, []Finding) {
	found := e.Detect(text)
	if len(found) == 0 {
		return text, nil
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, f := range found {
		b.WriteString(text[last:f.Start])
		b.WriteString(replace(f))
		last = f.End
	}
	b.WriteString(text[last:])
	return b.String(), found
}

// resolve turns overlapping candidates into a sorted, non-overlapping set.
//
// Candidates are ranked by priority-equivalent ordering: higher category
// sensitivity first (a credential rule beats a path rule on the same bytes),
// then longer spans, then earlier position for a stable result. Accepting
// greedily in that order yields the "most specific rule wins, in full" property
// the leak tests depend on.
func (e *Engine) resolve(cands []Finding) []Finding {
	if len(cands) == 0 {
		return nil
	}
	rank := make(map[string]int, len(cands))
	for _, c := range cands {
		rank[c.Rule] = e.priority(c)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if rank[cands[i].Rule] != rank[cands[j].Rule] {
			return rank[cands[i].Rule] > rank[cands[j].Rule]
		}
		li, lj := cands[i].End-cands[i].Start, cands[j].End-cands[j].Start
		if li != lj {
			return li > lj
		}
		return cands[i].Start < cands[j].Start
	})

	var accepted []Finding
	for _, c := range cands {
		overlaps := false
		for _, a := range accepted {
			if c.Start < a.End && a.Start < c.End {
				overlaps = true
				break
			}
		}
		if !overlaps {
			accepted = append(accepted, c)
		}
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].Start < accepted[j].Start })
	return accepted
}

// priority ranks a finding by the priority declared on its rule. Findings from
// the entropy detector carry no rule entry, so they fall back to a rank derived
// from their category — a detected credential still outranks a path.
func (e *Engine) priority(f Finding) int {
	if p, ok := e.byName[f.Rule]; ok {
		return p
	}
	return int(f.Category.Sensitivity()) * 20
}

// internalDomainRule synthesises a hostname rule from configured suffixes.
// Internal hostnames are topology disclosure — "prod-db-tokyo-01.internal.corp"
// tells an attacker more than the IP does — but the suffixes are site-specific,
// so they come from config rather than a shipped pack.
func internalDomainRule(domains []string) *Rule {
	var clean []string
	for _, d := range domains {
		d = strings.TrimSpace(strings.TrimPrefix(d, "."))
		if d != "" {
			clean = append(clean, regexp.QuoteMeta(d))
		}
	}
	if len(clean) == 0 {
		return nil
	}
	return &Rule{
		Name:        "internal_hostname",
		Category:    CategoryNetwork,
		Priority:    75,
		Pattern:     `\b[A-Za-z0-9][A-Za-z0-9\-]*(?:\.[A-Za-z0-9][A-Za-z0-9\-]*)*\.(?:` + strings.Join(clean, "|") + `)\b`,
		Description: "hostname under a configured internal domain suffix",
	}
}
