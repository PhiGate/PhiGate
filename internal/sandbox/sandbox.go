// Package sandbox implements PhiGate's Dynamic Security Sandbox: the egress
// guardrail that inspects model output before it reaches an operator or an
// automation runner.
//
// Detection is deterministic — no model in the loop — so every block is
// attributable to a named rule, which is what an auditor needs.
//
// Two design decisions distinguish this from a regex deny list:
//
//  1. **Scope.** Rules run only against text that could plausibly be executed:
//     fenced code, inline code, and prose lines that are unambiguously commands.
//     The previous version matched the whole answer, so "reboot the node" and
//     "graceful shutdown is configured via SIGTERM" were blocked as destructive
//     commands. A guard that fires on prose gets turned off, and a guard that is
//     turned off protects nothing.
//
//  2. **Structure.** Commands are lexed into argv and matched on program and
//     flags rather than on surface text. The previous version caught "rm -rf"
//     but let "rm -f -r /var/lib" and "rm --force --recursive /" through.
//
// Severity replaces the old binary block/allow. Most destructive-looking
// operations are legitimate remediations in context; blocking all of them is
// what made operators disable the guard. Only unambiguously catastrophic
// operations block by default.
package sandbox

import (
	"fmt"
	"sort"
	"strings"
)

// Severity is how seriously the guard treats a matched rule.
type Severity int

const (
	// SeverityInfo records the match in audit logs and does nothing else.
	SeverityInfo Severity = iota
	// SeverityWarn annotates the response but still delivers it. This is the
	// right default for operations that are destructive but routinely correct,
	// like restarting a service.
	SeverityWarn
	// SeverityBlock withholds the content.
	SeverityBlock
)

// String renders a Severity for config and audit records.
func (s Severity) String() string {
	switch s {
	case SeverityBlock:
		return "block"
	case SeverityWarn:
		return "warn"
	default:
		return "info"
	}
}

// ParseSeverity maps a config string to a Severity.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "allow", "off":
		return SeverityInfo, true
	case "warn":
		return SeverityWarn, true
	case "block", "deny":
		return SeverityBlock, true
	}
	return SeverityInfo, false
}

// Rule is a named check over an extracted command or code segment.
type Rule struct {
	// Name identifies the rule in audit records.
	Name string
	// Severity is the action taken when the rule matches.
	Severity Severity
	// Description explains, in operator language, why this is dangerous.
	Description string
	// MatchCommand inspects a lexed command. Either this or MatchSegment is set.
	MatchCommand func(Command) bool
	// MatchSegment inspects raw segment text, for rules that are not about a
	// single command — SQL statements and fork bombs.
	MatchSegment func(Segment) bool
}

// Verdict is the result of inspecting a span of model output.
type Verdict struct {
	// Blocked is true when a block-severity rule fired. It is the field the
	// streaming path and the response handler act on.
	Blocked bool
	// Rule is the name of the highest-severity rule that fired.
	Rule string
	// Match is the offending text, for audit logs.
	Match string
	// Severity is the highest severity observed.
	Severity Severity
	// Reason explains the verdict to the operator.
	Reason string
	// Findings lists every rule that fired, including warnings.
	Findings []Finding
}

// Finding is one rule match.
type Finding struct {
	Rule        string   `json:"rule"`
	Severity    string   `json:"severity"`
	Match       string   `json:"match"`
	Description string   `json:"description"`
	Scope       string   `json:"scope"`
	Argv        []string `json:"argv,omitempty"`
}

// Guard inspects text and decides whether it is safe to emit.
type Guard interface {
	Inspect(text string) Verdict
}

// RuleGuard is the default deterministic Guard.
type RuleGuard struct {
	rules     []Rule
	overrides map[string]Severity
}

// NewGuard returns a RuleGuard loaded with DefaultRules.
func NewGuard() *RuleGuard { return &RuleGuard{rules: DefaultRules()} }

// NewGuardWith returns a RuleGuard with a custom rule set (used in tests).
func NewGuardWith(rules ...Rule) *RuleGuard { return &RuleGuard{rules: rules} }

// WithOverrides returns a guard whose named rules use the given severities.
// This is how an enterprise tunes the guard to its own risk appetite — raising
// host_power_state to block in a change-controlled production environment, or
// lowering sql_truncate to warn in a data-engineering context — without
// forking the rule set.
func (g *RuleGuard) WithOverrides(o map[string]Severity) *RuleGuard {
	cp := &RuleGuard{rules: g.rules, overrides: map[string]Severity{}}
	for k, v := range o {
		cp.overrides[k] = v
	}
	return cp
}

// severityOf returns the effective severity for a rule.
func (g *RuleGuard) severityOf(r Rule) Severity {
	if g.overrides != nil {
		if s, ok := g.overrides[r.Name]; ok {
			return s
		}
	}
	return r.Severity
}

// Inspect evaluates every rule against the executable parts of text and returns
// the aggregate verdict.
func (g *RuleGuard) Inspect(text string) Verdict {
	var v Verdict
	g.eachFinding(text, func(_ Segment, f Finding, sev Severity) { v.add(f, sev) })
	sort.SliceStable(v.Findings, func(i, j int) bool {
		return severityRank(v.Findings[i].Severity) > severityRank(v.Findings[j].Severity)
	})
	return v
}

// eachFinding evaluates every rule against every executable segment of text and
// calls fn once per match.
//
// Inspect and Redact share it so the two can never disagree about what fired.
// A redaction that removed a different span from the one the verdict named
// would be the worst kind of bug here: the answer would look vetted and the
// dangerous line would still be in it.
func (g *RuleGuard) eachFinding(text string, fn func(Segment, Finding, Severity)) {
	for _, seg := range extractExecutable(text) {
		cmds := splitCommands(seg.Text)
		for _, r := range g.rules {
			// Info-severity matches are still recorded: they carry no action
			// but are useful in the audit trail.
			sev := g.severityOf(r)
			if r.MatchSegment != nil && r.MatchSegment(seg) {
				fn(seg, Finding{
					Rule: r.Name, Severity: sev.String(), Match: trim(seg.Text),
					Description: r.Description, Scope: scopeName(seg.Scope),
				}, sev)
			}
			if r.MatchCommand == nil {
				continue
			}
			for _, c := range cmds {
				if r.MatchCommand(c) {
					fn(seg, Finding{
						Rule: r.Name, Severity: sev.String(), Match: trim(c.Raw),
						Description: r.Description, Scope: scopeName(seg.Scope), Argv: c.Argv,
					}, sev)
				}
			}
		}
	}
}

// Redact returns text with the spans a blocking rule matched replaced by a
// notice, along with the verdict for the whole text.
//
// # Why this exists
//
// Withholding the entire response was measured against the eval corpus and cost
// 7.4 points out of 10 on disk-full-remediation: the model answered a full /var
// with a du hunt, an lsof check for deleted-but-open files, log rotation advice,
// and one `find ... -delete` rooted at a system directory. The guard was right
// about the last of those and threw away the other four with it, so an operator
// with a service down received a wall on the single most common emergency in
// the job. A guard that behaves that way is a guard that gets switched off, and
// a guard that is switched off protects nothing — the same reasoning that
// scoped the rules to code rather than prose in the first place.
//
// # Why a line is the unit
//
// The redaction unit is the whole segment the rules matched on, rounded out to
// its line boundaries, and never anything smaller. Cutting a matched command in
// half would be the one outcome worse than either blocking or allowing it. That
// the result is clean is not left to argument: [RuleGuard.Redact] is covered by
// a property test asserting that re-inspecting its output is never Blocked, run
// over the same fuzz corpus as the streaming scanner.
func (g *RuleGuard) Redact(text string) (string, Verdict) {
	var v Verdict
	// First blocked line of a span -> the rule that blocked it, and how far the
	// span reaches. Segments can overlap: two inline spans share a line, and a
	// fence covers many, so the widest reach for a given start wins.
	rule := map[int]string{}
	reach := map[int]int{}

	g.eachFinding(text, func(seg Segment, f Finding, sev Severity) {
		v.add(f, sev)
		if sev < SeverityBlock {
			return
		}
		end := seg.EndLine
		if end < seg.Line {
			end = seg.Line
		}
		if prev, seen := reach[seg.Line]; !seen || end > prev {
			reach[seg.Line] = end
			rule[seg.Line] = f.Rule
		}
	})

	sort.SliceStable(v.Findings, func(i, j int) bool {
		return severityRank(v.Findings[i].Severity) > severityRank(v.Findings[j].Severity)
	})
	if !v.Blocked {
		return text, v
	}

	lines := strings.Split(text, "\n")
	out := make([]string, 0, len(lines))
	for i := 0; i < len(lines); {
		end, blocked := reach[i]
		if !blocked {
			out = append(out, lines[i])
			i++
			continue
		}
		if end >= len(lines) {
			end = len(lines) - 1
		}
		out = append(out, withheldNotice(end-i+1, rule[i]))
		i = end + 1
	}
	return strings.Join(out, "\n"), v
}

// withheldNotice is what replaces a withheld span.
//
// It has to survive being fed back through the guard, so it is prose and opens
// with a character no command starts with.
func withheldNotice(lines int, rule string) string {
	unit := "lines"
	if lines == 1 {
		unit = "line"
	}
	return fmt.Sprintf("⛔ [PhiGate withheld %d %s — rule: %s]", lines, unit, rule)
}

func (v *Verdict) add(f Finding, sev Severity) {
	for _, existing := range v.Findings {
		if existing.Rule == f.Rule && existing.Match == f.Match {
			return // same rule, same text: report once
		}
	}
	v.Findings = append(v.Findings, f)
	if sev > v.Severity || v.Rule == "" {
		v.Severity = sev
		v.Rule = f.Rule
		v.Match = f.Match
		v.Reason = f.Description
	}
	if sev >= SeverityBlock {
		v.Blocked = true
	}
}

// Rules exposes the configured rules for introspection and the /rules endpoint.
func (g *RuleGuard) Rules() []Rule { return g.rules }

// Describe renders the effective rule set, so operators can see what is enforced.
func (g *RuleGuard) Describe() []string {
	out := make([]string, 0, len(g.rules))
	for _, r := range g.rules {
		out = append(out, fmt.Sprintf("%s=%s", r.Name, g.severityOf(r)))
	}
	sort.Strings(out)
	return out
}

func severityRank(s string) int {
	switch s {
	case "block":
		return 2
	case "warn":
		return 1
	}
	return 0
}

func scopeName(s Scope) string {
	switch s {
	case ScopeCode:
		return "code"
	case ScopeCommandLine:
		return "command_line"
	}
	return "prose"
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
