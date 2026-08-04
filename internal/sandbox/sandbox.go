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
	segs := extractExecutable(text)
	if len(segs) == 0 {
		return Verdict{}
	}

	var v Verdict
	for _, seg := range segs {
		cmds := splitCommands(seg.Text)
		for _, r := range g.rules {
			// Info-severity matches are still recorded: they carry no action
			// but are useful in the audit trail.
			sev := g.severityOf(r)
			if r.MatchSegment != nil && r.MatchSegment(seg) {
				v.add(Finding{
					Rule: r.Name, Severity: sev.String(), Match: trim(seg.Text),
					Description: r.Description, Scope: scopeName(seg.Scope),
				}, sev)
			}
			if r.MatchCommand == nil {
				continue
			}
			for _, c := range cmds {
				if r.MatchCommand(c) {
					v.add(Finding{
						Rule: r.Name, Severity: sev.String(), Match: trim(c.Raw),
						Description: r.Description, Scope: scopeName(seg.Scope), Argv: c.Argv,
					}, sev)
				}
			}
		}
	}

	sort.SliceStable(v.Findings, func(i, j int) bool {
		return severityRank(v.Findings[i].Severity) > severityRank(v.Findings[j].Severity)
	})
	return v
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
