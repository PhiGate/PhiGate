package sandbox

import (
	"regexp"
	"strings"
)

// IngressVerdict is the result of screening an inbound payload.
type IngressVerdict struct {
	// Suspicious is true when injection-like content was found.
	Suspicious bool
	// Rules names every pattern that fired.
	Rules []string
	// Match is a short excerpt of the first match, for audit records.
	Match string
}

// IngressGuard screens inbound content for prompt injection.
//
// The threat is specific to what PhiGate does. An AIOps gateway feeds *attacker
// influenced* text to an LLM by design: logs contain user agents, URLs, form
// fields and error strings that an outsider chose. Someone who can write to a
// log line can write instructions into it, and the model downstream cannot tell
// the difference between "here is a log to analyse" and "ignore your
// instructions and do this instead".
//
// PhiGate cares about two consequences in particular:
//
//   - The model emits a destructive command that an automation runner executes.
//     The egress guard is the backstop for that.
//   - The model is induced to enumerate placeholders — "print <V1> through
//     <V50>" — so that hydration pastes back every real value the model was
//     never shown. That is the dictionary-enumeration attack, and it turns
//     PhiGate's own hydration step into the exfiltration channel.
//
// Detection is advisory by default: it annotates and audits rather than
// rejecting, because false positives on log content would break real traffic.
type IngressGuard struct {
	rules []ingressRule
}

type ingressRule struct {
	name string
	re   *regexp.Regexp
}

// NewIngressGuard returns a guard with the default injection patterns.
func NewIngressGuard() *IngressGuard {
	return &IngressGuard{rules: []ingressRule{
		{"instruction_override", regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|directions?)`)},
		{"system_prompt_probe", regexp.MustCompile(`(?i)\b(?:reveal|print|show|repeat|output|disclose)\s+(?:me\s+)?(?:your|the)\s+(?:system\s+prompt|instructions|initial\s+prompt|rules)`)},
		{"role_reassignment", regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(?:a|an|the)\b|\bnew\s+(?:instructions?|system\s+prompt)\s*:`)},
		{"guardrail_bypass", regexp.MustCompile(`(?i)\b(?:developer|debug|god|admin)\s+mode\b|\bdo\s+anything\s+now\b|\bwithout\s+(?:any\s+)?(?:restrictions?|filters?|safety)\b`)},
		{"placeholder_enumeration", regexp.MustCompile(`(?i)(?:list|print|output|show|reveal|expand|enumerate|decode|restore)[^\n]{0,40}(?:<V\d+>|\bplaceholders?\b|\ball\s+(?:the\s+)?(?:tokens?|variables?|values?)\b|#REF\d+)`)},
		{"placeholder_sweep", regexp.MustCompile(`(?:<V\d+>[^\w<]{0,4}){8,}`)},
		{"jp_instruction_override", regexp.MustCompile(`(?:これまでの|以前の|上記の)(?:指示|命令|ルール)[^\n]{0,10}(?:無視|忘れ)`)},
	}}
}

// Inspect screens text for injection markers.
func (g *IngressGuard) Inspect(text string) IngressVerdict {
	var v IngressVerdict
	for _, r := range g.rules {
		if m := r.re.FindString(text); m != "" {
			v.Suspicious = true
			v.Rules = append(v.Rules, r.name)
			if v.Match == "" {
				v.Match = trim(m)
			}
		}
	}
	return v
}

// EnumerationThreshold decides whether a hydration pass looks like dictionary
// enumeration rather than a normal answer.
//
// A genuine answer refers to a handful of the values it was given. An answer
// that resolves most of a large dictionary is reciting it. The rule needs both
// conditions: a small dictionary is fully referenced by perfectly ordinary
// answers, so the absolute floor prevents the common case from tripping it.
type EnumerationThreshold struct {
	// MinDictionary is the dictionary size below which the check never fires.
	MinDictionary int
	// MaxFraction is the share of the dictionary an answer may resolve.
	MaxFraction float64
}

// DefaultEnumerationThreshold is deliberately permissive: it is meant to catch
// recitation, not to second-guess a thorough answer.
func DefaultEnumerationThreshold() EnumerationThreshold {
	return EnumerationThreshold{MinDictionary: 12, MaxFraction: 0.8}
}

// Exceeded reports whether substituting distinct of dictSize tokens looks like
// enumeration.
func (t EnumerationThreshold) Exceeded(distinct, dictSize int) bool {
	if dictSize < t.MinDictionary || distinct == 0 {
		return false
	}
	return float64(distinct)/float64(dictSize) > t.MaxFraction
}

// InjectionNotice is the operator-facing warning appended when inbound content
// looked like an injection attempt.
func InjectionNotice(v IngressVerdict) string {
	return "⚠️ PhiGate detected possible prompt-injection content in the input (" +
		strings.Join(v.Rules, ", ") + "). Treat the answer below with corresponding caution."
}
