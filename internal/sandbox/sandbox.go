// Package sandbox implements PhiGate's Dynamic Security Sandbox: the egress
// guardrail that inspects model output and blocks high-risk, destructive
// commands before they ever reach an operator or an automation runner.
//
// Detection is deterministic and rule-based (no model in the loop) so the
// guarantee is auditable: a command is blocked because a named rule matched,
// and that rule name is reported. The default rule set is intentionally
// conservative and easily extended for an enterprise's own policy.
package sandbox

import "regexp"

// Rule is a named destructive-command pattern.
type Rule struct {
	Name    string
	Pattern *regexp.Regexp
}

// Verdict is the result of inspecting a span of model output.
type Verdict struct {
	Blocked bool
	Rule    string // name of the rule that fired
	Match   string // the offending substring (for audit logs)
}

// Guard inspects text and decides whether it is safe to emit.
type Guard interface {
	Inspect(text string) Verdict
}

// RuleGuard is the default deterministic Guard.
type RuleGuard struct {
	rules []Rule
}

// NewGuard returns a RuleGuard loaded with DefaultRules.
func NewGuard() *RuleGuard { return &RuleGuard{rules: DefaultRules()} }

// NewGuardWith returns a RuleGuard with a custom rule set (used in tests).
func NewGuardWith(rules ...Rule) *RuleGuard { return &RuleGuard{rules: rules} }

// Inspect returns the first rule that matches text.
func (g *RuleGuard) Inspect(text string) Verdict {
	for _, r := range g.rules {
		if m := r.Pattern.FindString(text); m != "" {
			return Verdict{Blocked: true, Rule: r.Name, Match: m}
		}
	}
	return Verdict{}
}

// Rules exposes the configured rules (for introspection/debug).
func (g *RuleGuard) Rules() []Rule { return g.rules }

// DefaultRules is PhiGate's baseline destructive-command deny list. It is not
// exhaustive — it targets unambiguously catastrophic operations that should
// never be auto-executed against production infrastructure.
func DefaultRules() []Rule {
	return []Rule{
		// Recursive force delete: rm -rf / rm -fr (flags combined).
		{"rm_recursive_force", regexp.MustCompile(`(?i)\brm\s+(?:-[\w-]+\s+)*-[\w]*(?:rf|fr)[\w]*`)},
		// Recursive + force expressed as separate flags / long options.
		{"rm_recursive_force_split", regexp.MustCompile(`(?i)\brm\s+(?:-{1,2}[\w-]+\s+)*--?r(?:ecursive)?\b.*--?f(?:orce)?\b`)},
		// Filesystem creation over an existing device.
		{"mkfs", regexp.MustCompile(`(?i)\bmkfs(?:\.\w+)?\s+/dev/`)},
		// Raw disk overwrite.
		{"dd_to_device", regexp.MustCompile(`(?i)\bdd\b[^\n]*\bof=/dev/`)},
		// Redirect into a block device.
		{"write_block_device", regexp.MustCompile(`>\s*/dev/(?:sd|nvme|hd|vd|mmcblk)`)},
		// Classic fork bomb.
		{"fork_bomb", regexp.MustCompile(`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`)},
		// Recursive chmod/chown rooted at /.
		{"recursive_perm_root", regexp.MustCompile(`(?i)\bch(?:mod|own)\s+(?:-[\w-]+\s+)*-[\w]*R[\w]*\s+\S+\s+/(?:\s|$)`)},
		// Pipe a download straight into a shell.
		{"pipe_to_shell", regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|d)?sh\b`)},
		// Host power state changes.
		{"host_power_state", regexp.MustCompile(`(?i)\b(?:shutdown|reboot|poweroff|halt)\b|\binit\s+0\b`)},
		// Destructive SQL.
		{"sql_drop", regexp.MustCompile(`(?i)\bdrop\s+(?:table|database|schema)\b`)},
		{"sql_truncate", regexp.MustCompile(`(?i)\btruncate\s+table\b`)},
		// Wipe-all operations on orchestration/firewall state.
		{"kubectl_delete_all", regexp.MustCompile(`(?i)\bkubectl\s+delete\b[^\n]*--all\b`)},
		{"iptables_flush", regexp.MustCompile(`(?i)\biptables\s+-F\b`)},
	}
}
