package sandbox

import (
	"strings"
	"testing"
)

// diskFullAnswer is the shape that motivated Redact: a real remediation answer
// where the dangerous command is one step out of four, in its own fence.
const diskFullAnswer = "Here is a safe sequence to reclaim space in /var.\n" +
	"\n" +
	"### 1. Find the big consumers\n" +
	"```bash\n" +
	"du -xh /var --max-depth=2 | sort -rh | head -20\n" +
	"```\n" +
	"\n" +
	"### 2. Check for deleted-but-open files\n" +
	"```bash\n" +
	"lsof +L1 | grep /var\n" +
	"```\n" +
	"\n" +
	"### 3. Reclaim it\n" +
	"```bash\n" +
	"find /var -type f -name '*.log' -delete\n" +
	"```\n" +
	"\n" +
	"Rotate logs afterwards so this does not recur.\n"

// TestRedactKeepsTheAnswerAndDropsTheCommand.
//
// The whole point: an operator with a service down should still get the
// investigation steps. Withholding the response wholesale cost 7.4 points out
// of 10 on this case in the eval, which is what a wall looks like when it is
// measured instead of argued about.
func TestRedactKeepsTheAnswerAndDropsTheCommand(t *testing.T) {
	out, v := NewGuard().Redact(diskFullAnswer)

	if !v.Blocked {
		t.Fatal("the dangerous command was not blocked at all")
	}
	for _, keep := range []string{
		"du -xh /var",
		"lsof +L1",
		"Rotate logs afterwards",
		"### 1. Find the big consumers",
	} {
		if !strings.Contains(out, keep) {
			t.Errorf("redaction dropped safe content: %q", keep)
		}
	}
	if strings.Contains(out, "-delete") {
		t.Error("the blocked command survived redaction")
	}
	if !strings.Contains(out, "PhiGate withheld") {
		t.Error("no notice was left where the command had been")
	}
}

// TestRedactedOutputIsNeverBlocked is the safety property. Whatever Redact
// returns must be clean, or the caller has an answer that looks vetted and is
// not.
func TestRedactedOutputIsNeverBlocked(t *testing.T) {
	g := NewGuard()
	for name, in := range map[string]string{
		"disk full":        diskFullAnswer,
		"bare rm":          "```\nrm -rf /\n```",
		"long flags":       "```\nrm --force --recursive /\n```",
		"split flags":      "```sh\nrm -f -r /var/lib\n```",
		"find delete":      "```\nfind / -delete\n```",
		"inline":           "Run `rm -rf /` to fix it.",
		"command line":     "sudo rm -rf /var/lib\n",
		"two fences":       "```\nrm -rf /\n```\ntext\n```\nfind / -delete\n```",
		"unterminated":     "```\nrm -rf /",
		"prose only":       "If that fails, reboot the node and check SIGTERM handling.",
		"empty":            "",
		"notice lookalike": "⛔ [PhiGate withheld 1 line — rule: rm_rf_root]",
	} {
		t.Run(name, func(t *testing.T) {
			out, _ := g.Redact(in)
			if after := g.Inspect(out); after.Blocked {
				t.Errorf("redacted output is still blocked by %s\n--- in ---\n%s\n--- out ---\n%s",
					after.Rule, in, out)
			}
		})
	}
}

// TestRedactLeavesCleanTextAlone. A guard that rewrites safe answers is a guard
// that gets switched off just as fast as one that blocks them.
func TestRedactLeavesCleanTextAlone(t *testing.T) {
	for _, in := range []string{
		"If that fails, reboot the node.",
		"```bash\ndu -xh /var | sort -rh\n```",
		"Graceful shutdown is configured via SIGTERM.",
	} {
		out, v := NewGuard().Redact(in)
		if v.Blocked {
			t.Errorf("clean text was blocked: %q", in)
		}
		if out != in {
			t.Errorf("clean text was modified\n want: %q\n  got: %q", in, out)
		}
	}
}

// TestRedactAgreesWithInspect. The two share an evaluation path so that a
// redaction can never remove a different span from the one the verdict named.
func TestRedactAgreesWithInspect(t *testing.T) {
	g := NewGuard()
	for _, in := range []string{diskFullAnswer, "```\nrm -rf /\n```", "prose only", ""} {
		_, got := g.Redact(in)
		want := g.Inspect(in)
		if got.Blocked != want.Blocked || got.Rule != want.Rule || got.Severity != want.Severity {
			t.Errorf("verdicts differ for %q:\n Redact:  blocked=%v rule=%q sev=%v\n Inspect: blocked=%v rule=%q sev=%v",
				in, got.Blocked, got.Rule, got.Severity, want.Blocked, want.Rule, want.Severity)
		}
		if len(got.Findings) != len(want.Findings) {
			t.Errorf("finding counts differ for %q: Redact %d, Inspect %d",
				in, len(got.Findings), len(want.Findings))
		}
	}
}

// FuzzRedactedOutputIsNeverBlocked runs the safety property over arbitrary
// input. A redaction that leaves something executable behind is the one failure
// mode that matters here, and it is not the kind to be established by example.
func FuzzRedactedOutputIsNeverBlocked(f *testing.F) {
	for _, seed := range []string{
		diskFullAnswer, "```\nrm -rf /\n```", "`rm -rf /`", "find / -delete",
		"```\n", "```\n```", "~~~\nmkfs.ext4 /dev/sda\n~~~", "",
	} {
		f.Add(seed)
	}
	g := NewGuard()
	f.Fuzz(func(t *testing.T, in string) {
		out, v := g.Redact(in)
		if !v.Blocked {
			if out != in {
				t.Fatalf("unblocked input was modified\n in: %q\nout: %q", in, out)
			}
			return
		}
		if after := g.Inspect(out); after.Blocked {
			t.Fatalf("redacted output still blocked by %s\n in: %q\nout: %q", after.Rule, in, out)
		}
	})
}
