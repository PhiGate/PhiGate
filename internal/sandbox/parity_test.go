package sandbox

import (
	"strings"
	"testing"
)

// The guard has two entry points and they must agree.
//
// A blocking response is inspected whole: handler.go calls Guard.Inspect on the
// entire hydrated answer. A streamed response is inspected by StreamScanner as
// it arrives. If those two disagree, then whether a catastrophic command reaches
// the operator depends on whether the client passed "stream": true — which is a
// client's performance preference, not a security decision, and not something an
// operator can see in an audit log after the fact.
//
// "Catastrophic commands never reach the operator" is one of the guarantees
// PhiGate is sold on, so the two paths agreeing is itself a guarantee and
// belongs in `make guarantees`.

// streamVerdict runs text through a StreamScanner in the given chunks and
// reports what the streaming path concluded, plus everything it let through.
func streamVerdict(t *testing.T, chunks []string) (Verdict, string) {
	t.Helper()

	var emitted strings.Builder
	var got Verdict
	sc := NewStreamScanner(NewGuard(), nil,
		func(s string) error { emitted.WriteString(s); return nil },
		func(v Verdict) error { got = v; return nil },
	)
	for _, c := range chunks {
		if err := sc.Write(c); err != nil {
			t.Fatalf("Write(%q): %v", c, err)
		}
	}
	if err := sc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return got, emitted.String()
}

// byLine splits an answer the way a model actually emits it — a chunk per line,
// newline retained. Any splitting must give the same verdict; this one is just
// the most realistic.
func byLine(answer string) []string {
	parts := strings.SplitAfter(answer, "\n")
	if last := len(parts) - 1; last >= 0 && parts[last] == "" {
		parts = parts[:last]
	}
	return parts
}

func TestStreamingAgreesWithBlockingPath(t *testing.T) {
	cases := []struct {
		name   string
		answer string
		why    string
	}{
		{
			name: "fenced command invoked by absolute path",
			answer: "Clear the failed array first:\n\n" +
				"```bash\n" +
				"/usr/local/bin/mkfs.ext4 /dev/sda1\n" +
				"```\n",
			why: "inside a fence the blocking path lexes every line as code; the " +
				"streaming path sees one line with no fence context, and the " +
				"outside-a-fence path gates on isKnownBinary, which an absolute " +
				"path is not",
		},
		{
			name: "fork bomb split across lines inside a fence",
			answer: "Reproduce the resource exhaustion with:\n\n" +
				"```sh\n" +
				":(){\n" +
				" :|:& };:\n" +
				"```\n",
			why: "fork_bomb is a MatchSegment rule matched against whole-segment " +
				"text, so a construct spanning two lines is only visible when the " +
				"fence body is inspected as one segment",
		},
		{
			name: "block device redirect split across lines inside a fence",
			answer: "```bash\n" +
				"dd if=/dev/zero \\\n" +
				"  of=/dev/sda\n" +
				"```\n",
			why: "write_block_device matches the segment text; a line-at-a-time " +
				"scanner never sees the redirect and its target together",
		},
		{
			name:   "unfenced rm -rf / still blocks on both paths",
			answer: "Do not run rm -rf / on that host.\n",
			why:    "the control: this one already agrees, and must keep agreeing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := NewGuard().Inspect(tc.answer)
			got, emitted := streamVerdict(t, byLine(tc.answer))

			if got.Blocked != want.Blocked {
				t.Errorf("streaming and blocking paths disagree: streamed Blocked=%v, whole-answer Blocked=%v (rule %q)\n%s",
					got.Blocked, want.Blocked, want.Rule, tc.why)
			}
			if want.Blocked && got.Rule != want.Rule {
				t.Errorf("blocked by different rules: streamed %q, whole-answer %q", got.Rule, want.Rule)
			}
			// The verdict agreeing is not enough on its own. What matters to an
			// operator is that the dangerous text did not arrive.
			if want.Blocked {
				for _, line := range strings.Split(tc.answer, "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "```") {
						continue
					}
					if strings.Contains(emitted, line) && isDangerous(line) {
						t.Errorf("streaming path emitted text the blocking path withholds: %q", line)
					}
				}
			}
		})
	}
}

// isDangerous reports whether a line is one the guard is expected to withhold,
// so assertions about released text do not fire on the surrounding prose. It is
// deliberately a fragment list rather than a second guard implementation: a
// helper that reimplemented the rules would agree with them by construction and
// prove nothing.
func isDangerous(line string) bool {
	for _, frag := range []string{
		"mkfs", "dd ", "of=/dev/", "> /dev/", ":|:&", ":(){",
		"rm -rf", "rm -f -r", "rm --force", "rm -fr",
		"chmod -R", "chown -R", "| sudo bash", "iptables -F",
		"DROP TABLE", "DELETE FROM", "-delete", "terraform destroy",
	} {
		if strings.Contains(line, frag) {
			return true
		}
	}
	return false
}
