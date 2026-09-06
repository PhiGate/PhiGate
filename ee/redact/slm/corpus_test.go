// SPDX-License-Identifier: BUSL-1.1

package slm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phigate/phigate/internal/redact"
)

// TestCommunityLeakCorpusPassesUnchanged runs the community edition's own leak
// corpus through the enterprise detector.
//
// This is the load-bearing test of the whole package. ee/README.md's rule is
// that an EE detector wraps CE's rather than replacing it, because one that
// could find *less* would quietly weaken the guarantee CE's corpus is written
// against. A comment saying so is worth nothing; running the corpus is worth
// something.
//
// The recognizer used here claims every candidate it is offered, which is the
// adversarial case: a maximally greedy name detector must still not displace a
// single credential, My Number or hostname the regex engine found.
func TestCommunityLeakCorpusPassesUnchanged(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "internal", "redact", "testdata")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("community corpus not readable: %v", err)
	}

	eng, err := redact.NewEngine(redact.Options{InternalDomains: []string{"corp", "internal"}})
	if err != nil {
		t.Fatal(err)
	}
	greedy := recognizerFunc(func(_ context.Context, _ string, cands []Span) ([]Span, error) {
		return cands, nil
	})
	d, err := New(Options{Engine: eng, Recognizer: greedy, MaxCandidates: 1000})
	if err != nil {
		t.Fatal(err)
	}

	files := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		files++
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			want := eng.Detect(line)
			_, got := d.Redact(line, mask)

			for _, w := range want {
				if !containsFinding(got, w) {
					t.Fatalf("%s: EE lost a CE finding\n  line: %q\n  lost: %s [%d,%d) %q",
						e.Name(), line, w.Rule, w.Start, w.End, w.Text)
				}
			}
		}
	}
	if files == 0 {
		t.Skip("no corpus files found")
	}
	t.Logf("every community finding survived across %d corpus file(s)", files)
}

func containsFinding(set []redact.Finding, want redact.Finding) bool {
	for _, f := range set {
		if f.Start == want.Start && f.End == want.End && f.Rule == want.Rule {
			return true
		}
	}
	return false
}
