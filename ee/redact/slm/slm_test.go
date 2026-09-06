// SPDX-License-Identifier: BUSL-1.1

package slm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/phigate/phigate/internal/redact"
)

// fakeRecognizer accepts the candidates whose text is in accept.
type fakeRecognizer struct {
	accept map[string]bool
	err    error
	calls  int
	seen   []string
}

// Names models the documented contract: a recognizer may return a span narrower
// than the candidate it was offered, since the candidate is the widest
// plausible extent and deciding where the name actually ends is its job.
func (f *fakeRecognizer) Names(_ context.Context, text string, cands []Span) ([]Span, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	var out []Span
	for _, c := range cands {
		s := text[c.Start:c.End]
		f.seen = append(f.seen, s)
		for want := range f.accept {
			if i := strings.Index(s, want); i >= 0 {
				out = append(out, Span{Start: c.Start + i, End: c.Start + i + len(want)})
				break
			}
		}
	}
	return out, nil
}

func newDetector(t *testing.T, rec Recognizer) *Detector {
	t.Helper()
	eng, err := redact.NewEngine(redact.Options{InternalDomains: []string{"corp", "internal"}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(Options{Engine: eng, Recognizer: rec})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// mask is a replacement that makes each finding visible in the output.
func mask(f redact.Finding) string { return "<" + f.Rule + ">" }

// TestDetectsEverythingTheCommunityEngineDoes is the superset property, and the
// reason composition is the rule rather than a preference. A detector that
// could find less than CE's would quietly weaken the guarantee CE's own leak
// corpus is written against.
func TestDetectsEverythingTheCommunityEngineDoes(t *testing.T) {
	eng, err := redact.NewEngine(redact.Options{InternalDomains: []string{"corp", "internal"}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(Options{
		Engine: eng,
		// A recognizer that claims everything, which is the worst case for the
		// property: it must still not displace a single CE finding.
		Recognizer: &fakeRecognizer{accept: map[string]bool{}},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, text := range []string{
		"disk full on 10.0.0.5 and web-1.corp",
		"従業員の個人番号 1234 5678 9018 が登録できません",
		"contact tanaka@example.com about ticket 550e8400-e29b-41d4-a716-446655440000",
		"db.Open(\"postgres://svc:Hx7kQ2mZpW@db1/app\")",
		"佐藤太郎の個人番号は 1234 5678 9018 です",
		"AKIAIOSFODNN7EXAMPLE and 192.168.1.1",
		"no sensitive data here at all",
	} {
		want := eng.Detect(text)
		_, got := d.Redact(text, mask)

		for _, w := range want {
			found := false
			for _, g := range got {
				if g.Start == w.Start && g.End == w.End && g.Rule == w.Rule {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("EE lost a CE finding in %q: %s at [%d,%d) %q",
					text, w.Rule, w.Start, w.End, w.Text)
			}
		}
	}
}

// TestFindsANameTheRegexEngineCannot is what the layer is for. jp.json's
// jp_name_kanji is disabled by default and says why: free-form kanji names
// cannot be decided by pattern.
func TestFindsANameTheRegexEngineCannot(t *testing.T) {
	rec := &fakeRecognizer{accept: map[string]bool{"田中太郎": true}}
	d := newDetector(t, rec)

	const text = "担当は田中太郎です"
	out, found := d.Redact(text, mask)

	if !strings.Contains(out, "<"+RuleName+">") {
		t.Fatalf("the name was not masked: %q (findings %+v)", out, found)
	}
	if strings.Contains(out, "田中太郎") {
		t.Errorf("the name survived in the output: %q", out)
	}
	if len(found) != 1 || found[0].Category != redact.CategoryPII {
		t.Errorf("finding = %+v, want one PII finding", found)
	}
}

// TestOrdinaryProseIsNotMasked is the counterpart, and the failure mode
// jp.json declined to ship. A gazetteer hit is a candidate, not a name.
func TestOrdinaryProseIsNotMasked(t *testing.T) {
	// The recognizer rejects everything, which is what it should do for text
	// where the surname characters are not a person.
	rec := &fakeRecognizer{accept: map[string]bool{}}
	d := newDetector(t, rec)

	for _, text := range []string{
		"田中さんの件は林の中で解決した",  // place/word uses
		"森ビルの前で待ち合わせ",      // company name containing a surname
		"高橋を渡って右に曲がってください", // a bridge, not a person
	} {
		out, found := d.Redact(text, mask)
		if strings.Contains(out, RuleName) {
			t.Errorf("ordinary prose was masked as a name: %q -> %q (%+v)", text, out, found)
		}
	}
	if rec.calls == 0 {
		t.Error("the recognizer was never consulted; the gazetteer found no candidates at all")
	}
}

// TestRecognizerFailureFallsBackToTheCommunityEngine. Detection degrading is
// acceptable; a request failing because a name detector timed out is not.
func TestRecognizerFailureFallsBackToTheCommunityEngine(t *testing.T) {
	rec := &fakeRecognizer{err: errors.New("model unavailable")}
	d := newDetector(t, rec)

	const text = "担当は田中太郎、host は web-1.corp です"
	out, found := d.Redact(text, mask)

	if strings.Contains(out, "web-1.corp") {
		t.Errorf("CE detection stopped working when the recognizer failed: %q", out)
	}
	if strings.Contains(out, RuleName) {
		t.Errorf("a name was masked despite the recognizer failing: %q", out)
	}
	if len(found) == 0 {
		t.Error("no findings at all; the fallback lost CE's detection entirely")
	}
	if got := d.Stats().Degraded; got != 1 {
		t.Errorf("Stats().Degraded = %d, want 1 — a silent degradation is one "+
			"nobody can alert on", got)
	}
}

// TestNoRecognizerIsExactlyTheCommunityEngine: with the layer disabled the
// detector must be indistinguishable from CE, so a deployment can turn it off
// and know what it has.
func TestNoRecognizerIsExactlyTheCommunityEngine(t *testing.T) {
	eng, err := redact.NewEngine(redact.Options{InternalDomains: []string{"corp"}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(Options{Engine: eng})
	if err != nil {
		t.Fatal(err)
	}

	const text = "担当は田中太郎、host は web-1.corp、個人番号 1234 5678 9018"
	wantOut, wantFound := eng.Redact(text, mask)
	gotOut, gotFound := d.Redact(text, mask)

	if gotOut != wantOut {
		t.Errorf("output differs from CE:\n got %q\nwant %q", gotOut, wantOut)
	}
	if len(gotFound) != len(wantFound) {
		t.Errorf("finding count %d, want CE's %d", len(gotFound), len(wantFound))
	}
	if len(d.Rules()) != len(eng.Rules()) {
		t.Error("the disabled layer still advertises a rule")
	}
}

// TestRuleIsAdvertised: /v1/phigate/rules is what an auditor reads to confirm
// what is enforced, and a detector contributing findings without appearing
// there would be a control nobody can see.
func TestRuleIsAdvertised(t *testing.T) {
	d := newDetector(t, &fakeRecognizer{accept: map[string]bool{}})
	for _, r := range d.Rules() {
		if r.Name == RuleName {
			if r.Description == "" {
				t.Error("the rule is advertised without a description")
			}
			return
		}
	}
	t.Fatalf("%s is not in Rules()", RuleName)
}

// TestCommunityFindingWinsAConflict: if the regex says a twelve-digit string is
// a My Number and the model says it is part of a name, the deterministic,
// check-digit-validated rule wins.
func TestCommunityFindingWinsAConflict(t *testing.T) {
	// A recognizer that tries to claim the whole text, My Number included.
	greedy := recognizerFunc(func(_ context.Context, text string, _ []Span) ([]Span, error) {
		return []Span{{Start: 0, End: len(text)}}, nil
	})
	d := newDetector(t, greedy)

	const text = "佐藤太郎 1234 5678 9018"
	_, found := d.Redact(text, mask)

	sawMyNumber := false
	for _, f := range found {
		if f.Rule == "jp_mynumber" {
			sawMyNumber = true
		}
	}
	if !sawMyNumber {
		t.Fatalf("the model's span displaced the My Number rule: %+v", found)
	}
}

type recognizerFunc func(context.Context, string, []Span) ([]Span, error)

func (f recognizerFunc) Names(ctx context.Context, text string, c []Span) ([]Span, error) {
	return f(ctx, text, c)
}

// TestOutOfRangeSpansAreIgnored: a recognizer is an untrusted component, and a
// span outside the text would panic the slicing that builds a finding.
func TestOutOfRangeSpansAreIgnored(t *testing.T) {
	bad := recognizerFunc(func(_ context.Context, text string, _ []Span) ([]Span, error) {
		return []Span{
			{Start: -5, End: 3},
			{Start: 0, End: len(text) + 100},
			{Start: 4, End: 2},
		}, nil
	})
	d := newDetector(t, bad)

	out, found := d.Redact("担当は田中太郎です", mask)
	if strings.Contains(out, RuleName) {
		t.Errorf("an out-of-range span was masked: %q (%+v)", out, found)
	}
}

// TestCandidatesCoverTheGivenName: masking only the surname leaves half the
// value in the text.
func TestCandidatesCoverTheGivenName(t *testing.T) {
	g := newGazetteer(DefaultSurnames())
	const text = "担当は田中太郎です"
	cands := g.candidates(text)
	if len(cands) == 0 {
		t.Fatal("no candidate for a text containing a listed surname")
	}
	got := text[cands[0].Start:cands[0].End]
	if !strings.HasPrefix(got, "田中") {
		t.Fatalf("candidate = %q, want it to start at the surname", got)
	}
	if got == "田中" {
		t.Error("the candidate stops at the surname; the given name would survive masking")
	}
}

// TestCandidatesStopAtNonNameCharacters keeps a span from swallowing a
// sentence, which would leave the model only wrong answers to give.
func TestCandidatesStopAtNonNameCharacters(t *testing.T) {
	g := newGazetteer([]string{"田中"})
	for _, tc := range []struct{ text, want string }{
		{"田中 太郎", "田中 太郎"}, // one space joins a surname to a given name
		{"田中(営業)", "田中"},   // punctuation ends it
		{"田中123", "田中"},    // digits end it
		{"田中さんが", "田中さん"},  // kana continue it; the particle ends it
		{"田中太郎です", "田中太郎"}, // the copula is grammar, not a name
		{"田中 ", "田中"},      // a trailing space is not part of a name
	} {
		cands := g.candidates(tc.text)
		if len(cands) == 0 {
			t.Errorf("%q: no candidate", tc.text)
			continue
		}
		if got := tc.text[cands[0].Start:cands[0].End]; got != tc.want {
			t.Errorf("%q: candidate = %q, want %q", tc.text, got, tc.want)
		}
	}
}

func TestParseIndices(t *testing.T) {
	for _, tc := range []struct {
		reply string
		want  int
		bad   bool
	}{
		{`{"names":[0,2]}`, 2, false},
		{"Sure!\n```json\n{\"names\":[1]}\n```", 1, false},
		{`{"names":[]}`, 0, false},
		{`I could not determine any names.`, 0, true},
		{`{"names":"all of them"}`, 0, true},
	} {
		got, err := parseIndices(tc.reply)
		if tc.bad {
			if err == nil {
				t.Errorf("parseIndices(%q) accepted an unusable reply", tc.reply)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseIndices(%q): %v", tc.reply, err)
			continue
		}
		if len(got) != tc.want {
			t.Errorf("parseIndices(%q) = %v, want %d indices", tc.reply, got, tc.want)
		}
	}
}

// TestMaxCandidatesBoundsThePrompt: a pathological payload must not turn one
// request into an unbounded prompt to the model.
func TestMaxCandidatesBoundsThePrompt(t *testing.T) {
	eng, err := redact.NewEngine(redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rec := &fakeRecognizer{accept: map[string]bool{}}
	d, err := New(Options{Engine: eng, Recognizer: rec, MaxCandidates: 3})
	if err != nil {
		t.Fatal(err)
	}

	d.Redact(strings.Repeat("田中 ", 50), mask)
	if len(rec.seen) > 3 {
		t.Errorf("recognizer was given %d candidates, want at most 3", len(rec.seen))
	}
}

func TestEngineIsRequired(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("a detector was built with no community engine to compose with")
	}
}
