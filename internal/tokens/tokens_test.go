package tokens

import "testing"

// TestEstimateIsInTheRightRange checks the heuristic against hand-counted
// expectations. It is a sanity band, not an exact match: the estimator is
// documented as approximate, and pinning it to exact values would make it
// impossible to improve.
func TestEstimateIsInTheRightRange(t *testing.T) {
	c := NewHeuristic()
	cases := []struct {
		text     string
		min, max int
	}{
		{"hello world", 2, 4},
		{"the quick brown fox jumps over the lazy dog", 8, 14},
		{"2026-06-29T15:04:05Z ERROR connection refused 10.0.0.5:8080", 15, 32},
	}
	for _, tc := range cases {
		got := c.Estimate(tc.text)
		if got < tc.min || got > tc.max {
			t.Errorf("Estimate(%q) = %d, want between %d and %d", tc.text, got, tc.min, tc.max)
		}
	}
}

// TestCJKCostsMoreThanLatin is the check that matters for a Japan-first
// product: assuming 4 characters per token would understate Japanese prompt
// cost several-fold, and every savings figure derived from it would be wrong.
func TestCJKCostsMoreThanLatin(t *testing.T) {
	c := NewHeuristic()
	japanese := "決済システムでタイムアウトが多発しています"
	latin := "payment system is experiencing frequent"

	jp, en := c.Estimate(japanese), c.Estimate(latin)
	if jp <= en {
		t.Errorf("Japanese (%d chars -> %d tokens) should cost more than similar-length Latin text (%d chars -> %d tokens)",
			len([]rune(japanese)), jp, len([]rune(latin)), en)
	}
	if jp < len([]rune(japanese))/2 {
		t.Errorf("CJK estimate %d is far below one token per character for %d characters",
			jp, len([]rune(japanese)))
	}
}

func TestEstimateNeverZeroForNonEmpty(t *testing.T) {
	c := NewHeuristic()
	if c.Estimate("") != 0 {
		t.Error("empty string should estimate to 0")
	}
	if c.Estimate("x") < 1 {
		t.Error("non-empty input must estimate to at least 1")
	}
}

func TestPriceBookPrefersMostSpecificModel(t *testing.T) {
	b := NewPriceBook()
	mini, ok := b.Lookup("gpt-4o-mini")
	if !ok || mini.Model != "gpt-4o-mini" {
		t.Fatalf("gpt-4o-mini resolved to %+v (found=%v)", mini, ok)
	}
	dated, ok := b.Lookup("gpt-4o-2024-11-20")
	if !ok || dated.Model != "gpt-4o" {
		t.Errorf("dated model should inherit the base price, got %+v", dated)
	}
	if _, ok := b.Lookup("some-unlisted-model"); ok {
		t.Error("an unknown model should report as unpriced rather than matching something")
	}
}

// TestLedgerCountsAvoidedCloudCalls verifies the accounting that the savings
// claim rests on: a locally-served request avoids the entire cloud prompt cost,
// not merely the compressed difference.
func TestLedgerCountsAvoidedCloudCalls(t *testing.T) {
	l := NewLedger(NewPriceBook())
	l.Record(Record{
		Route: RouteLocal, Model: "phi4-mini",
		BaselineTokens: 1000, PromptTokens: 300, CompletionTokens: 100,
	}, "gpt-4o")

	tot := l.Totals()
	if tot.TokensSaved != 1000 {
		t.Errorf("tokens saved = %d, want the full 1000-token baseline (nothing reached the cloud)", tot.TokensSaved)
	}
	if tot.CloudCost != 0 {
		t.Errorf("cloud cost = %f, want 0 for a locally-served request", tot.CloudCost)
	}
	if tot.CostSaved <= 0 {
		t.Error("a locally-served request should record a positive saving")
	}
}

func TestLedgerCountsCompressionOnCloudCalls(t *testing.T) {
	l := NewLedger(NewPriceBook())
	l.Record(Record{
		Route: RouteCloud, Model: "gpt-4o",
		BaselineTokens: 1000, PromptTokens: 400, CompletionTokens: 100,
		UsageReported: true,
	}, "gpt-4o")

	tot := l.Totals()
	if tot.TokensSaved != 600 {
		t.Errorf("tokens saved = %d, want 600 (1000 baseline - 400 sent)", tot.TokensSaved)
	}
	if tot.CloudCost <= 0 {
		t.Error("a cloud-served request should record real spend")
	}
	if tot.EstimatedRequests != 0 {
		t.Error("a request with provider usage should not count as estimated")
	}
}

func TestLedgerFlagsEstimatedAccounting(t *testing.T) {
	// Estimates must be visibly separated from provider-reported usage so
	// nobody mistakes one for a bill.
	l := NewLedger(NewPriceBook())
	l.Record(Record{Route: RouteCloud, Model: "gpt-4o", BaselineTokens: 100, PromptTokens: 50}, "gpt-4o")
	if l.Totals().EstimatedRequests != 1 {
		t.Error("a request without provider usage must be flagged as estimated")
	}
}
