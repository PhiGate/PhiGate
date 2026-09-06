package tokens

import "testing"

// TestCurrentClaudeModelsAreNotMispricedByAnOlderPrefix.
//
// The book matches longest-name-first, so a family entry silently absorbs every
// later generation. "claude-opus-4" was in the table at $15/$75 before the 4.x
// generations existed at $5/$25 — a request on claude-opus-4-8 would have been
// reported at three times what it cost, in a figure a finance team is being
// asked to trust.
func TestCurrentClaudeModelsAreNotMispricedByAnOlderPrefix(t *testing.T) {
	b := NewPriceBook()
	for model, want := range map[string]Price{
		"claude-opus-5":     {InputPerMillion: 5.00, OutputPerMillion: 25.00},
		"claude-opus-4-8":   {InputPerMillion: 5.00, OutputPerMillion: 25.00},
		"claude-opus-4-7":   {InputPerMillion: 5.00, OutputPerMillion: 25.00},
		"claude-opus-4-6":   {InputPerMillion: 5.00, OutputPerMillion: 25.00},
		"claude-sonnet-5":   {InputPerMillion: 2.00, OutputPerMillion: 10.00},
		"claude-sonnet-4-6": {InputPerMillion: 3.00, OutputPerMillion: 15.00},
		"claude-haiku-4-5":  {InputPerMillion: 1.00, OutputPerMillion: 5.00},
		"claude-fable-5-1":  {InputPerMillion: 10.00, OutputPerMillion: 50.00},
		"claude-fable-5":    {InputPerMillion: 10.00, OutputPerMillion: 50.00},
		// The older entries must still resolve to their own rates.
		"claude-opus-4":   {InputPerMillion: 15.00, OutputPerMillion: 75.00},
		"claude-sonnet-4": {InputPerMillion: 3.00, OutputPerMillion: 15.00},
	} {
		got, ok := b.Lookup(model)
		if !ok {
			t.Errorf("%s has no price", model)
			continue
		}
		if got.InputPerMillion != want.InputPerMillion || got.OutputPerMillion != want.OutputPerMillion {
			t.Errorf("%s priced at $%.2f/$%.2f, want $%.2f/$%.2f",
				model, got.InputPerMillion, got.OutputPerMillion,
				want.InputPerMillion, want.OutputPerMillion)
		}
	}
}

// TestDatedSnapshotsInheritTheirGeneration is the property the prefix match
// exists for: a pinned snapshot should not need its own entry.
func TestDatedSnapshotsInheritTheirGeneration(t *testing.T) {
	b := NewPriceBook()
	got, ok := b.Lookup("claude-opus-5-20260401")
	if !ok {
		t.Fatal("a dated snapshot has no price")
	}
	if got.InputPerMillion != 5.00 {
		t.Errorf("snapshot priced at $%.2f, want its generation's $5.00", got.InputPerMillion)
	}
}

// TestBedrockModelsAreUnpricedRatherThanMispriced. Bedrock is partner-operated
// with its own rates; aliasing "anthropic.claude-opus-5" onto the first-party
// price would report a number that is confidently wrong. Unpriced is visible in
// the stats endpoint; wrong is not.
func TestBedrockModelsAreUnpricedRatherThanMispriced(t *testing.T) {
	b := NewPriceBook()
	if _, ok := b.Lookup("anthropic.claude-opus-5"); ok {
		t.Error("a Bedrock model id resolved to a first-party price; " +
			"partner platforms have separate rates and must be supplied explicitly")
	}
}
