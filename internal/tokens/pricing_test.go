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
		assertPrice(t, b, model, want)
	}
}

// TestCurrentOpenAIModelsAreNotMispricedByAnOlderPrefix is the same property
// for OpenAI, where the prefix overlap is worse than Anthropic's: every 5.x
// generation starts with the literal "gpt-5", which is itself a priced model at
// $1.25/$10. A generation missing from the table is therefore not unpriced and
// visible — it is priced at a fifth of its input cost and silently believed.
func TestCurrentOpenAIModelsAreNotMispricedByAnOlderPrefix(t *testing.T) {
	b := NewPriceBook()
	for model, want := range map[string]Price{
		"gpt-6-astra":   {InputPerMillion: 10.00, OutputPerMillion: 50.00},
		"gpt-5.6-sol":   {InputPerMillion: 4.00, OutputPerMillion: 20.00},
		"gpt-5.6-terra": {InputPerMillion: 2.00, OutputPerMillion: 12.00},
		"gpt-5.6-luna":  {InputPerMillion: 0.20, OutputPerMillion: 1.20},
		"gpt-5.5-pro":   {InputPerMillion: 30.00, OutputPerMillion: 180.00},
		"gpt-5.5":       {InputPerMillion: 5.00, OutputPerMillion: 30.00},
		"gpt-5.4-mini":  {InputPerMillion: 0.75, OutputPerMillion: 4.50},
		"gpt-5.4":       {InputPerMillion: 2.50, OutputPerMillion: 15.00},
		"gpt-5.2":       {InputPerMillion: 1.75, OutputPerMillion: 14.00},
		"gpt-5.1":       {InputPerMillion: 1.25, OutputPerMillion: 10.00},
		"gpt-5-mini":    {InputPerMillion: 0.25, OutputPerMillion: 2.00},
		"gpt-5":         {InputPerMillion: 1.25, OutputPerMillion: 10.00},
		// "o3" must not absorb "o3-mini", and "o1" must not absorb "o1-pro".
		"o3-pro":  {InputPerMillion: 20.00, OutputPerMillion: 80.00},
		"o3-mini": {InputPerMillion: 1.10, OutputPerMillion: 4.40},
		"o3":      {InputPerMillion: 2.00, OutputPerMillion: 8.00},
		"o1-pro":  {InputPerMillion: 150.00, OutputPerMillion: 600.00},
		"o1":      {InputPerMillion: 15.00, OutputPerMillion: 60.00},
		// The older entries must still resolve to their own rates.
		"gpt-4o-mini": {InputPerMillion: 0.15, OutputPerMillion: 0.60},
		"gpt-4o":      {InputPerMillion: 2.50, OutputPerMillion: 10.00},
		"gpt-4.1":     {InputPerMillion: 2.00, OutputPerMillion: 8.00},
	} {
		assertPrice(t, b, model, want)
	}
}

// TestCurrentGeminiModelsAreNotMispricedByAnOlderPrefix. The hazard here is the
// "-lite" suffix: "gemini-2.5-flash" is a prefix of "gemini-2.5-flash-lite", so
// dropping the lite entry prices the cheapest model in the family at three times
// its rate.
func TestCurrentGeminiModelsAreNotMispricedByAnOlderPrefix(t *testing.T) {
	b := NewPriceBook()
	for model, want := range map[string]Price{
		"gemini-3.8-flash":       {InputPerMillion: 0.75, OutputPerMillion: 3.75},
		"gemini-3.5-flash":       {InputPerMillion: 1.50, OutputPerMillion: 9.00},
		"gemini-3.5-flash-lite":  {InputPerMillion: 0.30, OutputPerMillion: 2.50},
		"gemini-3.1-pro-preview": {InputPerMillion: 2.00, OutputPerMillion: 12.00},
		"gemini-2.5-pro":         {InputPerMillion: 1.25, OutputPerMillion: 10.00},
		"gemini-2.5-flash":       {InputPerMillion: 0.30, OutputPerMillion: 2.50},
		"gemini-2.5-flash-lite":  {InputPerMillion: 0.10, OutputPerMillion: 0.40},
		"gemini-2.0-flash":       {InputPerMillion: 0.10, OutputPerMillion: 0.40},
	} {
		assertPrice(t, b, model, want)
	}
}

func assertPrice(t *testing.T, b *PriceBook, model string, want Price) {
	t.Helper()
	got, ok := b.Lookup(model)
	if !ok {
		t.Errorf("%s has no price", model)
		return
	}
	if got.InputPerMillion != want.InputPerMillion || got.OutputPerMillion != want.OutputPerMillion {
		t.Errorf("%s priced at $%.2f/$%.2f, want $%.2f/$%.2f",
			model, got.InputPerMillion, got.OutputPerMillion,
			want.InputPerMillion, want.OutputPerMillion)
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

// TestShippedExampleBookDoesNotMisprice loads the price book we actually ship
// and asserts the property the table above guarantees for the built-in one.
//
// This is the file that had the bug: the example is where a deployment starts,
// and it listed claude-opus-4 with none of the 4.x generations, so every
// claude-opus-4-8 request it priced was reported at three times its cost. Hand
// checking a JSON file is how that survived. Checking it here is how it stays
// fixed.
func TestShippedExampleBookDoesNotMisprice(t *testing.T) {
	const path = "../../deploy/price-book.example.json"
	b := NewPriceBook()
	if err := b.LoadFile(path); err != nil {
		t.Skipf("example book not readable from here: %v", err)
	}
	if b.Currency() != "JPY" {
		t.Errorf("example book currency is %q, want JPY", b.Currency())
	}
	// Converted at JPY 150 = USD 1, the rate the file documents.
	for model, want := range map[string]Price{
		"claude-opus-4-8":   {InputPerMillion: 750, OutputPerMillion: 3750},
		"claude-opus-4-7":   {InputPerMillion: 750, OutputPerMillion: 3750},
		"claude-opus-4-6":   {InputPerMillion: 750, OutputPerMillion: 3750},
		"claude-opus-5":     {InputPerMillion: 750, OutputPerMillion: 3750},
		"claude-sonnet-5":   {InputPerMillion: 300, OutputPerMillion: 1500},
		"claude-sonnet-4-6": {InputPerMillion: 450, OutputPerMillion: 2250},
		"claude-haiku-4-5":  {InputPerMillion: 150, OutputPerMillion: 750},
		// The legacy rows must keep their own, genuinely higher, rates.
		"claude-opus-4":   {InputPerMillion: 2250, OutputPerMillion: 11250},
		"claude-sonnet-4": {InputPerMillion: 450, OutputPerMillion: 2250},
		// The "-lite" suffix hazard, in the file rather than the table.
		"gemini-2.5-flash":      {InputPerMillion: 45, OutputPerMillion: 375},
		"gemini-2.5-flash-lite": {InputPerMillion: 15, OutputPerMillion: 60},
	} {
		assertPrice(t, b, model, want)
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
