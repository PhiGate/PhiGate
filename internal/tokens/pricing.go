package tokens

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// Price is the per-million-token cost of a model, in the ledger's currency.
type Price struct {
	// Model is the prefix this entry applies to, e.g. "gpt-4o".
	Model string `json:"model"`
	// InputPerMillion is the cost of one million prompt tokens.
	InputPerMillion float64 `json:"input_per_million"`
	// OutputPerMillion is the cost of one million completion tokens.
	OutputPerMillion float64 `json:"output_per_million"`
}

// Cost returns the money cost of a call at this price.
func (p Price) Cost(in, out int) float64 {
	return float64(in)/1e6*p.InputPerMillion + float64(out)/1e6*p.OutputPerMillion
}

// PriceBook maps model names to prices by longest-prefix match, so
// "gpt-4o-2024-11-20" inherits the price of "gpt-4o" without a separate entry.
//
// Prices change frequently and vary by contract — a Japanese enterprise buying
// through Azure has different rates than one on the public OpenAI API. The
// built-in table is therefore a *default*, explicitly overridable from a JSON
// file, and the ledger records which price it applied so a finance team can
// reconcile the numbers.
type PriceBook struct {
	mu       sync.RWMutex
	currency string
	prices   []Price
	local    float64 // cost per million tokens of self-hosted inference
}

// DefaultPrices is the built-in table, in USD per million tokens. Local models
// are priced at zero by default: the marginal cost of a request served by an
// already-running Ollama instance is close enough to zero that counting it
// would obscure the comparison. Set PHIGATE_LOCAL_COST_PER_MTOK to amortise
// hardware if your finance team wants a fully-loaded figure.
var DefaultPrices = []Price{
	{Model: "gpt-4o-mini", InputPerMillion: 0.15, OutputPerMillion: 0.60},
	{Model: "gpt-4o", InputPerMillion: 2.50, OutputPerMillion: 10.00},
	{Model: "gpt-4.1-mini", InputPerMillion: 0.40, OutputPerMillion: 1.60},
	{Model: "gpt-4.1", InputPerMillion: 2.00, OutputPerMillion: 8.00},
	{Model: "o3-mini", InputPerMillion: 1.10, OutputPerMillion: 4.40},
	{Model: "claude-3-5-haiku", InputPerMillion: 0.80, OutputPerMillion: 4.00},
	{Model: "claude-3-5-sonnet", InputPerMillion: 3.00, OutputPerMillion: 15.00},
	{Model: "claude-sonnet-4", InputPerMillion: 3.00, OutputPerMillion: 15.00},
	{Model: "claude-opus-4", InputPerMillion: 15.00, OutputPerMillion: 75.00},
	{Model: "gemini-2.0-flash", InputPerMillion: 0.10, OutputPerMillion: 0.40},
	{Model: "gemini-1.5-pro", InputPerMillion: 1.25, OutputPerMillion: 5.00},
}

// NewPriceBook returns a PriceBook seeded with DefaultPrices.
func NewPriceBook() *PriceBook {
	p := &PriceBook{currency: "USD", local: 0}
	p.prices = append(p.prices, DefaultPrices...)
	p.sort()
	return p
}

// LoadFile replaces the price table from a JSON file of the form:
//
//	{"currency":"JPY","local_per_million":12.0,
//	 "prices":[{"model":"gpt-4o","input_per_million":375,"output_per_million":1500}]}
//
// Overriding is expected, not exceptional: published list prices are rarely
// what an enterprise actually pays.
func (b *PriceBook) LoadFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read price book: %w", err)
	}
	var doc struct {
		Currency        string  `json:"currency"`
		LocalPerMillion float64 `json:"local_per_million"`
		Prices          []Price `json:"prices"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse price book: %w", err)
	}
	if len(doc.Prices) == 0 {
		return fmt.Errorf("price book %s contains no prices", path)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if doc.Currency != "" {
		b.currency = doc.Currency
	}
	b.local = doc.LocalPerMillion
	b.prices = doc.Prices
	b.sortLocked()
	return nil
}

// SetLocalCost sets the amortised cost per million tokens of local inference.
func (b *PriceBook) SetLocalCost(perMillion float64) {
	b.mu.Lock()
	b.local = perMillion
	b.mu.Unlock()
}

// Currency reports the ledger currency, e.g. "USD" or "JPY".
func (b *PriceBook) Currency() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.currency
}

// Lookup returns the price for model by longest-prefix match, and whether a
// specific entry was found. An unknown model yields a zero price rather than an
// error: an unpriced model must not break the proxy, it must simply not be
// counted, and the "unpriced" flag surfaces in the stats endpoint.
func (b *PriceBook) Lookup(model string) (Price, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	m := strings.ToLower(strings.TrimSpace(model))
	for _, p := range b.prices {
		if strings.HasPrefix(m, strings.ToLower(p.Model)) {
			return p, true
		}
	}
	return Price{Model: model}, false
}

// LocalPrice returns the synthetic price used for locally-served requests.
func (b *PriceBook) LocalPrice() Price {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return Price{Model: "local", InputPerMillion: b.local, OutputPerMillion: b.local}
}

// Prices returns a copy of the table for the stats endpoint.
func (b *PriceBook) Prices() []Price {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Price, len(b.prices))
	copy(out, b.prices)
	return out
}

func (b *PriceBook) sort() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sortLocked()
}

// sortLocked orders entries longest-model-name first so prefix matching picks
// the most specific entry ("gpt-4o-mini" before "gpt-4o").
func (b *PriceBook) sortLocked() {
	sort.SliceStable(b.prices, func(i, j int) bool {
		return len(b.prices[i].Model) > len(b.prices[j].Model)
	})
}
