package tokens

import (
	"sync"
	"time"
)

// Route names where a request was served, for per-route accounting.
type Route string

const (
	// RouteLocal is a request served by the local SLM.
	RouteLocal Route = "local"
	// RouteCloud is a request served by a cloud provider.
	RouteCloud Route = "cloud"
	// RouteCache is a request served from PhiGate's own cache.
	RouteCache Route = "cache"
)

// Record is one accounted request.
type Record struct {
	// Route is where the answer came from.
	Route Route
	// Model is the upstream model actually used.
	Model string
	// BaselineTokens is the estimated prompt size had PhiGate forwarded the
	// raw payload to the cloud model — the counterfactual being avoided.
	BaselineTokens int
	// PromptTokens and CompletionTokens are what was actually consumed.
	// They come from the provider's usage block when it reports one.
	PromptTokens     int
	CompletionTokens int
	// UsageReported records whether the provider supplied real numbers or
	// whether these are estimates. The stats endpoint surfaces the split so
	// nobody mistakes an estimate for a bill.
	UsageReported bool
}

// Totals is a snapshot of the ledger.
type Totals struct {
	Requests          int64   `json:"requests"`
	LocalRequests     int64   `json:"local_requests"`
	CloudRequests     int64   `json:"cloud_requests"`
	CacheHits         int64   `json:"cache_hits"`
	PromptTokens      int64   `json:"prompt_tokens"`
	CompletionTokens  int64   `json:"completion_tokens"`
	BaselineTokens    int64   `json:"baseline_tokens"`
	TokensSaved       int64   `json:"tokens_saved"`
	CloudCost         float64 `json:"cloud_cost"`
	BaselineCost      float64 `json:"baseline_cost"`
	CostSaved         float64 `json:"cost_saved"`
	Currency          string  `json:"currency"`
	EstimatedRequests int64   `json:"estimated_requests"`
	UnpricedRequests  int64   `json:"unpriced_requests"`
	Since             string  `json:"since"`
}

// SavingsPercent reports the share of baseline spend that PhiGate avoided.
func (t Totals) SavingsPercent() float64 {
	if t.BaselineCost <= 0 {
		return 0
	}
	pct := t.CostSaved / t.BaselineCost * 100
	if pct < 0 {
		return 0
	}
	return pct
}

// LedgerStore is the seam accounting backends plug into.
//
// The community edition keeps totals in memory, which is honest for a PoC and
// wrong for a production quota: a rolling update or a crash resets every
// tenant's consumption to zero, so a monthly hard limit stops being a limit.
// Durable and cross-node implementations substitute here without the request
// path changing.
type LedgerStore interface {
	// Record accounts one request against baselineModel, the model whose price
	// defines what the request would have cost without PhiGate.
	Record(r Record, baselineModel string)
	// Totals returns a process-wide snapshot.
	Totals() Totals
}

// Compile-time proof that the in-memory ledger satisfies the seam.
var _ LedgerStore = (*Ledger)(nil)

// Ledger accumulates token and money accounting across the process lifetime.
//
// It answers the only FinOps question that matters: "how much did PhiGate save
// us, and how do you know?" Every request contributes both what it actually
// cost and what it would have cost sent raw to the cloud model, so the delta is
// explicit rather than inferred from a compression ratio.
type Ledger struct {
	mu     sync.Mutex
	prices *PriceBook
	since  time.Time

	t Totals
}

// NewLedger returns a Ledger pricing against book.
func NewLedger(book *PriceBook) *Ledger {
	return &Ledger{prices: book, since: time.Now()}
}

// Baseline is the model whose price defines "what this would have cost without
// PhiGate". It is the configured cloud model: without the gateway, every
// request would have gone there.
func (l *Ledger) Record(r Record, baselineModel string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.t.Requests++
	switch r.Route {
	case RouteLocal:
		l.t.LocalRequests++
	case RouteCache:
		l.t.CacheHits++
	default:
		l.t.CloudRequests++
	}
	if !r.UsageReported {
		l.t.EstimatedRequests++
	}

	l.t.PromptTokens += int64(r.PromptTokens)
	l.t.CompletionTokens += int64(r.CompletionTokens)
	l.t.BaselineTokens += int64(r.BaselineTokens)

	base, pricedBase := l.prices.Lookup(baselineModel)
	if !pricedBase {
		l.t.UnpricedRequests++
	}
	// The counterfactual: the raw prompt, and the same answer length, billed at
	// the cloud model's rate.
	baselineCost := base.Cost(r.BaselineTokens, r.CompletionTokens)
	l.t.BaselineCost += baselineCost

	var actual float64
	switch r.Route {
	case RouteLocal:
		actual = l.prices.LocalPrice().Cost(r.PromptTokens, r.CompletionTokens)
	case RouteCache:
		actual = 0
	default:
		p, _ := l.prices.Lookup(r.Model)
		actual = p.Cost(r.PromptTokens, r.CompletionTokens)
		l.t.CloudCost += actual
	}

	saved := baselineCost - actual
	if saved < 0 {
		saved = 0
	}
	l.t.CostSaved += saved

	tokensSaved := int64(r.BaselineTokens - r.PromptTokens)
	if r.Route != RouteCloud {
		// Nothing reached the cloud at all, so the whole prompt was avoided.
		tokensSaved = int64(r.BaselineTokens)
	}
	if tokensSaved > 0 {
		l.t.TokensSaved += tokensSaved
	}
}

// Totals returns a snapshot.
func (l *Ledger) Totals() Totals {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.t
	out.Currency = l.prices.Currency()
	out.Since = l.since.UTC().Format(time.RFC3339)
	return out
}
