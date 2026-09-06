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
	// Tenant is the API key's tenant label, so consumption can be attributed.
	//
	// A quota is per-tenant or it is not a quota, and attribution cannot be
	// reconstructed once the request has finished, so it is carried here rather
	// than added when the first store needs it.
	Tenant string
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

// TenantLedger is the optional half of the seam: a store that attributes
// consumption to tenants and can answer what one has spent.
//
// It is separate from LedgerStore so that a store which cannot answer these
// questions is not obliged to pretend it can. What it does *not* promise is
// durability. The community edition implements it in memory, which enforces a
// budget honestly for as long as the process lives and resets every tenant to
// zero on a rolling update — so a monthly limit backed by it is not a limit.
// That is the gap the enterprise edition's implementation closes, and it is a
// different axis from this interface.
//
// Callers must treat a store that does not implement this as "no limit known",
// never as "limit reached": failing closed on a missing ledger would turn an
// accounting outage into an outage.
type TenantLedger interface {
	LedgerStore
	// TenantTotals is one tenant's snapshot, shaped like the process-wide one.
	TenantTotals(tenant string) Totals
	// Consumed reports the tokens a tenant has spent since a point in time,
	// which is what a period-bounded budget is checked against.
	Consumed(tenant string, since time.Time) (prompt, completion int64)
}

// Compile-time proof that the in-memory ledger satisfies both halves of the
// seam.
//
// It satisfies TenantLedger because it does genuinely account per tenant. What
// it does not do is survive a restart, which is a different axis and the one
// the enterprise edition's implementation exists for — see the note on
// LedgerStore. A budget checked against this one is honest about a running
// process and resets to zero on a rolling update.
var (
	_ LedgerStore  = (*Ledger)(nil)
	_ TenantLedger = (*Ledger)(nil)
)

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
	// perTenant is the same accounting, split by tenant, so a budget can be
	// checked against what one tenant has spent rather than what the process
	// has. It is still memory only: this satisfies TenantLedger's shape, not
	// its usefulness as a monthly quota, which needs durability the enterprise
	// edition supplies.
	perTenant map[string]*Totals
	// spend is when each tenant's consumption was recorded, so Consumed can
	// answer for a window rather than for all time. One entry per request is
	// wasteful; one per tenant per minute is enough to bound a budget period
	// and is what this keeps.
	spend map[string][]spendPoint
}

// spendPoint is one minute of one tenant's consumption.
type spendPoint struct {
	minute             time.Time
	prompt, completion int64
}

// NewLedger returns a Ledger pricing against book.
func NewLedger(book *PriceBook) *Ledger {
	return &Ledger{
		prices:    book,
		since:     time.Now(),
		perTenant: map[string]*Totals{},
		spend:     map[string][]spendPoint{},
	}
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

	l.recordTenantLocked(r, baselineCost, actual, tokensSaved)
}

// recordTenantLocked mirrors the process-wide accounting into the tenant's own.
func (l *Ledger) recordTenantLocked(r Record, baselineCost, actual float64, tokensSaved int64) {
	if r.Tenant == "" {
		return
	}
	t, ok := l.perTenant[r.Tenant]
	if !ok {
		t = &Totals{}
		l.perTenant[r.Tenant] = t
	}
	t.Requests++
	switch r.Route {
	case RouteLocal:
		t.LocalRequests++
	case RouteCache:
		t.CacheHits++
	default:
		t.CloudRequests++
		t.CloudCost += actual
	}
	if !r.UsageReported {
		t.EstimatedRequests++
	}
	t.PromptTokens += int64(r.PromptTokens)
	t.CompletionTokens += int64(r.CompletionTokens)
	t.BaselineTokens += int64(r.BaselineTokens)
	t.BaselineCost += baselineCost
	if saved := baselineCost - actual; saved > 0 {
		t.CostSaved += saved
	}
	if tokensSaved > 0 {
		t.TokensSaved += tokensSaved
	}

	// Bucket the spend by minute so Consumed can answer for a window without
	// keeping a point per request.
	minute := time.Now().UTC().Truncate(time.Minute)
	pts := l.spend[r.Tenant]
	if n := len(pts); n > 0 && pts[n-1].minute.Equal(minute) {
		pts[n-1].prompt += int64(r.PromptTokens)
		pts[n-1].completion += int64(r.CompletionTokens)
	} else {
		pts = append(pts, spendPoint{minute, int64(r.PromptTokens), int64(r.CompletionTokens)})
	}
	// A month of minutes is ~44k points per tenant; keep a bounded tail.
	if len(pts) > maxSpendPoints {
		pts = pts[len(pts)-maxSpendPoints:]
	}
	l.spend[r.Tenant] = pts
}

// maxSpendPoints bounds the per-tenant spend history. Roughly 45 days of
// minutes, which covers a monthly period with room for a late reset.
const maxSpendPoints = 65000

// TenantTotals returns one tenant's snapshot.
func (l *Ledger) TenantTotals(tenant string) Totals {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.perTenant[tenant]
	if !ok {
		return Totals{Currency: l.prices.Currency(), Since: l.since.UTC().Format(time.RFC3339)}
	}
	out := *t
	out.Currency = l.prices.Currency()
	out.Since = l.since.UTC().Format(time.RFC3339)
	return out
}

// Consumed reports what a tenant has spent at or after since.
//
// It answers for the running process only. Whatever this ledger had accounted
// before a restart is gone, which is why a budget enforced against it is
// best-effort — see LedgerStore's doc.
func (l *Ledger) Consumed(tenant string, since time.Time) (prompt, completion int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := since.UTC().Truncate(time.Minute)
	for _, p := range l.spend[tenant] {
		if p.minute.Before(cutoff) {
			continue
		}
		prompt += p.prompt
		completion += p.completion
	}
	return prompt, completion
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
