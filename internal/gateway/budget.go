package gateway

import (
	"net/http"
	"strconv"
	"time"

	"github.com/phigate/phigate/internal/tokens"
)

// budgetGuard refuses a tenant that has spent its allowance for the period.
//
// # What it can and cannot promise
//
// A request's token cost is not known until the request has finished, so this
// checks what a tenant has *already* spent and lets the next request through if
// there is anything left. One request therefore always overshoots the budget,
// and a streaming answer can overshoot it by a lot. That is inherent to the
// shape of the problem — the alternative is refusing to serve until the answer
// exists, which is not serving — and it is written down here and in the
// configuration reference rather than discovered from a bill.
//
// The bound is that a tenant cannot keep overshooting: the first request after
// the allowance is exhausted is refused.
//
// # Why it lives in the community edition
//
// The enterprise edition contains no request-path logic. It substitutes the
// ledger this asks, which is what turns a best-effort budget into a durable
// one; the decision itself belongs here, with the rest of the controls, so both
// editions enforce it identically.
type budgetGuard struct {
	g *Gateway
}

// newBudgetGuard returns a guard, or nil when no tenant is budgeted at startup.
//
// As with the rate limiter, a deployment that begins with no budget anywhere
// cannot gain one by reload alone; introducing the first one needs a restart,
// and the configuration reference says so.
func newBudgetGuard(g *Gateway) *budgetGuard {
	if !g.now().cfg.AnyBudget() {
		return nil
	}
	return &budgetGuard{g: g}
}

// Wrap enforces the budget on a handler.
func (b *budgetGuard) Wrap(next http.Handler) http.Handler {
	if b == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if remaining, budget, ok := b.check(r); !ok {
			w.Header().Set("X-PhiGate-Budget", strconv.FormatInt(budget, 10))
			w.Header().Set("X-PhiGate-Budget-Remaining", "0")
			writeError(w, http.StatusTooManyRequests,
				"token budget exhausted for this tenant in the current period",
				"rate_limit_error", "token_budget_exceeded")
			return
		} else if budget > 0 {
			w.Header().Set("X-PhiGate-Budget", strconv.FormatInt(budget, 10))
			w.Header().Set("X-PhiGate-Budget-Remaining", strconv.FormatInt(remaining, 10))
		}
		next.ServeHTTP(w, r)
	})
}

// check reports the tenant's remaining allowance and whether to serve.
func (b *budgetGuard) check(r *http.Request) (remaining, budget int64, ok bool) {
	st := b.g.now()
	tenant := tenantOf(r)

	budget = st.cfg.BudgetFor(tenant)
	if budget <= 0 {
		return 0, 0, true // this tenant is not budgeted
	}

	// A ledger that cannot answer means "no limit known", never "limit
	// reached". Failing closed here would turn an accounting outage — or
	// simply a deployment whose ledger has been substituted for one that does
	// not track tenants — into a refusal to serve.
	tl, isTenantLedger := b.g.ledger.(tokens.TenantLedger)
	if !isTenantLedger {
		return 0, 0, true
	}

	prompt, completion := tl.Consumed(tenant, st.cfg.PeriodStart(time.Now()))
	spent := prompt + completion
	if spent >= budget {
		return 0, budget, false
	}
	return budget - spent, budget, true
}
