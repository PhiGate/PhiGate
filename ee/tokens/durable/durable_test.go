// SPDX-License-Identifier: BUSL-1.1

package durable

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/phigate/phigate/internal/config"
	"github.com/phigate/phigate/internal/tokens"
)

// monthlyJST is the period function a configured gateway supplies.
func monthlyJST() func(time.Time) time.Time {
	cfg := config.Defaults()
	return cfg.PeriodStart
}

func open(t *testing.T, path string, now func() time.Time) *Ledger {
	t.Helper()
	l, err := Open(Options{
		Path:          path,
		Inner:         tokens.NewLedger(tokens.NewPriceBook()),
		PeriodStart:   monthlyJST(),
		FlushInterval: time.Hour, // flush explicitly; no timing in the assertions
		now:           now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func spend(l *Ledger, tenant string, prompt, completion int) {
	l.Record(tokens.Record{
		Tenant:           tenant,
		Route:            tokens.RouteCloud,
		Model:            "gpt-4o",
		PromptTokens:     prompt,
		CompletionTokens: completion,
	}, "gpt-4o")
}

// TestConsumptionSurvivesARestart is the claim the package exists for, and the
// one internal/tokens says the community ledger cannot make.
func TestConsumptionSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	first := open(t, path, clock)
	spend(first, "team-a", 1000, 500)
	spend(first, "team-a", 200, 100)
	spend(first, "team-b", 7, 3)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// A rolling update: same database, new process.
	second := open(t, path, clock)
	defer func() { _ = second.Close() }()

	p, c := second.Consumed("team-a", now)
	if p != 1200 || c != 600 {
		t.Fatalf("after restart team-a consumed = (%d, %d), want (1200, 600) — "+
			"this is the reset the durable ledger exists to prevent", p, c)
	}
	if p, c := second.Consumed("team-b", now); p != 7 || c != 3 {
		t.Errorf("after restart team-b consumed = (%d, %d), want (7, 3)", p, c)
	}
}

// TestTenantsDoNotSeeEachOther: one tenant's spend must never count against
// another's budget.
func TestTenantsDoNotSeeEachOther(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	l := open(t, filepath.Join(t.TempDir(), "l.db"), func() time.Time { return now })
	defer func() { _ = l.Close() }()

	spend(l, "a", 100, 0)
	spend(l, "b", 5, 0)

	if p, _ := l.Consumed("a", now); p != 100 {
		t.Errorf("a consumed %d, want 100", p)
	}
	if p, _ := l.Consumed("b", now); p != 5 {
		t.Errorf("b consumed %d, want 5", p)
	}
	if p, _ := l.Consumed("c", now); p != 0 {
		t.Errorf("an unknown tenant consumed %d, want 0", p)
	}
}

// TestUnflushedSpendIsCounted: reading only what is on disk would let a fast
// client outrun its budget by a flush interval, repeatedly.
func TestUnflushedSpendIsCounted(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	l := open(t, filepath.Join(t.TempDir(), "l.db"), func() time.Time { return now })
	defer func() { _ = l.Close() }()

	spend(l, "a", 400, 100)
	// Nothing has been flushed: FlushInterval is an hour and Close has not run.
	if p, c := l.Consumed("a", now); p != 400 || c != 100 {
		t.Fatalf("consumed = (%d, %d) before a flush, want (400, 100)", p, c)
	}
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	if p, c := l.Consumed("a", now); p != 400 || c != 100 {
		t.Fatalf("consumed = (%d, %d) after the flush, want the same (400, 100) — "+
			"a flush must move spend, not double or lose it", p, c)
	}
}

// TestPeriodsAreSeparate: a budget resets, and last period's spend must not
// count against this one.
func TestPeriodsAreSeparate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.db")
	march := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	april := time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)

	clock := march
	l := open(t, path, func() time.Time { return clock })
	defer func() { _ = l.Close() }()

	spend(l, "a", 900, 0)
	if p, _ := l.Consumed("a", march); p != 900 {
		t.Fatalf("March consumed = %d, want 900", p)
	}

	clock = april
	spend(l, "a", 5, 0)

	if p, _ := l.Consumed("a", april); p != 5 {
		t.Errorf("April consumed = %d, want 5 — March's spend leaked into the new period", p)
	}
	if p, _ := l.Consumed("a", march); p != 900 {
		t.Errorf("March consumed = %d after April spend, want 900 — history was overwritten", p)
	}
}

// TestPeriodBoundaryUsesTheConfiguredZone. The default is JST, and a customer's
// month ends at midnight JST: a boundary computed in UTC would put nine hours
// of every month-end in the wrong month.
func TestPeriodBoundaryUsesTheConfiguredZone(t *testing.T) {
	cfg := config.Defaults()
	jst, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		t.Skip("no tzdata")
	}

	// 2026-04-01 00:30 JST is still 2026-03-31 15:30 UTC. The period it belongs
	// to is April's, not March's.
	justAfterMidnightJST := time.Date(2026, 4, 1, 0, 30, 0, 0, jst)
	start := cfg.PeriodStart(justAfterMidnightJST)
	if start.In(jst).Month() != time.April {
		t.Fatalf("period start = %s, want April — the boundary was computed in the wrong zone",
			start.In(jst))
	}

	// And half an hour earlier is still March.
	justBefore := time.Date(2026, 3, 31, 23, 30, 0, 0, jst)
	if got := cfg.PeriodStart(justBefore).In(jst).Month(); got != time.March {
		t.Errorf("period start month = %v just before midnight JST, want March", got)
	}
}

// TestFlushFailureDoesNotDiscardSpend: a transient write failure must not hand
// every tenant its allowance back.
func TestFlushFailureDoesNotDiscardSpend(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "l.db")
	l := open(t, path, func() time.Time { return now })

	spend(l, "a", 500, 0)

	// Close the database underneath the ledger so the next flush fails.
	if err := l.db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Flush(); err == nil {
		t.Fatal("expected the flush to fail against a closed database")
	}
	if p, _ := l.pendingPrompt("a", now); p != 500 {
		t.Errorf("pending spend = %d after a failed flush, want the 500 still queued", p)
	}
}

// pendingPrompt is a test hook onto the unflushed accumulator.
func (l *Ledger) pendingPrompt(tenant string, at time.Time) (int64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p, ok := l.pending[key(tenant, l.periodStart(at))]
	if !ok {
		return 0, false
	}
	return p.PromptTokens, true
}

// TestTotalsComeFromTheInnerLedger: the dashboard asks what this process saved,
// not what every process that ever ran did.
func TestTotalsComeFromTheInnerLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.db")
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	first := open(t, path, clock)
	spend(first, "a", 100, 50)
	if got := first.Totals().Requests; got != 1 {
		t.Fatalf("Totals().Requests = %d, want 1", got)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second := open(t, path, clock)
	defer func() { _ = second.Close() }()
	if got := second.Totals().Requests; got != 0 {
		t.Errorf("Totals().Requests = %d in a fresh process, want 0; process-wide "+
			"totals must not be read back from disk", got)
	}
	// While the per-tenant half did survive, which is the split the package is
	// built around.
	if p, _ := second.Consumed("a", now); p != 100 {
		t.Errorf("per-tenant consumption = %d after restart, want 100", p)
	}
}

func TestPeriodsReport(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	l := open(t, filepath.Join(t.TempDir(), "l.db"), func() time.Time { return now })
	defer func() { _ = l.Close() }()

	spend(l, "a", 10, 5)
	spend(l, "b", 20, 10)

	periods, err := l.Periods()
	if err != nil {
		t.Fatal(err)
	}
	if len(periods) != 2 {
		t.Fatalf("got %d periods, want 2", len(periods))
	}
	byTenant := map[string]Period{}
	for _, p := range periods {
		byTenant[p.Tenant] = p
	}
	if byTenant["a"].PromptTokens != 10 || byTenant["b"].PromptTokens != 20 {
		t.Errorf("periods report the wrong spend: %+v", byTenant)
	}
}
