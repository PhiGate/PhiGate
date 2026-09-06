package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/phigate/phigate/internal/cache"
	"github.com/phigate/phigate/internal/tokens"
)

// The doubles below stand in for the enterprise edition. They exist to prove
// the seams are reachable from the request path and carry what an EE
// implementation would need — not to implement anything.

// probeStore records the probes it is handed and otherwise behaves as the
// community cache does.
type probeStore struct {
	cache.Store
	probes []cache.Probe
}

func (p *probeStore) GetProbe(pr cache.Probe) (cache.Entry, bool) {
	p.probes = append(p.probes, pr)
	return p.Store.Get(pr.Key)
}

// tenantLedger records what it is asked to account for.
type tenantLedger struct {
	tokens.LedgerStore
	records []tokens.Record
}

func (l *tenantLedger) Record(r tokens.Record, baseline string) {
	l.records = append(l.records, r)
	l.LedgerStore.Record(r, baseline)
}

func (l *tenantLedger) TenantTotals(string) tokens.Totals { return tokens.Totals{} }
func (l *tenantLedger) Consumed(string, time.Time) (int64, int64) {
	return 0, 0
}

// TestCacheProbeSeamReachesTheStore: a store that can use more than the key is
// handed the whole probe, and the compressed text in it is what a semantic tier
// would index. Without this the seam is undeliverable — Key is a SHA-256 digest
// and the one operation that cannot be undone.
func TestCacheProbeSeamReachesTheStore(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	cfg.CacheEnabled = true
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	ps := &probeStore{Store: cache.New(time.Minute, 100)}
	g.SetCache(ps)

	postAsAnon(t, g, "disk full on 10.0.0.5")

	if len(ps.probes) != 1 {
		t.Fatalf("store received %d probes, want 1 — the request path did not "+
			"detect the optional interface", len(ps.probes))
	}
	p := ps.probes[0]
	if p.Key == "" {
		t.Error("probe carries no key, so an exact-match tier could not serve it")
	}
	if len(p.Texts) == 0 {
		t.Fatal("probe carries no compressed text, so a semantic tier has nothing to index")
	}
	if p.Model == "" {
		t.Error("probe carries no model; two models' answers are not interchangeable")
	}
	// The obligation the whole cache design rests on: nothing here is a raw
	// value, so a tier that persists a probe persists no customer data.
	for _, txt := range p.Texts {
		if strings.Contains(txt, "10.0.0.5") {
			t.Fatalf("probe carries a raw value: %q", txt)
		}
	}
}

// TestCommunityCacheIgnoresTheProbeSeam: CE must not implement ProbeStore. If
// it did, the package's claim to hold no prompt text — not even masked text —
// would stop being true the moment someone made the exact-match store use the
// probe for convenience.
func TestCommunityCacheIgnoresTheProbeSeam(t *testing.T) {
	var s cache.Store = cache.New(time.Minute, 10)
	if _, ok := s.(cache.ProbeStore); ok {
		t.Fatal("the community cache implements ProbeStore; it must keep holding only hashes")
	}
}

// TestLedgerSeamCarriesTheTenant: a quota is per-tenant or it is not a quota,
// and attribution cannot be reconstructed after the request has finished.
func TestLedgerSeamCarriesTheTenant(t *testing.T) {
	cfg := testConfig()
	cfg.AllowAnonymous = false
	cfg.APIKeys = map[string]string{"k-fin": "team-finance"}
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	tl := &tenantLedger{LedgerStore: tokens.NewLedger(tokens.NewPriceBook())}
	g.SetLedger(tl)

	if rec := postAs(t, g, "k-fin", "disk full"); rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if len(tl.records) != 1 {
		t.Fatalf("ledger saw %d records, want 1", len(tl.records))
	}
	if got := tl.records[0].Tenant; got != "team-finance" {
		t.Errorf("record tenant = %q, want team-finance", got)
	}
}

// TestCommunityLedgerAccountsPerTenant: CE implements TenantLedger because it
// genuinely attributes per tenant. What it cannot do is survive a restart,
// which is the enterprise edition's job and a different axis. A budget check
// that silently answered for the whole deployment would be the failure worth
// guarding against, so this asserts the attribution is real.
func TestCommunityLedgerAccountsPerTenant(t *testing.T) {
	l := tokens.NewLedger(tokens.NewPriceBook())
	var store tokens.LedgerStore = l
	tl, ok := store.(tokens.TenantLedger)
	if !ok {
		t.Fatal("the in-memory ledger no longer implements TenantLedger")
	}

	l.Record(tokens.Record{Tenant: "a", Route: tokens.RouteCloud, PromptTokens: 100}, "gpt-4o")
	l.Record(tokens.Record{Tenant: "b", Route: tokens.RouteCloud, PromptTokens: 7}, "gpt-4o")

	if got := tl.TenantTotals("a").PromptTokens; got != 100 {
		t.Errorf("tenant a prompt tokens = %d, want 100", got)
	}
	if got := tl.TenantTotals("b").PromptTokens; got != 7 {
		t.Errorf("tenant b prompt tokens = %d, want 7 — one tenant is seeing another's spend", got)
	}
	if p, _ := tl.Consumed("a", time.Now().Add(-time.Hour)); p != 100 {
		t.Errorf("Consumed(a) = %d, want 100", p)
	}
	if p, _ := tl.Consumed("nobody", time.Now().Add(-time.Hour)); p != 0 {
		t.Errorf("Consumed for an unknown tenant = %d, want 0", p)
	}
}
