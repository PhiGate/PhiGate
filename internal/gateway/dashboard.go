package gateway

import (
	_ "embed"
	"html/template"
	"net/http"
	"sort"
	"time"

	"github.com/phigate/phigate/internal/cache"
	"github.com/phigate/phigate/internal/tokens"
)

//go:embed dashboard.html
var dashboardHTML string

var dashboardTmpl = template.Must(template.New("dashboard").Parse(dashboardHTML))

// dashboardData is the view model.
type dashboardData struct {
	Uptime       string
	Totals       tokens.Totals
	SavingsPct   string
	Cache        cache.Stats
	CacheHitPct  string
	Sessions     int
	Policy       string
	GuardRules   []string
	RedactRules  []string
	Backends     map[string]string
	Currency     string
	Generated    string
	LocalPct     string
	CloudPct     string
	CachePct     string
	AuditEnabled bool
	DebugOn      bool
}

// handleDashboard renders a single self-contained operations page.
//
// It ships embedded in the binary with no external assets, because the
// deployments PhiGate targets — a JP enterprise's internal network, often
// air-gapped from the public internet — cannot load a CDN, and a dashboard that
// renders blank in the customer's environment is worse than none.
func (g *Gateway) handleDashboard(w http.ResponseWriter, _ *http.Request) {
	t := g.ledger.Totals()
	cs := g.cache.Stats()

	redact := make([]string, 0, len(g.engine.Rules()))
	for _, r := range g.engine.Rules() {
		redact = append(redact, r.Name+" — "+string(r.Category))
	}
	sort.Strings(redact)

	data := dashboardData{
		Uptime:       time.Since(g.started).Round(time.Second).String(),
		Totals:       t,
		SavingsPct:   trimFloat(t.SavingsPercent()),
		Cache:        cs,
		CacheHitPct:  trimFloat(cs.HitRate * 100),
		Sessions:     g.sessions.Len(),
		Policy:       g.policy.Describe(),
		GuardRules:   g.guard.Describe(),
		RedactRules:  redact,
		Currency:     t.Currency,
		Generated:    time.Now().Format(time.RFC1123),
		LocalPct:     sharePct(t.LocalRequests, t.Requests),
		CloudPct:     sharePct(t.CloudRequests, t.Requests),
		CachePct:     sharePct(t.CacheHits, t.Requests),
		AuditEnabled: g.audit.Enabled(),
		DebugOn:      g.cfg.DebugEnabled,
		Backends: map[string]string{
			"local": breakerState(g.local),
			"cloud": breakerState(g.cloud),
		},
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	if err := dashboardTmpl.Execute(w, data); err != nil {
		writeError(w, http.StatusInternalServerError, "render error", "api_error", "")
	}
}

func sharePct(n, total int64) string {
	if total <= 0 {
		return "0"
	}
	return trimFloat(float64(n) / float64(total) * 100)
}
