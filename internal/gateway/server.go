// Package gateway exposes PhiGate's OpenAI-compatible HTTP surface and wires
// the compression, policy, routing, caching and sandbox layers into the request
// path.
package gateway

import (
	"context"
	"net/http"
	"time"

	"github.com/phigate/phigate/internal/compressor"
	"github.com/phigate/phigate/internal/config"
	"github.com/phigate/phigate/internal/llm"
	"github.com/phigate/phigate/internal/types"
)

// Routes returns the configured HTTP handler.
//
// The route table encodes the access model:
//   - /healthz and /readyz are unauthenticated, because probes cannot carry
//     credentials and they disclose nothing.
//   - Everything else requires an API key.
//   - /debug/* exists only when explicitly enabled, because it discloses raw
//     values.
func (g *Gateway) Routes() http.Handler {
	mux := http.NewServeMux()

	// Unauthenticated: liveness and readiness only.
	mux.HandleFunc("/healthz", g.handleHealthz)
	mux.HandleFunc("/readyz", g.handleReadyz)

	auth := newAuthenticator(g.cfg.APIKeys, g.cfg.AllowAnonymous)
	limiter := newRateLimiter(g.cfg.RateLimitPerMin, g.cfg.RateLimitBurst)
	protect := func(h http.HandlerFunc) http.Handler {
		return auth.Wrap(limiter.Wrap(h))
	}

	mux.Handle("/v1/chat/completions", protect(g.handleChatCompletions))
	mux.Handle("/v1/models", protect(g.handleModels))
	mux.Handle("/v1/phigate/stats", protect(g.handleStats))
	mux.Handle("/v1/phigate/rules", protect(g.handleRules))
	mux.Handle(g.cfg.MetricsPath, protect(g.handleMetrics))

	if g.cfg.DashboardOn {
		mux.Handle("/dashboard", protect(g.handleDashboard))
	}

	// The debug endpoint returns the dictionary — every masked value in
	// plaintext. It shipped enabled and unauthenticated, which made it an
	// exfiltration endpoint for exactly the data the gateway exists to
	// protect. It is now opt-in and behind authentication.
	if g.cfg.DebugEnabled {
		mux.Handle("/debug/compress", protect(g.handleDebugCompress))
	}

	return recoverPanic(withRequestID(mux))
}

// handleHealthz reports process liveness.
func (g *Gateway) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// readiness is the /readyz payload.
type readiness struct {
	Status   string            `json:"status"`
	Uptime   string            `json:"uptime"`
	Backends map[string]string `json:"backends"`
	Policy   string            `json:"policy"`
	Cache    bool              `json:"cache_enabled"`
	Audit    bool              `json:"audit_enabled"`
}

// handleReadyz reports whether PhiGate can actually serve traffic.
//
// Liveness and readiness are separated because they answer different questions
// for an orchestrator: PhiGate stays *alive* when a backend is down — it can
// still fall back or fail cleanly — but should not receive new traffic when
// every backend is unreachable.
func (g *Gateway) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	backends := map[string]string{}
	healthy := 0
	for name, c := range map[string]llm.Client{"local": g.local, "cloud": g.cloud} {
		p, ok := c.(interface {
			Probe(context.Context) error
			BreakerState() string
		})
		if !ok {
			backends[name] = "unknown"
			healthy++
			continue
		}
		if err := p.Probe(ctx); err != nil {
			backends[name] = "unreachable (breaker " + p.BreakerState() + ")"
			continue
		}
		backends[name] = "ok (breaker " + p.BreakerState() + ")"
		healthy++
	}

	status := http.StatusOK
	state := "ready"
	if healthy == 0 {
		status, state = http.StatusServiceUnavailable, "no backend reachable"
	}
	writeJSON(w, status, readiness{
		Status:   state,
		Uptime:   time.Since(g.started).Round(time.Second).String(),
		Backends: backends,
		Policy:   g.policy.Describe(),
		Cache:    g.cache.Stats().Enabled,
		Audit:    g.audit.Enabled(),
	})
}

// handleModels implements GET /v1/models.
//
// Client SDKs call it to validate configuration and to populate model pickers;
// without it, a "zero code change" integration fails on the first thing many
// clients do.
func (g *Gateway) handleModels(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().Unix()
	writeJSON(w, http.StatusOK, types.ModelList{
		Object: "list",
		Data: []types.Model{
			{ID: g.localModel, Object: "model", Created: now, OwnedBy: "phigate-local"},
			{ID: g.cloudModel, Object: "model", Created: now, OwnedBy: "phigate-cloud"},
		},
	})
}

// statsResponse is the /v1/phigate/stats payload: the FinOps and compliance
// summary an operator or dashboard reads.
type statsResponse struct {
	Uptime    string `json:"uptime"`
	Totals    any    `json:"totals"`
	SavedPct  string `json:"savings_percent"`
	Cache     any    `json:"cache"`
	Sessions  int    `json:"active_sessions"`
	Policy    string `json:"policy"`
	Guard     any    `json:"guard_rules"`
	Redaction any    `json:"redaction_rules"`
	Prices    any    `json:"price_book"`
	Backends  any    `json:"backends"`
}

func (g *Gateway) handleStats(w http.ResponseWriter, _ *http.Request) {
	t := g.ledger.Totals()
	rules := make([]string, 0, len(g.engine.Rules()))
	for _, r := range g.engine.Rules() {
		rules = append(rules, r.Name+" ("+string(r.Category)+")")
	}
	writeJSON(w, http.StatusOK, statsResponse{
		Uptime:    time.Since(g.started).Round(time.Second).String(),
		Totals:    t,
		SavedPct:  formatPercent(t.SavingsPercent()),
		Cache:     g.cache.Stats(),
		Sessions:  g.sessions.Len(),
		Policy:    g.policy.Describe(),
		Guard:     g.guard.Describe(),
		Redaction: rules,
		Prices:    g.prices.Prices(),
		Backends: map[string]string{
			"local": breakerState(g.local),
			"cloud": breakerState(g.cloud),
		},
	})
}

// handleRules exposes the effective control configuration, so an auditor can
// confirm what is enforced without reading the deployment's environment.
func (g *Gateway) handleRules(w http.ResponseWriter, _ *http.Request) {
	type ruleView struct {
		Name     string `json:"name"`
		Category string `json:"category"`
		Priority int    `json:"priority"`
		Desc     string `json:"description,omitempty"`
	}
	views := make([]ruleView, 0, len(g.engine.Rules()))
	for _, r := range g.engine.Rules() {
		views = append(views, ruleView{r.Name, string(r.Category), r.Priority, r.Description})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"redaction": views,
		"egress":    g.guard.Describe(),
		"policy":    g.policy.Describe(),
	})
}

func (g *Gateway) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(g.metrics.reg.Gather()))
}

// debugResult is the payload returned by /debug/compress.
type debugResult struct {
	Original   string            `json:"original"`
	Compressed string            `json:"compressed"`
	Hydrated   string            `json:"hydrated"`
	Dictionary map[string]string `json:"dictionary"`
	Findings   map[string]int    `json:"findings"`
	Rules      []string          `json:"rules_fired"`
	Sensitive  string            `json:"max_sensitivity"`
	Roundtrip  bool              `json:"roundtrip_ok"`
	Route      string            `json:"route"`
	RouteWhy   string            `json:"route_reason"`
	Policy     string            `json:"policy_action"`
	PolicyWhy  string            `json:"policy_reason"`
	Warning    string            `json:"warning"`
}

// handleDebugCompress exposes the compression layer for inspection. It returns
// raw values and must never be enabled in production; the response says so.
func (g *Gateway) handleDebugCompress(w http.ResponseWriter, r *http.Request) {
	raw, err := io_ReadAllLimited(r, g.cfg.MaxBodyBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read request body", "invalid_request_error", "")
		return
	}
	original := string(raw)

	sess := compressor.NewSession()
	compressed, err := g.pipeline.Compress(original, sess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "compression error", "api_error", "")
		return
	}
	hydrated := sess.Dict.Hydrate(compressed)
	decision, _ := g.router.Route(r.Context(), compressed)
	verdict := g.policy.Evaluate(sess.MaxSensitivity())

	findings := map[string]int{}
	for cat, n := range sess.Categories() {
		findings[string(cat)] = n
	}

	writeJSON(w, http.StatusOK, debugResult{
		Original:   original,
		Compressed: compressed,
		Hydrated:   hydrated,
		Dictionary: sess.Dict.Entries(),
		Findings:   findings,
		Rules:      sess.FiredRules(),
		Sensitive:  sess.MaxSensitivity().String(),
		Roundtrip:  hydrated == original,
		Route:      decision.Target.String(),
		RouteWhy:   decision.Reason,
		Policy:     verdict.Action.String(),
		PolicyWhy:  verdict.Reason,
		Warning: "This response contains the plaintext of every masked value. " +
			"PHIGATE_DEBUG must be off in production.",
	})
}

// NewServer builds an *http.Server from cfg with timeouts set.
//
// The timeouts matter: a server with no ReadHeaderTimeout is trivially held
// open by a Slowloris client, and PhiGate is by design an internet-adjacent
// service holding an expensive API key.
func NewServer(cfg config.Config, g *Gateway) *http.Server {
	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           g.Routes(),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		// WriteTimeout is intentionally left at the configured value, which
		// defaults to zero: a streaming completion may legitimately take
		// longer than any fixed bound, and cutting it off mid-answer is worse
		// than the risk it mitigates.
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}
}

func breakerState(c llm.Client) string {
	if b, ok := c.(interface{ BreakerState() string }); ok {
		return b.BreakerState()
	}
	return "unknown"
}

func formatPercent(f float64) string {
	return trimFloat(f) + "%"
}
