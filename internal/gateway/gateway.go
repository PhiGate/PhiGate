package gateway

import (
	"fmt"
	"time"

	"github.com/phigate/phigate/internal/audit"
	"github.com/phigate/phigate/internal/cache"
	"github.com/phigate/phigate/internal/compressor"
	"github.com/phigate/phigate/internal/config"
	"github.com/phigate/phigate/internal/llm"
	"github.com/phigate/phigate/internal/metrics"
	"github.com/phigate/phigate/internal/policy"
	"github.com/phigate/phigate/internal/redact"
	"github.com/phigate/phigate/internal/router"
	"github.com/phigate/phigate/internal/sandbox"
	"github.com/phigate/phigate/internal/session"
	"github.com/phigate/phigate/internal/tokens"
)

// Gateway holds the long-lived components shared across requests.
type Gateway struct {
	cfg config.Config

	// global is what applies to a tenant with no overrides, and what the
	// operator-facing endpoints describe. tenants holds one view per tenant
	// that narrows it.
	global  tenantView
	tenants map[string]tenantView

	// limiter holds live token buckets, so it belongs to the gateway rather
	// than to the route table: Routes may be called more than once, and a
	// limiter rebuilt per call would hand every caller a full bucket.
	limiter *rateLimiter

	router   router.Router
	guard    *sandbox.RuleGuard
	ingress  *sandbox.IngressGuard
	sessions *session.Store
	cache    cache.Store
	ledger   tokens.LedgerStore
	prices   *tokens.PriceBook
	counter  tokens.Counter
	audit    audit.Sink
	metrics  *gatewayMetrics

	local      llm.Client
	cloud      llm.Client
	localModel string
	cloudModel string
	preamble   string

	started time.Time
}

// tenantView is the set of controls in force for one tenant.
//
// A tenant may narrow what the operator configured globally — a stricter egress
// policy, a different rule pack — so each override needs its own compiled
// detector and its own compression pipeline: the pipeline captures its detector
// at construction, and a Masker cannot be swapped mid-request without racing
// every other request using it.
//
// Views are built once, at startup or at reload, never per request. There are
// as many as there are tenant labels, which is a handful, and building one
// compiles every regex in its rule packs.
type tenantView struct {
	engine   redact.Detector
	pipeline *compressor.Pipeline
	masker   *compressor.Masker
	policy   policy.Policy
}

// viewFor returns the controls in force for a tenant, falling back to the
// global ones for a tenant with no overrides.
func (g *Gateway) viewFor(tenant string) tenantView {
	if v, ok := g.tenants[tenant]; ok {
		return v
	}
	return g.global
}

// gatewayMetrics holds the registered metric handles.
type gatewayMetrics struct {
	reg       *metrics.Registry
	requests  *metrics.Counter
	blocked   *metrics.Counter
	redacted  *metrics.Counter
	policyDec *metrics.Counter
	cacheOps  *metrics.Counter
	upstream  *metrics.Counter
	injection *metrics.Counter
}

// New builds a Gateway from config. It returns an error when a rule pack,
// price book, or audit destination cannot be loaded, so a misconfigured control
// prevents startup instead of silently doing nothing.
func New(cfg config.Config) (*Gateway, error) {
	engine, err := BuildRedactEngine(cfg)
	if err != nil {
		return nil, err
	}

	prices := tokens.NewPriceBook()
	if cfg.PriceBookPath != "" {
		if err := prices.LoadFile(cfg.PriceBookPath); err != nil {
			return nil, err
		}
	}
	if cfg.LocalCostPerM > 0 {
		prices.SetLocalCost(cfg.LocalCostPerM)
	}

	local := llm.NewClient(backendConfig("local", cfg.Local, cfg))
	cloud := llm.NewClient(backendConfig("cloud", cfg.Cloud, cfg))

	return NewWith(cfg, engine, prices, local, cloud, router.NewHeuristicRouter())
}

// NewWith builds a Gateway with injected backends, detector and router. Tests
// use it to drive the full request path without network access, and the
// enterprise edition uses it to substitute its own implementations of the
// package seams without forking the request path.
func NewWith(
	cfg config.Config,
	engine redact.Detector,
	prices *tokens.PriceBook,
	local, cloud llm.Client,
	rtr router.Router,
) (*Gateway, error) {
	guard := sandbox.NewGuard()
	if len(cfg.GuardOverrides) > 0 {
		guard = guard.WithOverrides(cfg.GuardOverrides)
	}

	g := &Gateway{
		cfg:        cfg,
		global:     newTenantView(engine, cfg.Policy),
		router:     rtr,
		guard:      guard,
		ingress:    sandbox.NewIngressGuard(),
		sessions:   session.NewStore(cfg.SessionTTL, cfg.SessionMax),
		cache:      cache.New(cfg.CacheTTL, cfg.CacheMax),
		prices:     prices,
		ledger:     tokens.NewLedger(prices),
		counter:    tokens.NewHeuristic(),
		audit:      audit.Nop{},
		local:      local,
		cloud:      cloud,
		localModel: cfg.Local.Model,
		cloudModel: cfg.Cloud.Model,
		preamble:   cfg.SystemPreamble,
		started:    time.Now(),
	}

	g.limiter = newRateLimiter(&g.cfg)

	views, err := buildTenantViews(cfg, engine)
	if err != nil {
		return nil, err
	}
	g.tenants = views

	g.metrics = g.registerMetrics()
	return g, nil
}

// SetAudit attaches an audit destination. Passing nil restores the no-op sink
// rather than leaving a nil interface the request path would panic on.
func (g *Gateway) SetAudit(a audit.Sink) {
	if a == nil {
		g.audit = audit.Nop{}
		return
	}
	g.audit = a
}

// SetCache substitutes the answer cache — a semantic tier, or a store shared
// across gateway nodes.
//
// Whatever is installed inherits the obligation documented on cache.Store: it
// holds pre-hydration text only. A tier that stores hydrated answers serves one
// session's real values to another, which is the failure the whole caching
// design is arranged to prevent.
func (g *Gateway) SetCache(c cache.Store) {
	if c == nil {
		return
	}
	g.cache = c
}

// SetLedger substitutes the accounting backend, typically to make quota
// consumption survive a restart.
func (g *Gateway) SetLedger(l tokens.LedgerStore) {
	if l == nil {
		return
	}
	g.ledger = l
}

// The setters above are wiring, not runtime configuration: call them during
// startup, before the server begins accepting requests. The metric gauges read
// these fields at scrape time rather than capturing them, so a substitution
// made at startup is reflected correctly — but the fields are not guarded, and
// swapping one while requests are in flight is a data race.

// Close releases background resources.
func (g *Gateway) Close() {
	if g.sessions != nil {
		g.sessions.Close()
	}
}

// newTenantView compiles one tenant's controls.
//
// Tool-call arguments are masked but not compressed, so the view carries a bare
// Masker alongside the full pipeline: Drain and ASTPrune are lossy by design,
// and a lossy stage applied to a JSON argument string produces something the
// tool cannot be called with. Masking alone is reversible.
func newTenantView(engine redact.Detector, p policy.Policy) tenantView {
	return tenantView{
		engine: engine,
		pipeline: compressor.NewPipelineWith(
			compressor.NewMaskerWith(engine),
			compressor.NewDrain(),
			compressor.NewRefDict(),
			compressor.NewASTPruner(),
		),
		masker: compressor.NewMaskerWith(engine),
		policy: p,
	}
}

// buildTenantViews compiles a view for every tenant whose configuration differs
// from the global one. A tenant that overrides nothing gets no entry and falls
// through to the global view, so the common deployment allocates nothing extra.
//
// A tenant that overrides only its policy shares the global detector rather
// than compiling an identical copy of it.
func buildTenantViews(cfg config.Config, global redact.Detector) (map[string]tenantView, error) {
	out := map[string]tenantView{}
	for _, label := range cfg.TenantLabels() {
		t, ok := cfg.Tenants[label]
		if !ok {
			continue
		}
		engine := global
		if len(t.RedactPacks) > 0 || len(t.DisableRules) > 0 || len(t.InternalDomains) > 0 {
			packs, disable, domains := cfg.RedactionFor(label)
			e, err := BuildRedactEngine(config.Config{
				RedactPacks:     packs,
				DisableRules:    disable,
				InternalDomains: domains,
				DisableEntropy:  cfg.DisableEntropy,
				RedactRuleDir:   cfg.RedactRuleDir,
			})
			if err != nil {
				return nil, fmt.Errorf("tenant %q: %w", label, err)
			}
			engine = e
		}
		out[label] = newTenantView(engine, cfg.PolicyFor(label))
	}
	return out, nil
}

// BuildRedactEngine assembles the detection engine from config, including any
// site-specific rule packs.
//
// Exported because the enterprise edition's composite detector wraps the
// community engine rather than replacing it — a detector that could detect
// *less* than this one would quietly weaken the leak guarantee its own test
// corpus is written against.
func BuildRedactEngine(cfg config.Config) (*redact.Engine, error) {
	opts := redact.Options{
		Packs:           cfg.RedactPacks,
		DisableRules:    cfg.DisableRules,
		InternalDomains: cfg.InternalDomains,
		DisableEntropy:  cfg.DisableEntropy,
	}
	if cfg.RedactRuleDir != "" {
		extra, err := redact.RulesFromDir(cfg.RedactRuleDir)
		if err != nil {
			return nil, fmt.Errorf("load custom rule packs: %w", err)
		}
		opts.ExtraRules = extra
	}
	return redact.NewEngine(opts)
}

// backendConfig converts config.Backend into an llm.ProviderConfig.
func backendConfig(name string, b config.Backend, cfg config.Config) llm.ProviderConfig {
	return llm.ProviderConfig{
		Name:             name,
		Provider:         b.Provider,
		BaseURL:          b.BaseURL,
		APIKey:           b.APIKey,
		APIVersion:       b.APIVersion,
		Deployment:       b.Deployment,
		Timeout:          b.Timeout,
		Retries:          cfg.Retries,
		BreakerThreshold: cfg.BreakerThreshold,
		BreakerCooldown:  cfg.BreakerCooldown,
	}
}

// registerMetrics declares PhiGate's metric series.
func (g *Gateway) registerMetrics() *gatewayMetrics {
	reg := metrics.New()
	m := &gatewayMetrics{
		reg:       reg,
		requests:  reg.Counter("phigate_requests_total", "Requests handled, by route and outcome.", "route", "backend", "status"),
		blocked:   reg.Counter("phigate_egress_blocked_total", "Responses withheld by the egress guardrail, by rule.", "rule", "severity"),
		redacted:  reg.Counter("phigate_redactions_total", "Sensitive values masked, by data classification.", "category"),
		policyDec: reg.Counter("phigate_policy_decisions_total", "Egress policy verdicts, by action.", "action"),
		cacheOps:  reg.Counter("phigate_cache_total", "Template cache lookups.", "result"),
		upstream:  reg.Counter("phigate_upstream_calls_total", "Upstream backend calls.", "backend", "outcome"),
		injection: reg.Counter("phigate_ingress_suspicious_total", "Inbound payloads matching prompt-injection patterns.", "rule"),
	}

	reg.Gauge("phigate_tokens_saved_total", "Cumulative upstream tokens avoided.",
		func() float64 { return float64(g.ledger.Totals().TokensSaved) })
	reg.Gauge("phigate_cost_saved_total", "Cumulative upstream spend avoided, in the ledger currency.",
		func() float64 { return g.ledger.Totals().CostSaved })
	reg.Gauge("phigate_cost_spent_total", "Cumulative cloud spend, in the ledger currency.",
		func() float64 { return g.ledger.Totals().CloudCost })
	reg.Gauge("phigate_cache_hit_ratio", "Template cache hit ratio.",
		func() float64 { return g.cache.Stats().HitRate })
	reg.Gauge("phigate_cache_entries", "Entries currently held in the template cache.",
		func() float64 { return float64(g.cache.Stats().Entries) })
	reg.Gauge("phigate_sessions_active", "Live compression sessions.",
		func() float64 { return float64(g.sessions.Len()) })
	reg.Gauge("phigate_uptime_seconds", "Process uptime.",
		func() float64 { return time.Since(g.started).Seconds() })
	return m
}
