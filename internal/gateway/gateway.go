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
	cfg      config.Config
	pipeline *compressor.Pipeline
	router   router.Router
	guard    *sandbox.RuleGuard
	ingress  *sandbox.IngressGuard
	policy   policy.Policy
	sessions *session.Store
	cache    cache.Store
	ledger   tokens.LedgerStore
	prices   *tokens.PriceBook
	counter  tokens.Counter
	audit    audit.Sink
	metrics  *gatewayMetrics
	engine   redact.Detector

	local      llm.Client
	cloud      llm.Client
	localModel string
	cloudModel string
	preamble   string

	started time.Time
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
	engine, err := buildRedactEngine(cfg)
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
		cfg: cfg,
		pipeline: compressor.NewPipelineWith(
			compressor.NewMaskerWith(engine),
			compressor.NewDrain(),
			compressor.NewRefDict(),
			compressor.NewASTPruner(),
		),
		router:     rtr,
		guard:      guard,
		ingress:    sandbox.NewIngressGuard(),
		policy:     cfg.Policy,
		sessions:   session.NewStore(cfg.SessionTTL, cfg.SessionMax),
		cache:      cache.New(cfg.CacheTTL, cfg.CacheMax),
		prices:     prices,
		ledger:     tokens.NewLedger(prices),
		counter:    tokens.NewHeuristic(),
		audit:      audit.Nop{},
		engine:     engine,
		local:      local,
		cloud:      cloud,
		localModel: cfg.Local.Model,
		cloudModel: cfg.Cloud.Model,
		preamble:   cfg.SystemPreamble,
		started:    time.Now(),
	}
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

// buildRedactEngine assembles the detection engine from config, including any
// site-specific rule packs.
func buildRedactEngine(cfg config.Config) (*redact.Engine, error) {
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
