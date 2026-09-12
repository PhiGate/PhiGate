// SPDX-License-Identifier: BUSL-1.1

// Command phigate-ee is the enterprise edition of the PhiGate gateway.
//
// It contains no request-path logic of its own. The pipeline, the redaction
// engine, the egress policy and the sandbox all come from the community
// edition; EE's job is to substitute implementations of the seams that CE
// declares — cache.Store, tokens.LedgerStore, redact.Detector, audit.Sink —
// and then run the same server.
//
// Keeping the fork at the seams rather than in the handler is what stops the
// two editions from drifting. A bug fixed in CE is fixed in EE, and a leak test
// that passes in CE means something for EE too.
//
// # Why this file exists before any EE feature does
//
// It is the compile-time probe for the one assumption the whole Open-Core
// layout rests on: that a nested module may import the parent module's
// internal/ packages. The internal rule is path-based, and this package's
// import path sits inside the tree rooted at github.com/phigate/phigate/, so it
// should be permitted. If cmd/go's module-aware check disagrees, this file
// fails to build and the fix is known: promote the seam interfaces out of
// internal/ into a public package that both editions bind to.
//
// Settle it with `make ee`.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/phigate/phigate/ee/cache/shared"
	"github.com/phigate/phigate/ee/observability/tracing"
	"github.com/phigate/phigate/internal/cache"
	"log"
	"os"
	"strconv"

	"github.com/phigate/phigate/ee/audit/worm"
	"github.com/phigate/phigate/ee/redact/slm"
	"github.com/phigate/phigate/ee/tokens/durable"
	"github.com/phigate/phigate/internal/config"
	"github.com/phigate/phigate/internal/gateway"
	"github.com/phigate/phigate/internal/llm"
	"github.com/phigate/phigate/internal/redact"
	"github.com/phigate/phigate/internal/router"
	"github.com/phigate/phigate/internal/tokens"
	"time"
)

func main() {
	// `phigate-ee audit verify -dir <path>` recomputes the whole hash chain and
	// reports the first break. It is a subcommand rather than an endpoint
	// because an auditor verifying a log should not have to trust, or even
	// reach, the process that wrote it.
	if len(os.Args) > 2 && os.Args[1] == "audit" && os.Args[2] == "verify" {
		if err := verifyAudit(os.Args[3:]); err != nil {
			log.Fatalf("phigate-ee: %v", err)
		}
		return
	}

	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatalf("phigate-ee: %v", err)
	}

	// The detector is the one seam that cannot be substituted after
	// construction: the compression pipeline captures it, and swapping a Masker
	// while requests are in flight is a data race. So EE builds the gateway
	// through NewWith rather than New.
	//
	// Whatever goes here wraps the community engine, never replaces it. A
	// detector that could find *less* than CE's would quietly weaken the leak
	// guarantee that CE's own corpus is written against, so composition is the
	// rule and the EE detector's tests assert the superset property directly.
	detector, err := enterpriseDetector(cfg)
	if err != nil {
		log.Fatalf("phigate-ee: %v", err)
	}

	prices := tokens.NewPriceBook()
	if cfg.PriceBookPath != "" {
		if err := prices.LoadFile(cfg.PriceBookPath); err != nil {
			log.Fatalf("phigate-ee: %v", err)
		}
	}
	if cfg.LocalCostPerM > 0 {
		prices.SetLocalCost(cfg.LocalCostPerM)
	}

	// Tracing is installed before the gateway so the upstream clients can be
	// built with an instrumented transport. A trace that stops at PhiGate's
	// own span cannot answer the only question anyone asks of it: whether a
	// slow request was the pipeline or the model.
	traceCfg := tracing.Config{
		Endpoint:    os.Getenv("PHIGATE_EE_OTLP_ENDPOINT"),
		Insecure:    os.Getenv("PHIGATE_EE_OTLP_INSECURE") == "true",
		ServiceName: envOr("PHIGATE_EE_OTLP_SERVICE", "phigate"),
		Version:     envOr("PHIGATE_EE_VERSION", "dev"),
		SampleRatio: sampleRatio(),
	}
	shutdownTracing, err := tracing.Init(context.Background(), traceCfg)
	if err != nil {
		log.Fatalf("phigate-ee: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// Flushing on the way out matters: a gateway that exits without it
		// loses the trace of whatever it was doing when it was asked to stop,
		// which is the trace somebody wanted.
		_ = shutdownTracing(ctx)
	}()

	var clientOpts []llm.Option
	if traceCfg.Enabled() {
		clientOpts = append(clientOpts, llm.WithHTTPClient(tracing.InstrumentClient(nil)))
	}
	g, err := gateway.NewWith(cfg, detector, prices,
		llm.NewClient(gateway.BackendConfig("local", cfg.Local, cfg), clientOpts...),
		llm.NewClient(gateway.BackendConfig("cloud", cfg.Cloud, cfg), clientOpts...),
		router.NewHeuristicRouter())
	if err != nil {
		log.Fatalf("phigate-ee: %v", err)
	}
	defer g.Close()

	// The audit seam: an append-only chain in which altering, removing or
	// inserting a record is detectable. PHIGATE_EE_AUDIT_DIR selects it;
	// without it EE would be CE's file logger under an EE name.
	dir := os.Getenv("PHIGATE_EE_AUDIT_DIR")
	if dir == "" {
		log.Fatalf("phigate-ee: set PHIGATE_EE_AUDIT_DIR to the directory the " +
			"tamper-evident audit chain lives in. Without it this binary would be " +
			"the community edition under an enterprise name, which is a lie told " +
			"to whoever runs it; run cmd/phigate instead.")
	}
	sink, err := worm.New(worm.Options{
		Dir:       dir,
		Retention: auditRetention(),
	})
	if err != nil {
		log.Fatalf("phigate-ee: %v", err)
	}
	defer func() { _ = sink.Close() }()
	g.SetAudit(sink)

	// The accounting seam: per-tenant consumption that survives a rolling
	// update, which is what turns CE's best-effort budget into a real one. It
	// is optional — a deployment with no budgets does not need it — and the
	// community ledger stays underneath it for the process-wide FinOps figures.
	if path := os.Getenv("PHIGATE_EE_LEDGER_PATH"); path != "" {
		ledger, err := durable.Open(durable.Options{
			Path:        path,
			Inner:       tokens.NewLedger(prices),
			PeriodStart: cfg.PeriodStart,
		})
		if err != nil {
			log.Fatalf("phigate-ee: %v", err)
		}
		defer func() { _ = ledger.Close() }()
		g.SetLedger(ledger)
		log.Printf("  token ledger   : %s (%s periods, %s)",
			path, cfg.BudgetPeriod, cfg.BudgetTimezone)
	}

	if os.Getenv("PHIGATE_EE_NAME_DETECTION") == "true" {
		log.Printf("  name detection : on (local model %s, composed with the regex engine)",
			cfg.Local.Model)
	}

	if addr := os.Getenv("PHIGATE_EE_CACHE_REDIS"); addr != "" {
		backend, err := shared.NewRedis(shared.RedisOptions{
			Addr:     addr,
			Username: os.Getenv("PHIGATE_EE_CACHE_REDIS_USERNAME"),
			Password: os.Getenv("PHIGATE_EE_CACHE_REDIS_PASSWORD"),
			TLS:      os.Getenv("PHIGATE_EE_CACHE_REDIS_TLS") == "true",
		})
		if err != nil {
			log.Fatalf("phigate-ee: %v", err)
		}
		// Local first, shared behind it. The tier is installed through the
		// cache.Store seam, so nothing on the request path learns there is a
		// second tier — and nothing fails if it goes away.
		store := shared.New(cache.New(cfg.CacheTTL, cfg.CacheMax), backend, shared.Options{
			TTL:    cfg.CacheTTL,
			Prefix: cacheKeyPrefix(),
		})
		defer func() { _ = store.Close() }()
		g.SetCache(store)

		// Report reachability rather than require it. A cache tier that stops
		// the gateway from starting when it is unavailable would make the
		// product less available than it was without one.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		reach := "unreachable at startup, will retry per request"
		if err := backend.Ping(ctx); err == nil {
			reach = "reachable"
		}
		cancel()
		log.Printf("  shared cache   : redis %s (%s, prefix %q, ttl %s)",
			addr, reach, cacheKeyPrefix(), cfg.CacheTTL)
	}

	// Still to land, substituting the seam CE declares that is not yet filled:
	//
	//	g.SetCache(semantic.New(...))   // embedded HNSW tier, via cache.ProbeStore

	srv := gateway.NewServer(cfg, g)
	if traceCfg.Enabled() {
		// Wrap the handler NewServer built rather than rebuild the server, so
		// the timeouts and the streaming-safe WriteTimeout stay exactly as CE
		// configured them.
		srv.Handler = tracing.Middleware(traceCfg.ServiceName, srv.Handler)
		log.Printf("  tracing        : otlp %s (service %q, sampling %s)",
			traceCfg.Endpoint, traceCfg.ServiceName, samplingLabel())
	}
	log.Printf("phigate-ee listening on %s", srv.Addr)
	log.Printf("  audit chain    : %s (retention %s)", dir, auditRetention())
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("phigate-ee: %v", err)
	}
}

// auditRetention reads how long segments must be kept.
//
// The default is zero, which deletes nothing. A retention policy nobody
// configured should not be removing audit records, and an operator who has not
// decided how long to keep them has not decided to throw any away either.
func auditRetention() time.Duration {
	v := os.Getenv("PHIGATE_EE_AUDIT_RETENTION")
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("phigate-ee: PHIGATE_EE_AUDIT_RETENTION: %v", err)
	}
	return d
}

// verifyAudit recomputes a chain and reports what it found.
func verifyAudit(args []string) error {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	dir := fs.String("dir", os.Getenv("PHIGATE_EE_AUDIT_DIR"), "audit chain directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("audit verify: -dir is required")
	}

	rep, err := worm.Verify(*dir)
	if err != nil {
		fmt.Printf("FAIL  %v\n", err)
		fmt.Printf("      %d record(s) over %d segment(s) verified before the break\n",
			rep.Records, rep.Segments)
		os.Exit(1)
	}
	fmt.Printf("OK    %d record(s) over %d segment(s), %d checkpoint(s)\n",
		rep.Records, rep.Segments, rep.Checkpoints)
	if rep.First != "" {
		fmt.Printf("      %s .. %s\n", rep.First, rep.Last)
	}
	fmt.Printf("      head %s\n", rep.Head)
	if rep.Dropped > 0 {
		// Not a failure: the chain is intact and says so itself. But an
		// operator has to know the log is missing events, and why.
		fmt.Printf("WARN  %d event(s) were dropped by a full audit queue and are "+
			"recorded as gaps in the chain\n", rep.Dropped)
	}
	return nil
}

// enterpriseDetector returns the detector EE runs with.
//
// It is the community engine until an enterprise detector exists. Returning
// CE's engine rather than nil keeps the wiring above honest: the seam is
// resolved and exercised, and the day a dictionary- or SLM-backed detector
// lands it is composed here and nothing else in this file changes.
func enterpriseDetector(cfg config.Config) (redact.Detector, error) {
	engine, err := gateway.BuildRedactEngine(cfg)
	if err != nil {
		return nil, err
	}
	if os.Getenv("PHIGATE_EE_NAME_DETECTION") != "true" {
		return engine, nil
	}

	// The adjudicating model is the *local* one, always. A detector whose job
	// is to find personal data cannot send the text it is inspecting to a cloud
	// provider in order to decide whether it contains personal data — that is
	// the exfiltration the gateway exists to prevent, performed by the gateway.
	local := llm.NewClient(gateway.BackendConfig("local", cfg.Local, cfg))
	return slm.New(slm.Options{
		Engine:     engine,
		Recognizer: slm.NewModelRecognizer(local, cfg.Local.Model),
	})
}

// cacheKeyPrefix namespaces shared cache keys.
//
// One Redis often serves several deployments, and two PhiGates sharing a
// keyspace would serve each other's answers — which is correct only if they
// also share a rule set and a model, and nothing here can check that. The
// prefix makes the assumption explicit instead of silent.
func cacheKeyPrefix() string {
	if p := os.Getenv("PHIGATE_EE_CACHE_PREFIX"); p != "" {
		return p
	}
	return "phigate:"
}

// envOr reads an environment variable with a fallback.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// sampleRatio reads the head sampling fraction.
//
// Zero — sample everything — is the right default here. A gateway in front of
// AIOps traffic sees low request volume by the standards of a web tier, and the
// traces worth having are the slow and the blocked ones, which is exactly what
// a ratio sampler throws away at random.
func sampleRatio() float64 {
	v := os.Getenv("PHIGATE_EE_OTLP_SAMPLE_RATIO")
	if v == "" {
		return 0
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f < 0 || f > 1 {
		log.Printf("  tracing        : ignoring PHIGATE_EE_OTLP_SAMPLE_RATIO=%q, sampling everything", v)
		return 0
	}
	return f
}

func samplingLabel() string {
	if r := sampleRatio(); r > 0 {
		return strconv.FormatFloat(r, 'g', -1, 64)
	}
	return "all"
}
