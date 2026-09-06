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
	"log"

	"github.com/phigate/phigate/internal/config"
	"github.com/phigate/phigate/internal/gateway"
	"github.com/phigate/phigate/internal/llm"
	"github.com/phigate/phigate/internal/redact"
	"github.com/phigate/phigate/internal/router"
	"github.com/phigate/phigate/internal/tokens"
)

func main() {
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

	g, err := gateway.NewWith(cfg, detector, prices,
		llm.NewClient(gateway.BackendConfig("local", cfg.Local, cfg)),
		llm.NewClient(gateway.BackendConfig("cloud", cfg.Cloud, cfg)),
		router.NewHeuristicRouter())
	if err != nil {
		log.Fatalf("phigate-ee: %v", err)
	}
	defer g.Close()

	// The remaining substitutions are registered here as each phase lands:
	//
	//	g.SetAudit(worm.New(...))       // append-only, retention proofs
	//	g.SetCache(semantic.New(...))   // embedded HNSW tier, via cache.ProbeStore
	//	g.SetLedger(durable.New(...))   // survives a rolling update, per tenant
	//
	// Until then this binary would be CE under an EE name, and shipping that
	// would be a lie told to whoever runs it. It refuses to serve instead.
	srv := gateway.NewServer(cfg, g)
	log.Fatalf("phigate-ee: no enterprise implementations are registered yet; "+
		"run the community edition instead (cmd/phigate). "+
		"Seams resolved and server buildable on %s.", srv.Addr)
}

// enterpriseDetector returns the detector EE runs with.
//
// It is the community engine until an enterprise detector exists. Returning
// CE's engine rather than nil keeps the wiring above honest: the seam is
// resolved and exercised, and the day a dictionary- or SLM-backed detector
// lands it is composed here and nothing else in this file changes.
func enterpriseDetector(cfg config.Config) (redact.Detector, error) {
	return gateway.BuildRedactEngine(cfg)
}
