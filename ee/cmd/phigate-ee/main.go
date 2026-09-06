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
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/phigate/phigate/ee/audit/worm"
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

	g, err := gateway.NewWith(cfg, detector, prices,
		llm.NewClient(gateway.BackendConfig("local", cfg.Local, cfg)),
		llm.NewClient(gateway.BackendConfig("cloud", cfg.Cloud, cfg)),
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

	// Still to land, each substituting a seam CE already declares:
	//
	//	g.SetCache(semantic.New(...))   // embedded HNSW tier, via cache.ProbeStore
	//	g.SetLedger(durable.New(...))   // survives a rolling update, per tenant
	//	detector                        // dictionary/SLM-backed, composed with CE's

	srv := gateway.NewServer(cfg, g)
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
	return gateway.BuildRedactEngine(cfg)
}
