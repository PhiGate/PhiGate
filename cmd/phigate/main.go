// Command phigate starts the PhiGate AI gateway: an OpenAI-compatible reverse
// proxy that compresses and anonymises enterprise logs and code, enforces an
// egress policy over the result, routes each request between a local SLM and a
// cloud LLM, and vets the answer before it reaches an operator.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/phigate/phigate/internal/audit"
	"github.com/phigate/phigate/internal/config"
	"github.com/phigate/phigate/internal/gateway"
	"github.com/phigate/phigate/internal/redact"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("phigate: %v", err)
	}
}

func run() error {
	addr := flag.String("addr", "", "listen address (overrides PHIGATE_ADDR)")
	showRules := flag.Bool("rules", false, "print the effective redaction rule packs and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe the local gateway's /healthz and exit 0 or 1")
	flag.Parse()

	if *showRules {
		return printRules()
	}
	if *healthcheck {
		return probeSelf(*addr)
	}

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if *addr != "" {
		cfg.Addr = *addr
	}

	auditLog, closer, err := audit.New(audit.Options{Path: cfg.AuditPath, Disabled: cfg.AuditDisabled})
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer func() { _ = closer.Close() }()

	g, err := gateway.New(cfg)
	if err != nil {
		return err
	}
	g.SetAudit(auditLog)
	defer g.Close()

	srv := gateway.NewServer(cfg, g)
	banner(cfg)

	// Serve until a termination signal arrives, then drain.
	//
	// Graceful shutdown matters more here than in a typical service: PhiGate
	// proxies long-running streaming completions, and killing the process
	// mid-stream leaves the caller with a truncated answer while the upstream
	// request has already been billed.
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-stop:
		log.Printf("received %s; draining for up to %s", sig, cfg.ShutdownGrace)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Print("stopped cleanly")
	return nil
}

// banner prints the effective configuration, so the controls actually in force
// are visible in the startup logs rather than having to be inferred from the
// environment.
func banner(cfg config.Config) {
	log.Printf("PhiGate listening on %s", cfg.Addr)
	log.Printf("  local backend  : %s %s (model %s)", cfg.Local.Provider, cfg.Local.BaseURL, cfg.Local.Model)
	log.Printf("  cloud backend  : %s %s (model %s)", cfg.Cloud.Provider, cfg.Cloud.BaseURL, cfg.Cloud.Model)
	log.Printf("  egress policy  : %s", cfg.Policy.Describe())
	log.Printf("  redaction      : packs=%v internal-domains=%v entropy=%v",
		orAll(cfg.RedactPacks), cfg.InternalDomains, !cfg.DisableEntropy)
	log.Printf("  template cache : enabled=%v ttl=%s max=%d", cfg.CacheEnabled, cfg.CacheTTL, cfg.CacheMax)
	log.Printf("  sessions       : ttl=%s max=%d header=%s", cfg.SessionTTL, cfg.SessionMax, cfg.SessionHeader)

	if len(cfg.APIKeys) == 0 {
		log.Print("  auth           : ⚠️  DISABLED — anyone who can reach this port can spend your upstream quota")
	} else {
		log.Printf("  auth           : %d API key(s) configured", len(cfg.APIKeys))
	}
	if cfg.AuditDisabled {
		log.Print("  audit          : ⚠️  DISABLED")
	} else if cfg.AuditPath != "" {
		log.Printf("  audit          : %s", cfg.AuditPath)
	} else {
		log.Print("  audit          : stderr (JSON)")
	}
	if cfg.DebugEnabled {
		log.Print("  ⚠️  PHIGATE_DEBUG is on: /debug/compress returns plaintext of every masked value")
	}

	log.Print("  endpoints      : POST /v1/chat/completions · GET /v1/models · GET /v1/phigate/stats")
	log.Printf("                   GET %s · GET /healthz · GET /readyz", cfg.MetricsPath)
	if cfg.DashboardOn {
		log.Print("                   GET /dashboard")
	}
}

// probeSelf performs the container health check by actually calling /healthz.
//
// The image is distroless and has no shell or curl, so the binary has to be its
// own health probe. Checking something cheap and local — like printing the rule
// packs — would report healthy even with the HTTP server wedged, which is the
// one failure a health check exists to catch.
func probeSelf(addrFlag string) error {
	addr := addrFlag
	if addr == "" {
		addr = os.Getenv("PHIGATE_ADDR")
	}
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("cannot parse listen address %q: %w", addr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return fmt.Errorf("health probe failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe returned %d", resp.StatusCode)
	}
	return nil
}

// printRules lists the built-in rule packs, for operators reviewing coverage
// before a deployment.
func printRules() error {
	packs, err := redact.LoadBuiltinPacks()
	if err != nil {
		return err
	}
	for _, p := range packs {
		fmt.Printf("\n== pack %s ==\n%s\n\n", p.Name, p.Description)
		for _, r := range p.Rules {
			state := ""
			if r.Disabled {
				state = "  [disabled by default]"
			}
			fmt.Printf("  %-26s %-11s prio=%-4d%s\n", r.Name, r.Category, r.Priority, state)
			if r.Description != "" {
				fmt.Printf("  %-26s %s\n", "", r.Description)
			}
		}
	}
	fmt.Println()
	return nil
}

func orAll(v []string) any {
	if len(v) == 0 {
		return "all"
	}
	return v
}
