// Command phigate starts the PhiGate AI gateway: an OpenAI-compatible reverse
// proxy that compresses and anonymises enterprise logs/code, then intelligently
// routes each request between a local SLM (Phi-4-mini) and a cloud LLM.
package main

import (
	"flag"
	"log"

	"github.com/tenkan/phigate/internal/config"
	"github.com/tenkan/phigate/internal/gateway"
)

func main() {
	cfg := config.FromEnv()
	addr := flag.String("addr", cfg.Addr, "listen address")
	flag.Parse()
	cfg.Addr = *addr

	srv := gateway.NewServer(cfg)
	log.Printf("PhiGate listening on %s", cfg.Addr)
	log.Printf("  local backend : %s (model %s)", cfg.LocalBaseURL, cfg.LocalModel)
	log.Printf("  cloud backend : %s (model %s)", cfg.CloudBaseURL, cfg.CloudModel)
	log.Printf("  POST /v1/chat/completions   (OpenAI-compatible, routed)")
	log.Printf("  POST /debug/compress        (inspect compression + routing)")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
