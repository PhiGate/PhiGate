// Package gateway exposes PhiGate's OpenAI-compatible HTTP surface and wires the
// compression pipeline (and, in later steps, the routing and sandbox layers)
// into the request path.
package gateway

import (
	"net/http"

	"github.com/tenkan/phigate/internal/config"
)

// Routes returns the configured HTTP handler for the gateway.
func (g *Gateway) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", g.handleChatCompletions)
	mux.HandleFunc("/debug/compress", g.handleDebugCompress)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// NewServer builds an *http.Server from cfg serving the gateway routes.
func NewServer(cfg config.Config) *http.Server {
	g := NewGateway(cfg)
	return &http.Server{
		Addr:    cfg.Addr,
		Handler: g.Routes(),
	}
}
