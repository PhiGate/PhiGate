package gateway

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/tenkan/phigate/internal/compressor"
	"github.com/tenkan/phigate/internal/config"
	"github.com/tenkan/phigate/internal/llm"
	"github.com/tenkan/phigate/internal/router"
	"github.com/tenkan/phigate/internal/sandbox"
	"github.com/tenkan/phigate/internal/types"
)

// Gateway holds the long-lived components shared across requests: the
// compression pipeline, the routing classifier, the local/cloud LLM backends,
// and (from Step 3) the egress sandbox.
type Gateway struct {
	pipeline *compressor.Pipeline
	router   router.Router
	guard    sandbox.Guard

	local      llm.Client
	cloud      llm.Client
	localModel string
	cloudModel string
	preamble   string
}

// NewGateway constructs a Gateway from config, building the default compression
// pipeline, heuristic router, and OpenAI-compatible local/cloud clients.
func NewGateway(cfg config.Config) *Gateway {
	return NewGatewayWith(cfg,
		llm.NewOpenAIClient("local", cfg.LocalBaseURL, cfg.LocalAPIKey),
		llm.NewOpenAIClient("cloud", cfg.CloudBaseURL, cfg.CloudAPIKey),
		router.NewHeuristicRouter(),
	)
}

// NewGatewayWith builds a Gateway with injected backends/router (used in tests).
func NewGatewayWith(cfg config.Config, local, cloud llm.Client, rtr router.Router) *Gateway {
	return &Gateway{
		pipeline:   compressor.NewPipeline(),
		router:     rtr,
		guard:      sandbox.NewGuard(),
		local:      local,
		cloud:      cloud,
		localModel: cfg.LocalModel,
		cloudModel: cfg.CloudModel,
		preamble:   cfg.SystemPreamble,
	}
}

// handleChatCompletions implements the OpenAI-compatible
// POST /v1/chat/completions endpoint and is the heart of the gateway:
//
//	compress -> route (local vs cloud) -> dispatch -> hydrate -> respond
//
// Sensitive values never leave the process un-anonymized; the upstream model
// only ever sees <V*>/#REF*/AST placeholders, and the operator only ever sees
// the hydrated answer.
func (g *Gateway) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var req types.ChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	sess := compressor.NewSession()

	// 1. Compress every message; keep roles intact.
	compressedMsgs := make([]types.Message, 0, len(req.Messages)+1)
	var routeParts []string
	var origRunes, compRunes int
	for _, m := range req.Messages {
		c, err := g.pipeline.Compress(m.Content, sess)
		if err != nil {
			http.Error(w, "compression error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		origRunes += len([]rune(m.Content))
		compRunes += len([]rune(c))
		compressedMsgs = append(compressedMsgs, types.Message{Role: m.Role, Content: c})
		if m.Role != "system" {
			routeParts = append(routeParts, c)
		}
	}

	// 2. Route on the compressed user-visible content.
	decision, err := g.router.Route(r.Context(), strings.Join(routeParts, "\n"))
	if err != nil {
		http.Error(w, "routing error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Streaming requests take the SSE path so the egress sandbox can inspect
	//    output token-by-token (Step 3).
	if req.Stream {
		g.streamResponse(w, r, sess, &req, compressedMsgs, decision, origRunes, compRunes)
		return
	}

	// 4. Dispatch to the chosen backend, with local -> cloud fallback.
	client, model := g.backendFor(decision.Target)
	upstream := g.buildUpstream(model, req, compressedMsgs, false)

	backend := client.Name()
	reason := decision.Reason
	resp, err := client.Chat(r.Context(), upstream)
	if err != nil && decision.Target == router.TargetLocal {
		log.Printf("local backend failed (%v); falling back to cloud", err)
		client, model = g.cloud, g.cloudModel
		upstream = g.buildUpstream(model, req, compressedMsgs, false)
		backend = client.Name()
		reason = decision.Reason + " -> fell back to cloud after local error"
		resp, err = client.Chat(r.Context(), upstream)
	}
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}

	// 5. Hydrate the answer, then run the egress guardrail before the operator
	//    ever sees it. A blocked choice is redacted, not forwarded.
	var blockedRule string
	for i := range resp.Choices {
		hydrated := sess.Dict.Hydrate(resp.Choices[i].Message.Content)
		if v := g.guard.Inspect(hydrated); v.Blocked {
			blockedRule = v.Rule
			log.Printf("egress BLOCKED rule=%s match=%q", v.Rule, v.Match)
			resp.Choices[i].Message.Content = blockedNotice(v)
			resp.Choices[i].FinishReason = "content_filter"
		} else {
			resp.Choices[i].Message.Content = hydrated
		}
	}
	if resp.ID == "" {
		resp.ID = "chatcmpl-" + sess.ID
	}
	resp.Model = req.Model + " (phigate:" + backend + ")"

	// 6. Surface routing + FinOps + guardrail metadata for observability.
	w.Header().Set("X-PhiGate-Route", decision.Target.String())
	w.Header().Set("X-PhiGate-Backend", backend)
	w.Header().Set("X-PhiGate-Reason", reason)
	w.Header().Set("X-PhiGate-Compression", compressionRatio(origRunes, compRunes))
	if blockedRule != "" {
		w.Header().Set("X-PhiGate-Blocked", blockedRule)
	}
	log.Printf("route=%s backend=%s reason=%q compression=%s",
		decision.Target, backend, reason, compressionRatio(origRunes, compRunes))

	writeJSON(w, http.StatusOK, resp)
}

// backendFor maps a routing target to its client and model.
func (g *Gateway) backendFor(t router.Target) (llm.Client, string) {
	if t == router.TargetLocal {
		return g.local, g.localModel
	}
	return g.cloud, g.cloudModel
}

// buildUpstream assembles the request actually sent upstream: the configured
// system preamble (so the model understands the placeholders) followed by the
// compressed messages, with the backend's model name.
func (g *Gateway) buildUpstream(model string, orig types.ChatCompletionRequest, msgs []types.Message, stream bool) *types.ChatCompletionRequest {
	out := make([]types.Message, 0, len(msgs)+1)
	if g.preamble != "" {
		out = append(out, types.Message{Role: "system", Content: g.preamble})
	}
	out = append(out, msgs...)
	return &types.ChatCompletionRequest{
		Model:       model,
		Messages:    out,
		Temperature: orig.Temperature,
		MaxTokens:   orig.MaxTokens,
		Stream:      stream,
	}
}

// blockedNotice is the operator-facing replacement for a withheld command.
func blockedNotice(v sandbox.Verdict) string {
	return "⛔ PhiGate egress guardrail blocked a destructive command (rule: " +
		v.Rule + "). The model's suggested action was withheld for safety."
}

// debugResult is the payload returned by /debug/compress for inspection.
type debugResult struct {
	Original   string            `json:"original"`
	Compressed string            `json:"compressed"`
	Hydrated   string            `json:"hydrated"`
	Dictionary map[string]string `json:"dictionary"`
	Roundtrip  bool              `json:"roundtrip_ok"`
	Route      string            `json:"route"`
	RouteWhy   string            `json:"route_reason"`
}

// handleDebugCompress exposes the compression layer and routing decision
// directly: POST raw text, inspect the masked template, dictionary, hydrated
// round trip, and which backend the router would pick.
func (g *Gateway) handleDebugCompress(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	original := string(raw)

	sess := compressor.NewSession()
	compressed, err := g.pipeline.Compress(original, sess)
	if err != nil {
		http.Error(w, "compression error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	hydrated := sess.Dict.Hydrate(compressed)
	decision, _ := g.router.Route(r.Context(), compressed)

	writeJSON(w, http.StatusOK, debugResult{
		Original:   original,
		Compressed: compressed,
		Hydrated:   hydrated,
		Dictionary: sess.Dict.Entries(),
		Roundtrip:  hydrated == original,
		Route:      decision.Target.String(),
		RouteWhy:   decision.Reason,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// compressionRatio reports how much the payload shrank, e.g. "63% saved".
func compressionRatio(orig, comp int) string {
	if orig <= 0 {
		return "n/a"
	}
	saved := 100 * (orig - comp) / orig
	if saved < 0 {
		saved = 0
	}
	return itoa(saved) + "% saved"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
