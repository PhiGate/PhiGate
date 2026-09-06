package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/phigate/phigate/internal/audit"
	"github.com/phigate/phigate/internal/llm"
	"github.com/phigate/phigate/internal/policy"
	"github.com/phigate/phigate/internal/router"
	"github.com/phigate/phigate/internal/tokens"
	"github.com/phigate/phigate/internal/types"
)

// handleEmbeddings implements POST /v1/embeddings.
//
// # Why this endpoint matters more than it looks
//
// In a RAG deployment, the text sent for embedding is the corpus: the tickets,
// the contracts, the medical notes. It is the most sensitive traffic the
// gateway will ever see, and until this existed a client doing retrieval had to
// send it straight to the provider, past every control PhiGate offers, and then
// route only the *questions* through the gateway. Guarding the questions and
// not the documents is guarding the wrong half.
//
// # What is different from a completion
//
// Nothing is hydrated on the way back, because there is nothing to hydrate: the
// response is a vector. The consequence is worth stating, because it decides
// whether a deployment works. The vectors describe the *masked* text, so the
// index holds embeddings of masked text — and a query embedded through the same
// gateway with the same session dictionary is masked the same way, so retrieval
// matches. Indexing through PhiGate and querying around it will not work, and
// that is a property of the design rather than a defect in it.
//
// Only the masking stage runs. Drain and ASTPrune are lossy, and an embedding
// of a payload that has had its structure collapsed describes something the
// caller never wrote.
func (g *Gateway) handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "")
		return
	}
	st := g.now()

	body, err := io.ReadAll(io.LimitReader(r.Body, st.cfg.MaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read request body", "invalid_request_error", "")
		return
	}
	var req types.EmbeddingsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error(), "invalid_request_error", "")
		return
	}

	start := time.Now()
	tenant := tenantOf(r)
	view := st.viewFor(tenant)
	sess := g.sessions.Get(strings.TrimSpace(r.Header.Get(st.cfg.SessionHeader)))

	// Mask every input, on the session's dictionary, so the same value maps to
	// the same placeholder here as it does in a completion. That is what lets a
	// question and the documents it retrieves against agree.
	masked := make([]string, len(req.Texts))
	for i, text := range req.Texts {
		m, err := view.masker.Process(text, sess)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "compression error", "api_error", "")
			return
		}
		masked[i] = m
	}

	verdict := view.policy.Evaluate(sess.MaxSensitivity())
	event := audit.Event{
		RequestID:      requestIDOf(r),
		SessionID:      sess.ID,
		Tenant:         tenant,
		ClientIP:       clientIP(r, st.cfg.TrustedProxyHeader),
		Model:          req.Model,
		PromptHash:     audit.Hash(strings.Join(masked, "\n")),
		RedactionRules: sess.FiredRules(),
		MaxSensitivity: sess.MaxSensitivity().String(),
		PolicyAction:   verdict.Action.String(),
		PolicyReason:   verdict.Reason,
		BaselineTokens: tokens.EstimateMessages(g.counter, req.Texts),
	}

	if verdict.Action == policy.ActionDeny {
		g.metrics.policyDec.Inc("deny")
		event.Status = http.StatusForbidden
		g.finishEvent(event, tokens.Record{}, "")
		writeError(w, http.StatusForbidden,
			"blocked by egress policy: "+verdict.Reason, "invalid_request_error", "egress_policy")
		return
	}
	g.metrics.policyDec.Inc(verdict.Action.String())

	// The policy binds here exactly as it does on a completion: a corpus the
	// policy confines to local is embedded locally or not at all. Silently
	// embedding it in the cloud would be the same leak by a quieter route.
	target := router.TargetCloud
	if verdict.Action == policy.ActionLocalOnly {
		target = router.TargetLocal
	}
	client, model := g.backendFor(target)

	embedder, ok := client.(llm.Embedder)
	if !ok {
		// Said plainly rather than forwarded to find out. A backend without an
		// embeddings endpoint returns a provider error the caller has to
		// interpret; this names the problem.
		event.Status = http.StatusNotImplemented
		g.finishEvent(event, tokens.Record{}, client.Name())
		writeError(w, http.StatusNotImplemented,
			"the "+client.Name()+" backend does not provide embeddings",
			"invalid_request_error", "embeddings_unsupported")
		return
	}

	upstream := req
	upstream.Texts = masked
	if req.Model != "" && target == router.TargetLocal {
		// The caller names a model in its own namespace; the backend has its
		// own, exactly as on a completion.
		upstream.Model = model
	}

	resp, err := embedder.Embed(r.Context(), &upstream)
	g.metrics.upstream.Inc(client.Name(), outcome(err))
	if err != nil {
		event.Status = http.StatusBadGateway
		event.Error = err.Error()
		g.finishEvent(event, tokens.Record{}, client.Name())
		writeError(w, http.StatusBadGateway, "upstream backend unavailable", "api_error", "upstream_error")
		return
	}

	meta := &types.Meta{
		Route:          target.String(),
		Backend:        client.Name(),
		Reason:         "embeddings are not routed by cost; the policy decides",
		Policy:         verdict.Action.String(),
		MaxSensitivity: sess.MaxSensitivity().String(),
		BaselineTokens: event.BaselineTokens,
		PromptTokens:   tokens.EstimateMessages(g.counter, masked),
		RedactionRules: sess.FiredRules(),
	}
	setPhiGateHeaders(w, meta)
	resp.PhiGate = meta

	event.Route = target.String()
	event.Backend = client.Name()
	event.LatencyMS = time.Since(start).Milliseconds()
	event.PromptTokens = resp.Usage.PromptTokens
	g.finishEvent(event, tokens.Record{
		Tenant:         tenant,
		Route:          routeOf(target),
		Model:          model,
		BaselineTokens: event.BaselineTokens,
		PromptTokens:   resp.Usage.PromptTokens,
		UsageReported:  resp.Usage.PromptTokens > 0,
	}, client.Name())

	writeJSON(w, http.StatusOK, resp)
}

// finishEvent records accounting, metrics and the audit event for a request
// that has no requestPlan — the embeddings path, which does not compress,
// route or guard an answer and so has nothing to plan.
func (g *Gateway) finishEvent(e audit.Event, rec tokens.Record, backend string) {
	if e.Status == 0 {
		e.Status = http.StatusOK
	}
	if backend != "" {
		e.Backend = backend
	}
	if rec.Route != "" {
		g.ledger.Record(rec, g.cloudModel)
	}
	g.metrics.requests.Inc(e.Route, e.Backend, strconv.Itoa(e.Status))
	g.audit.Log(e)
}
