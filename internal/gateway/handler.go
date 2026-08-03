package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/phigate/phigate/internal/audit"
	"github.com/phigate/phigate/internal/cache"
	"github.com/phigate/phigate/internal/compressor"
	"github.com/phigate/phigate/internal/llm"
	"github.com/phigate/phigate/internal/policy"
	"github.com/phigate/phigate/internal/router"
	"github.com/phigate/phigate/internal/sandbox"
	"github.com/phigate/phigate/internal/tokens"
	"github.com/phigate/phigate/internal/types"
)

// requestPlan is everything the gateway worked out before dispatching.
//
// Building it in one place keeps the streaming and non-streaming paths from
// drifting apart. The previous version duplicated routing and fallback logic
// across the two, and the copies had already diverged.
type requestPlan struct {
	sess       *compressor.Session
	compressed []types.Message
	routed     router.Decision
	verdict    policy.Decision
	ingress    sandbox.IngressVerdict
	baseline   int
	promptEst  int
	cacheKey   string
	event      audit.Event
	start      time.Time
}

// handleChatCompletions implements POST /v1/chat/completions:
//
//	compress -> classify -> policy -> cache -> route -> dispatch -> hydrate -> guard
//
// The ordering is deliberate. Classification precedes routing because the
// policy's answer constrains the router's, never the other way round.
func (g *Gateway) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error", "")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, g.cfg.MaxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read request body", "invalid_request_error", "")
		return
	}
	var req types.ChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error(), "invalid_request_error", "")
		return
	}
	if len(req.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "messages must not be empty", "invalid_request_error", "")
		return
	}

	plan, err := g.plan(r, &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "compression error", "api_error", "")
		return
	}

	// A payload the policy refuses never reaches any backend.
	if plan.verdict.Action == policy.ActionDeny {
		g.metrics.policyDec.Inc("deny")
		plan.event.Status = http.StatusForbidden
		g.finish(plan, tokens.Record{}, "")
		writeError(w, http.StatusForbidden,
			"blocked by egress policy: "+plan.verdict.Reason, "invalid_request_error", "egress_policy")
		return
	}
	g.metrics.policyDec.Inc(plan.verdict.Action.String())

	if req.Stream {
		g.streamResponse(w, r, plan, &req)
		return
	}
	g.blockingResponse(w, r, plan, &req)
}

// plan compresses, classifies and routes the request.
func (g *Gateway) plan(r *http.Request, req *types.ChatCompletionRequest) (*requestPlan, error) {
	p := &requestPlan{start: time.Now()}

	// Session continuity: one conversation reuses one dictionary, so a given
	// IP is <V1> in every turn rather than a different token each time.
	p.sess = g.sessions.Get(strings.TrimSpace(r.Header.Get(g.cfg.SessionHeader)))

	if g.cfg.IngressScan {
		var joined strings.Builder
		for _, m := range req.Messages {
			joined.WriteString(m.Content)
			joined.WriteByte('\n')
		}
		p.ingress = g.ingress.Inspect(joined.String())
		for _, rule := range p.ingress.Rules {
			g.metrics.injection.Inc(rule)
		}
	}

	p.compressed = make([]types.Message, 0, len(req.Messages))
	var routeParts []string
	for _, m := range req.Messages {
		c, err := g.pipeline.Compress(m.Content, p.sess)
		if err != nil {
			return nil, err
		}
		out := m
		out.Content = c
		p.compressed = append(p.compressed, out)
		if m.Role != "system" {
			routeParts = append(routeParts, c)
		}
	}

	// Baseline: what the raw prompt would have cost at the cloud model. This is
	// the counterfactual every savings figure is measured against.
	p.baseline = tokens.EstimateMessages(g.counter, req.Contents())
	compressedTexts := make([]string, 0, len(p.compressed))
	for _, m := range p.compressed {
		compressedTexts = append(compressedTexts, m.Content)
	}
	p.promptEst = tokens.EstimateMessages(g.counter, compressedTexts)

	classes := p.sess.Categories()
	classCounts := make(map[string]int, len(classes))
	for cat, n := range classes {
		classCounts[string(cat)] = n
		g.metrics.redacted.Add(int64(n), string(cat))
	}

	p.verdict = g.policy.Evaluate(p.sess.MaxSensitivity())

	routed, err := g.router.Route(r.Context(), strings.Join(routeParts, "\n"))
	if err != nil {
		routed = router.Decision{Target: router.TargetCloud, Reason: "router error; defaulting to cloud"}
	}
	// The policy constrains the router's choice, never the reverse.
	if p.verdict.Action == policy.ActionLocalOnly && routed.Target == router.TargetCloud {
		routed = router.Decision{
			Target: router.TargetLocal,
			Reason: routed.Reason + " -> overridden to local by egress policy: " + p.verdict.Reason,
		}
	}
	p.routed = routed

	p.cacheKey = cache.Key(g.modelFor(routed.Target), compressedTexts, req.Temperature, req.MaxTokens)

	p.event = audit.Event{
		RequestID:       requestIDOf(r),
		SessionID:       p.sess.ID,
		Tenant:          tenantOf(r),
		ClientIP:        clientIP(r, g.cfg.TrustedProxyHeader),
		Model:           req.Model,
		PromptHash:      audit.Hash(strings.Join(compressedTexts, "\n")),
		Classifications: classCounts,
		RedactionRules:  p.sess.FiredRules(),
		MaxSensitivity:  p.sess.MaxSensitivity().String(),
		Route:           routed.Target.String(),
		RouteReason:     routed.Reason,
		PolicyAction:    p.verdict.Action.String(),
		PolicyReason:    p.verdict.Reason,
		IngressRules:    p.ingress.Rules,
		BaselineTokens:  p.baseline,
	}
	return p, nil
}

// blockingResponse handles the non-streaming path.
func (g *Gateway) blockingResponse(w http.ResponseWriter, r *http.Request, p *requestPlan, req *types.ChatCompletionRequest) {
	// The cache holds answers *before* hydration, so a hit is re-hydrated with
	// this session's dictionary. That is what makes sharing an entry across
	// sessions and tenants both correct and safe.
	if e, ok := g.cache.Get(p.cacheKey); ok {
		g.metrics.cacheOps.Inc("hit")
		p.event.CacheHit = true
		g.serveCached(w, p, req, e)
		return
	}
	g.metrics.cacheOps.Inc("miss")

	client, model := g.backendFor(p.routed.Target)
	upstream := g.buildUpstream(model, *req, p.compressed, false)

	backend := client.Name()
	resp, err := client.Chat(r.Context(), upstream)
	g.metrics.upstream.Inc(backend, outcome(err))

	// Fallback is permitted only for payloads the policy already cleared for
	// cloud egress. A local-only payload fails instead of leaking.
	if err != nil && p.routed.Target == router.TargetLocal {
		if g.policy.CloudFallbackAllowed(p.verdict) {
			client, model = g.cloud, g.cloudModel
			upstream = g.buildUpstream(model, *req, p.compressed, false)
			backend = client.Name()
			p.event.FellBackCloud = true
			p.event.RouteReason += " -> fell back to cloud after local error"
			resp, err = client.Chat(r.Context(), upstream)
			g.metrics.upstream.Inc(backend, outcome(err))
		} else {
			p.event.RouteReason += " -> local backend failed; cloud fallback forbidden by egress policy"
		}
	}
	if err != nil {
		g.failUpstream(w, p, backend, err)
		return
	}

	// Cache the masked answer, never the hydrated one.
	if len(resp.Choices) > 0 {
		g.cache.Put(p.cacheKey, cache.Entry{
			Content:          resp.Choices[0].Message.Content,
			Model:            model,
			Route:            p.routed.Target.String(),
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
		})
	}

	usage := resp.Usage
	reported := usage.PromptTokens > 0

	meta := g.finalize(w, p, resp, backend)
	if resp.ID == "" {
		resp.ID = "chatcmpl-" + p.sess.ID
	}
	if resp.Object == "" {
		resp.Object = "chat.completion"
	}
	resp.Model = req.Model + " (phigate:" + backend + ")"
	resp.PhiGate = meta

	if !reported {
		usage.PromptTokens = p.promptEst
		usage.CompletionTokens = g.counter.Estimate(answerText(resp))
	}
	g.finish(p, tokens.Record{
		Route:            routeOf(p.routed.Target),
		Model:            model,
		BaselineTokens:   p.baseline,
		PromptTokens:     usage.PromptTokens,
		CompletionTokens: usage.CompletionTokens,
		UsageReported:    reported,
	}, backend)

	writeJSON(w, http.StatusOK, resp)
}

// serveCached answers from the template cache.
func (g *Gateway) serveCached(w http.ResponseWriter, p *requestPlan, req *types.ChatCompletionRequest, e cache.Entry) {
	resp := &types.ChatCompletionResponse{
		ID:      "chatcmpl-" + p.sess.ID,
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Choices: []types.Choice{{
			Index:        0,
			Message:      types.Message{Role: "assistant", Content: e.Content},
			FinishReason: "stop",
		}},
	}
	meta := g.finalize(w, p, resp, "cache")
	resp.Model = req.Model + " (phigate:cache)"
	resp.PhiGate = meta

	g.finish(p, tokens.Record{
		Route:            tokens.RouteCache,
		Model:            e.Model,
		BaselineTokens:   p.baseline,
		CompletionTokens: e.CompletionTokens,
		UsageReported:    false,
	}, "cache")
	writeJSON(w, http.StatusOK, resp)
}

// finalize hydrates each choice, applies the enumeration and egress guards,
// sets the response headers, and returns the metadata block.
func (g *Gateway) finalize(w http.ResponseWriter, p *requestPlan, resp *types.ChatCompletionResponse, backend string) *types.Meta {
	var blockedRule, severity string

	for i := range resp.Choices {
		masked := resp.Choices[i].Message.Content
		hydrated, report := p.sess.Dict.HydrateReport(masked)

		// Dictionary enumeration: an answer that resolves most of a large
		// dictionary is reciting it rather than using it. Serving that would
		// turn hydration itself into the exfiltration channel.
		if g.cfg.Enumeration.Exceeded(report.Distinct, p.sess.Dict.Len()) {
			p.event.EnumerationStop = true
			p.event.EgressBlocked = true
			resp.Choices[i].Message.Content = enumerationNotice()
			resp.Choices[i].FinishReason = "content_filter"
			blockedRule, severity = "dictionary_enumeration", "block"
			g.metrics.blocked.Inc("dictionary_enumeration", "block")
			continue
		}

		v := g.guard.Inspect(hydrated)
		for _, f := range v.Findings {
			p.event.EgressFindings = append(p.event.EgressFindings, f.Rule+"="+f.Severity)
		}
		if v.Blocked {
			g.metrics.blocked.Inc(v.Rule, v.Severity.String())
			blockedRule, severity = v.Rule, v.Severity.String()
			p.event.EgressBlocked = true
			p.event.EgressRule = v.Rule
			p.event.EgressSeverity = v.Severity.String()
			resp.Choices[i].Message.Content = blockedNotice(v)
			resp.Choices[i].FinishReason = "content_filter"
			continue
		}
		if v.Severity == sandbox.SeverityWarn {
			// Report the rule for warnings too, not just for blocks: an
			// operator seeing "severity: warn" with no rule name has no way to
			// tell what was flagged.
			severity = "warn"
			blockedRule = v.Rule
			p.event.EgressRule = v.Rule
			p.event.EgressSeverity = "warn"
			hydrated = warnNotice(v) + hydrated
		}
		if p.ingress.Suspicious {
			hydrated = sandbox.InjectionNotice(p.ingress) + "\n\n" + hydrated
		}
		resp.Choices[i].Message.Content = hydrated
	}

	meta := g.buildMeta(p, backend, blockedRule, severity)
	setPhiGateHeaders(w, meta)
	return meta
}

// buildMeta computes the savings figures reported to the client.
func (g *Gateway) buildMeta(p *requestPlan, backend, blockedRule, severity string) *types.Meta {
	// A cache hit or a locally-served request sends nothing to the cloud, so
	// the whole baseline prompt was avoided rather than merely compressed.
	saved := p.baseline - p.promptEst
	if p.event.CacheHit || p.routed.Target == router.TargetLocal {
		saved = p.baseline
	}
	if saved < 0 {
		saved = 0
	}
	pct := 0
	if p.baseline > 0 {
		pct = 100 * saved / p.baseline
	}
	return &types.Meta{
		Route:          p.routed.Target.String(),
		Backend:        backend,
		Reason:         p.routed.Reason,
		Policy:         p.verdict.Action.String(),
		MaxSensitivity: p.sess.MaxSensitivity().String(),
		CacheHit:       p.event.CacheHit,
		BaselineTokens: p.baseline,
		PromptTokens:   p.promptEst,
		TokensSaved:    saved,
		SavedPercent:   pct,
		RedactionRules: p.sess.FiredRules(),
		EgressRule:     blockedRule,
		EgressSeverity: severity,
		IngressRules:   p.ingress.Rules,
	}
}

// setPhiGateHeaders exposes the decision on the response.
func setPhiGateHeaders(w http.ResponseWriter, m *types.Meta) {
	h := w.Header()
	h.Set("X-PhiGate-Route", m.Route)
	h.Set("X-PhiGate-Backend", m.Backend)
	h.Set("X-PhiGate-Reason", m.Reason)
	h.Set("X-PhiGate-Policy", m.Policy)
	h.Set("X-PhiGate-Sensitivity", m.MaxSensitivity)
	h.Set("X-PhiGate-Tokens-Saved", strconv.Itoa(m.TokensSaved))
	h.Set("X-PhiGate-Compression", strconv.Itoa(m.SavedPercent)+"% saved")
	if m.CacheHit {
		h.Set("X-PhiGate-Cache", "hit")
	}
	// X-PhiGate-Blocked must mean blocked. A warning names its rule in the
	// separate header so a client can distinguish "withheld" from "flagged".
	switch m.EgressSeverity {
	case "block":
		h.Set("X-PhiGate-Blocked", m.EgressRule)
	case "warn":
		h.Set("X-PhiGate-Warning", m.EgressRule)
	}
	if len(m.IngressRules) > 0 {
		h.Set("X-PhiGate-Ingress-Warning", strings.Join(m.IngressRules, ","))
	}
}

// failUpstream reports a backend failure without disclosing internals.
//
// The previous handler returned the raw upstream error to the caller, which
// leaked backend URLs and provider messages to anyone who could trigger a
// failure. The detail now goes to the audit log only.
func (g *Gateway) failUpstream(w http.ResponseWriter, p *requestPlan, backend string, err error) {
	status := http.StatusBadGateway
	msg := "upstream backend unavailable"
	if errors.Is(err, llm.ErrCircuitOpen) {
		status = http.StatusServiceUnavailable
		msg = "upstream backend is temporarily unavailable (circuit breaker open)"
	}
	p.event.Status = status
	p.event.Error = err.Error()
	g.finish(p, tokens.Record{}, backend)
	writeError(w, status, msg, "api_error", "upstream_error")
}

// finish records accounting, metrics and the audit event.
func (g *Gateway) finish(p *requestPlan, rec tokens.Record, backend string) {
	if p.event.Status == 0 {
		p.event.Status = http.StatusOK
	}
	if backend != "" {
		p.event.Backend = backend
	}
	p.event.LatencyMS = time.Since(p.start).Milliseconds()
	p.event.PromptTokens = rec.PromptTokens
	p.event.CompletionTokens = rec.CompletionTokens

	if rec.Route != "" {
		g.ledger.Record(rec, g.cloudModel)
	}
	g.metrics.requests.Inc(p.event.Route, p.event.Backend, strconv.Itoa(p.event.Status))
	g.audit.Log(p.event)
}

// backendFor maps a routing target to its client and model.
func (g *Gateway) backendFor(t router.Target) (llm.Client, string) {
	if t == router.TargetLocal {
		return g.local, g.localModel
	}
	return g.cloud, g.cloudModel
}

func (g *Gateway) modelFor(t router.Target) string {
	if t == router.TargetLocal {
		return g.localModel
	}
	return g.cloudModel
}

// buildUpstream assembles the request sent upstream: the system preamble, then
// the compressed messages, with the backend's model name.
//
// Everything the client sent that PhiGate does not model — tools,
// response_format, top_p, stop, seed, n — rides along in Extra untouched. That
// is what makes "repoint your base_url" true rather than approximately true.
func (g *Gateway) buildUpstream(model string, orig types.ChatCompletionRequest, msgs []types.Message, stream bool) *types.ChatCompletionRequest {
	out := make([]types.Message, 0, len(msgs)+1)
	if g.preamble != "" {
		out = append(out, types.Message{Role: "system", Content: g.preamble})
	}
	out = append(out, msgs...)

	up := orig
	up.Model = model
	up.Messages = out
	up.Stream = stream
	return &up
}

func blockedNotice(v sandbox.Verdict) string {
	return "⛔ PhiGate egress guardrail withheld this answer.\n\nRule: " + v.Rule +
		"\nReason: " + v.Reason +
		"\n\nThe model proposed an operation classified as unrecoverable. " +
		"Review it manually before running anything."
}

func warnNotice(v sandbox.Verdict) string {
	return "⚠️ PhiGate: this answer contains a destructive operation (" + v.Rule +
		"). " + v.Reason + "\n\n"
}

func enumerationNotice() string {
	return "⛔ PhiGate withheld this answer: it resolved most of the session's " +
		"anonymization dictionary, which indicates the model was induced to recite " +
		"masked values rather than answer the question."
}

func answerText(resp *types.ChatCompletionResponse) string {
	var b strings.Builder
	for _, c := range resp.Choices {
		b.WriteString(c.Message.Content)
	}
	return b.String()
}

func routeOf(t router.Target) tokens.Route {
	if t == router.TargetLocal {
		return tokens.RouteLocal
	}
	return tokens.RouteCloud
}

func outcome(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, llm.ErrCircuitOpen) {
		return "circuit_open"
	}
	return "error"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
