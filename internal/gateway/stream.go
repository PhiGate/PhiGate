package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/phigate/phigate/internal/cache"
	"github.com/phigate/phigate/internal/router"
	"github.com/phigate/phigate/internal/sandbox"
	"github.com/phigate/phigate/internal/tokens"
	"github.com/phigate/phigate/internal/types"
)

// streamResponse proxies a streaming completion as Server-Sent Events while the
// egress sandbox inspects every line.
//
// Output is hydrated and vetted before it reaches the client; a blocked command
// is replaced by a notice and the rest of the stream is sealed off. The scanner
// holds text until releasing it can no longer change the guard's verdict, so a
// command split across SSE chunks ("rm -r" then "f /") is still inspected as one
// unit, and a fenced code block is inspected as one segment — the same unit the
// blocking path sees.
func (g *Gateway) streamResponse(w http.ResponseWriter, r *http.Request, p *requestPlan, req *types.ChatCompletionRequest) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported", "api_error", "")
		return
	}

	// A cached answer is replayed as a stream so the client sees no difference
	// between a hit and a miss.
	if e, ok := g.cacheGet(p); ok {
		g.metrics.cacheOps.Inc("hit")
		p.event.CacheHit = true
		g.streamCached(w, flusher, p, req, e)
		return
	}
	g.metrics.cacheOps.Inc("miss")

	client, model := g.backendFor(p.routed.Target)
	meta := g.buildMeta(p, client.Name(), "", "")
	sw := newSSEWriter(w, flusher, "chatcmpl-"+p.sess.ID, req.Model+" (phigate:"+client.Name()+")", meta)

	// The upstream answer is accumulated in its masked form so a successful
	// stream can be cached. Only pre-hydration text is ever stored.
	var masked strings.Builder
	scanner := g.newScanner(p, sw)
	tools := newToolCallAccumulator()
	feed := func(d types.Delta) error {
		for _, frag := range d.ToolCalls {
			tools.add(frag)
		}
		if d.Content == "" {
			return nil
		}
		masked.WriteString(d.Content)
		return scanner.Write(d.Content)
	}

	upstream := g.buildUpstream(model, *req, p, true)
	err := client.ChatStream(r.Context(), upstream, feed)
	g.metrics.upstream.Inc(client.Name(), outcome(err))

	// Fallback only before the first byte, and only when policy permits it.
	if err != nil && !sw.started && p.routed.Target == router.TargetLocal {
		if p.view.policy.CloudFallbackAllowed(p.verdict) {
			client, model = g.cloud, g.cloudModel
			p.event.FellBackCloud = true
			p.event.RouteReason += " -> fell back to cloud after local error"
			sw.model = req.Model + " (phigate:" + client.Name() + ")"
			sw.meta.Backend = client.Name()
			masked.Reset()
			tools = newToolCallAccumulator()
			upstream = g.buildUpstream(model, *req, p, true)
			err = client.ChatStream(r.Context(), upstream, feed)
			g.metrics.upstream.Inc(client.Name(), outcome(err))
		} else {
			p.event.RouteReason += " -> local backend failed; cloud fallback forbidden by egress policy"
		}
	}
	if err != nil && !sw.started {
		g.failUpstream(w, p, client.Name(), err)
		return
	}

	_ = scanner.Close() // flush any held partial line through the guard

	// Tool calls are released here, whole and in one chunk — see the doc on
	// toolCallAccumulator for why they cannot be forwarded fragment by
	// fragment. This must precede done(), which writes [DONE].
	maskedCalls := tools.assembled()
	toolsBlocked := g.emitToolCalls(p, sw, scanner, maskedCalls)

	sw.done()

	if err == nil && !scanner.Blocked() && !toolsBlocked && (masked.Len() > 0 || len(maskedCalls) > 0) {
		g.cache.Put(p.cacheKey, cache.Entry{
			Content:   p.canonicalise(masked.String()),
			ToolCalls: p.canonicaliseCalls(maskedCalls),
			Model:     model,
			Route:     p.routed.Target.String(),
		})
	}

	g.finish(p, tokens.Record{
		Tenant:           p.tenant,
		Route:            routeOf(p.routed.Target),
		Model:            model,
		BaselineTokens:   p.baseline,
		PromptTokens:     p.promptEst,
		CompletionTokens: g.counter.Estimate(masked.String()),
		UsageReported:    false, // streaming responses rarely carry a usage block
	}, client.Name())
}

// emitToolCalls hydrates the reassembled calls, applies the same enumeration
// and egress checks the blocking path applies to them, and writes them as the
// final chunk. It reports whether they were withheld.
//
// The checks are duplicated here rather than run through the text scanner
// because the scanner's unit is a line of prose and these are a structured
// value that only exists once the stream has ended. What must not differ is the
// verdict, which is why both paths reach it through the same guard and the same
// argumentStrings extraction.
func (g *Gateway) emitToolCalls(p *requestPlan, sw *sseWriter, scanner *sandbox.StreamScanner, calls []types.ToolCall) bool {
	if len(calls) == 0 {
		return false
	}
	// The prose was already sealed off. Handing back the calls it described
	// would defeat the seal: an agent executes the call, not the notice.
	if scanner.Blocked() {
		return true
	}

	maskedArgs := make([]string, 0, len(calls))
	for _, c := range calls {
		if c.Function != nil {
			maskedArgs = append(maskedArgs, c.Function.Arguments)
		}
	}

	// Enumeration is counted over the calls as one body, the same union rule
	// the blocking path uses.
	_, report := p.sess.Dict.HydrateReport(strings.Join(maskedArgs, "\n"))
	if p.state.cfg.Enumeration.Exceeded(report.Distinct, p.sess.Dict.Len()) {
		p.event.EnumerationStop = true
		p.event.EgressBlocked = true
		g.metrics.blocked.Inc("dictionary_enumeration", "block")
		_ = sw.emit("\n"+enumerationNotice()+"\n", "content_filter")
		return true
	}

	hydrated := make([]types.ToolCall, len(calls))
	hydratedArgs := make([]string, 0, len(calls))
	for i, c := range calls {
		hydrated[i] = c
		if c.Function == nil {
			continue
		}
		fn := *c.Function
		fn.Arguments = p.sess.Dict.Hydrate(fn.Arguments)
		hydrated[i].Function = &fn
		hydratedArgs = append(hydratedArgs, fn.Arguments)
	}

	if v := p.state.guard.Inspect(strings.Join(argumentStrings(hydratedArgs), "\n")); v.Blocked {
		g.metrics.blocked.Inc(v.Rule, v.Severity.String())
		p.event.EgressBlocked = true
		p.event.EgressRule = v.Rule
		p.event.EgressSeverity = v.Severity.String()
		sw.meta.EgressRule = v.Rule
		sw.meta.EgressSeverity = v.Severity.String()
		sw.header("X-PhiGate-Blocked", v.Rule)
		_ = sw.emit("\n"+blockedNotice(v)+"\n", "content_filter")
		return true
	}

	_ = sw.emitToolCalls(hydrated)
	return false
}

// newScanner wires the egress guard, hydration and enumeration check into the
// streaming path, so a streamed answer gets exactly the same treatment as a
// blocking one. That the two agree is asserted in the sandbox package's
// parity_test.go, not merely intended here.
func (g *Gateway) newScanner(p *requestPlan, sw *sseWriter) *sandbox.StreamScanner {
	hydrate := func(line string) string {
		out, report := p.sess.Dict.HydrateReport(line)
		if p.state.cfg.Enumeration.Exceeded(report.Distinct, p.sess.Dict.Len()) {
			p.event.EnumerationStop = true
			return "" // withhold the line; the guard below seals the stream
		}
		return out
	}
	return sandbox.NewStreamScannerWith(p.state.guard, hydrate,
		func(safe string) error { return sw.emit(safe, "") },
		func(v sandbox.Verdict) error {
			g.metrics.blocked.Inc(v.Rule, v.Severity.String())
			p.event.EgressBlocked = true
			p.event.EgressRule = v.Rule
			p.event.EgressSeverity = v.Severity.String()
			sw.meta.EgressRule = v.Rule
			sw.meta.EgressSeverity = v.Severity.String()
			sw.header("X-PhiGate-Blocked", v.Rule)
			return sw.emit("\n"+blockedNotice(v)+"\n", "content_filter")
		},
		sandbox.Options{Mode: p.state.cfg.StreamMode, MaxBuffer: p.state.cfg.StreamMaxBuffer})
}

// streamCached replays a cached answer as SSE, hydrated for this session.
func (g *Gateway) streamCached(w http.ResponseWriter, flusher http.Flusher, p *requestPlan, req *types.ChatCompletionRequest, e cache.Entry) {
	meta := g.buildMeta(p, "cache", "", "")
	sw := newSSEWriter(w, flusher, "chatcmpl-"+p.sess.ID, req.Model+" (phigate:cache)", meta)
	scanner := g.newScanner(p, sw)
	_ = scanner.Write(cache.Restore(e.Content, p.restore))
	_ = scanner.Close()
	// A cached tool-call answer is replayed through the same checks as a live
	// one: the entry is pre-hydration, so this session's dictionary is what
	// resolves it, and this session's guard is what vets the result.
	g.emitToolCalls(p, sw, scanner, restoreCalls(e.ToolCalls, p.restore))
	sw.done()

	g.finish(p, tokens.Record{
		Tenant:           p.tenant,
		Route:            tokens.RouteCache,
		Model:            e.Model,
		BaselineTokens:   p.baseline,
		CompletionTokens: e.CompletionTokens,
	}, "cache")
}

// sseWriter emits OpenAI-style chat.completion.chunk events and writes response
// headers exactly once, on the first emitted byte.
type sseWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
	id      string
	model   string
	meta    *types.Meta
	started bool
}

func newSSEWriter(w http.ResponseWriter, f http.Flusher, id, model string, meta *types.Meta) *sseWriter {
	return &sseWriter{w: w, flusher: f, id: id, model: model, meta: meta}
}

// header sets a response header if the body has not started yet.
func (s *sseWriter) header(k, v string) {
	if !s.started {
		s.w.Header().Set(k, v)
	}
}

func (s *sseWriter) start() {
	if s.started {
		return
	}
	s.started = true
	h := s.w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // defeat proxy buffering of the SSE stream
	setPhiGateHeaders(s.w, s.meta)
	s.w.WriteHeader(http.StatusOK)
}

func (s *sseWriter) emit(content, finish string) error {
	if content == "" && finish == "" {
		return nil
	}
	s.start()
	var fr *string
	if finish != "" {
		fr = &finish
	}
	chunk := types.ChatCompletionChunk{
		ID:      s.id,
		Object:  "chat.completion.chunk",
		Created: time.Now().Unix(),
		Model:   s.model,
		Choices: []types.ChunkChoice{{
			Index:        0,
			Delta:        types.Delta{Content: content},
			FinishReason: fr,
		}},
	}
	b, _ := json.Marshal(chunk)
	if _, err := fmt.Fprintf(s.w, "data: %s\n\n", b); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}

// emitToolCalls writes the reassembled calls as one chunk.
//
// finish_reason is "tool_calls" because that is the signal a client waits for
// before dispatching them; emitting the calls under "stop" leaves them sitting
// unexecuted.
func (s *sseWriter) emitToolCalls(calls []types.ToolCall) error {
	if len(calls) == 0 {
		return nil
	}
	s.start()
	finish := "tool_calls"
	chunk := types.ChatCompletionChunk{
		ID:      s.id,
		Object:  "chat.completion.chunk",
		Created: time.Now().Unix(),
		Model:   s.model,
		Choices: []types.ChunkChoice{{
			Index:        0,
			Delta:        types.Delta{ToolCalls: calls},
			FinishReason: &finish,
		}},
	}
	b, _ := json.Marshal(chunk)
	if _, err := fmt.Fprintf(s.w, "data: %s\n\n", b); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}

func (s *sseWriter) done() {
	s.start()
	_, _ = fmt.Fprint(s.w, "data: [DONE]\n\n")
	s.flusher.Flush()
}
