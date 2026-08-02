package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/tenkan/phigate/internal/compressor"
	"github.com/tenkan/phigate/internal/llm"
	"github.com/tenkan/phigate/internal/router"
	"github.com/tenkan/phigate/internal/sandbox"
	"github.com/tenkan/phigate/internal/types"
)

// streamResponse proxies a streaming completion as Server-Sent Events while the
// egress sandbox inspects every line. Output is hydrated and vetted before it
// reaches the client; a destructive command is replaced by a redaction notice
// and the rest of the stream is sealed off.
func (g *Gateway) streamResponse(
	w http.ResponseWriter, r *http.Request, sess *compressor.Session,
	req *types.ChatCompletionRequest, compressedMsgs []types.Message,
	decision router.Decision, origRunes, compRunes int,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported by server", http.StatusInternalServerError)
		return
	}

	client, model := g.backendFor(decision.Target)
	sw := &sseWriter{
		w:           w,
		flusher:     flusher,
		id:          "chatcmpl-" + sess.ID,
		model:       req.Model + " (phigate:" + client.Name() + ")",
		route:       decision.Target.String(),
		backend:     client.Name(),
		reason:      decision.Reason,
		compression: compressionRatio(origRunes, compRunes),
	}

	scanner := sandbox.NewStreamScanner(g.guard,
		func(line string) string { return sess.Dict.Hydrate(line) },
		func(safe string) error { return sw.emit(safe, "") },
		func(v sandbox.Verdict) error {
			sw.blockedRule = v.Rule
			sw.header("X-PhiGate-Blocked", v.Rule)
			log.Printf("egress BLOCKED (stream) rule=%s match=%q", v.Rule, v.Match)
			return sw.emit("\n"+blockedNotice(v)+"\n", "content_filter")
		})
	feed := func(d string) error { return scanner.Write(d) }

	// Primary dispatch with local -> cloud fallback (only before first byte).
	upstream := g.buildUpstream(model, *req, compressedMsgs, true)
	err := client.ChatStream(r.Context(), upstream, feed)
	if err != nil && !sw.started && decision.Target == router.TargetLocal {
		log.Printf("local stream failed (%v); falling back to cloud", err)
		client, model = g.cloud, g.cloudModel
		sw.model = req.Model + " (phigate:" + client.Name() + ")"
		sw.backend = client.Name()
		sw.reason = decision.Reason + " -> fell back to cloud after local error"
		upstream = g.buildUpstream(model, *req, compressedMsgs, true)
		err = client.ChatStream(r.Context(), upstream, feed)
	}
	if err != nil && !sw.started {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}

	_ = scanner.Close() // flush any held partial line through the guard
	sw.done()
	log.Printf("stream route=%s backend=%s reason=%q compression=%s blocked=%q",
		decision.Target, sw.backend, sw.reason, sw.compression, sw.blockedRule)
}

// sseWriter emits OpenAI-style chat.completion.chunk events and writes response
// headers exactly once, on the first emitted byte.
type sseWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
	id      string
	model   string

	route       string
	backend     string
	reason      string
	compression string
	blockedRule string

	started bool
}

// header sets a response header if the body hasn't started yet.
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
	h.Set("X-PhiGate-Route", s.route)
	h.Set("X-PhiGate-Backend", s.backend)
	h.Set("X-PhiGate-Reason", s.reason)
	h.Set("X-PhiGate-Compression", s.compression)
	if s.blockedRule != "" {
		h.Set("X-PhiGate-Blocked", s.blockedRule)
	}
	s.w.WriteHeader(http.StatusOK)
}

func (s *sseWriter) emit(content, finish string) error {
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

func (s *sseWriter) done() {
	s.start()
	_, _ = fmt.Fprint(s.w, "data: [DONE]\n\n")
	s.flusher.Flush()
}

// compile-time assertion that OpenAIClient satisfies the streaming Client.
var _ llm.Client = (*llm.OpenAIClient)(nil)
