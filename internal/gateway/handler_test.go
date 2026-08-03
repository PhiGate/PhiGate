package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phigate/phigate/internal/config"
	"github.com/phigate/phigate/internal/llm"
	"github.com/phigate/phigate/internal/policy"
	"github.com/phigate/phigate/internal/redact"
	"github.com/phigate/phigate/internal/router"
	"github.com/phigate/phigate/internal/sandbox"
	"github.com/phigate/phigate/internal/tokens"
	"github.com/phigate/phigate/internal/types"
)

// fakeClient is an llm.Client test double.
type fakeClient struct {
	name   string
	reply  string
	stream []string // deltas emitted by ChatStream
	err    error
	calls  int
	gotReq *types.ChatCompletionRequest
}

func (f *fakeClient) Name() string { return f.name }
func (f *fakeClient) Chat(_ context.Context, req *types.ChatCompletionRequest) (*types.ChatCompletionResponse, error) {
	f.calls++
	f.gotReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &types.ChatCompletionResponse{
		Choices: []types.Choice{{Message: types.Message{Role: "assistant", Content: f.reply}}},
	}, nil
}
func (f *fakeClient) ChatStream(_ context.Context, req *types.ChatCompletionRequest, onDelta llm.StreamFunc) error {
	f.calls++
	f.gotReq = req
	if f.err != nil {
		return f.err
	}
	for _, d := range f.stream {
		if err := onDelta(d); err != nil {
			return err
		}
	}
	return nil
}

func testConfig() config.Config {
	return config.Config{
		Local:           config.Backend{Model: "phi4-mini"},
		Cloud:           config.Backend{Model: "gpt-4o"},
		SystemPreamble:  "PREAMBLE",
		Policy:          policy.Default(),
		AllowAnonymous:  true,
		SessionHeader:   "X-PhiGate-Session",
		SessionTTL:      time.Minute,
		SessionMax:      100,
		MetricsPath:     "/metrics",
		DashboardOn:     true,
		MaxBodyBytes:    1 << 20,
		Enumeration:     sandbox.DefaultEnumerationThreshold(),
		InternalDomains: []string{"corp", "internal"},
		CacheTTL:        time.Minute,
		CacheMax:        0, // most tests want deterministic upstream calls
	}
}

func newTestGateway(t *testing.T, cfg config.Config, local, cloud llm.Client) *Gateway {
	t.Helper()
	eng, err := redact.NewEngine(redact.Options{InternalDomains: cfg.InternalDomains})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	g, err := NewWith(cfg, eng, tokens.NewPriceBook(), local, cloud, router.NewHeuristicRouter())
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	t.Cleanup(g.Close)
	return g
}

func postChat(t *testing.T, g *Gateway, content string) (*httptest.ResponseRecorder, types.ChatCompletionResponse) {
	t.Helper()
	return postRaw(t, g, `{"model":"gpt-4o","messages":[{"role":"user","content":`+quote(content)+`}]}`)
}

func postRaw(t *testing.T, g *Gateway, body string) (*httptest.ResponseRecorder, types.ChatCompletionResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	g.Routes().ServeHTTP(rec, httpReq)

	var resp types.ChatCompletionResponse
	if rec.Code == 200 {
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	}
	return rec, resp
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestDispatchLocalAndHydrate(t *testing.T) {
	local := &fakeClient{name: "local", reply: "investigate host <V1>"}
	cloud := &fakeClient{name: "cloud", reply: "should not be called"}
	g := newTestGateway(t, testConfig(), local, cloud)

	rec, resp := postChat(t, g, "disk full on 10.0.0.5")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if local.calls != 1 || cloud.calls != 0 {
		t.Fatalf("expected local-only dispatch, local=%d cloud=%d", local.calls, cloud.calls)
	}
	if rec.Header().Get("X-PhiGate-Route") != "local" {
		t.Errorf("route header = %q, want local", rec.Header().Get("X-PhiGate-Route"))
	}
	if got := resp.Choices[0].Message.Content; got != "investigate host 10.0.0.5" {
		t.Fatalf("content = %q, want hydrated IP", got)
	}
	sent := local.gotReq
	if sent.Messages[0].Role != "system" || sent.Messages[0].Content != "PREAMBLE" {
		t.Errorf("preamble not prepended: %+v", sent.Messages[0])
	}
	for _, m := range sent.Messages {
		if strings.Contains(m.Content, "10.0.0.5") {
			t.Fatalf("raw IP leaked upstream: %q", m.Content)
		}
	}
	if sent.Model != "phi4-mini" {
		t.Errorf("upstream model = %q, want phi4-mini", sent.Model)
	}
}

func TestLocalFallbackToCloud(t *testing.T) {
	local := &fakeClient{name: "local", err: errors.New("connection refused")}
	cloud := &fakeClient{name: "cloud", reply: "host <V1> is down"}
	g := newTestGateway(t, testConfig(), local, cloud)

	rec, resp := postChat(t, g, "disk full on 10.0.0.5")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if local.calls != 1 || cloud.calls != 1 {
		t.Fatalf("expected fallback, local=%d cloud=%d", local.calls, cloud.calls)
	}
	if got := resp.Choices[0].Message.Content; got != "host 10.0.0.5 is down" {
		t.Fatalf("content = %q, want hydrated", got)
	}
}

// TestPolicyForbidsCloudFallbackForSensitiveData is the regression test for the
// hole the audit found: a local backend failure silently retried against the
// cloud, carrying whatever the local model had been trusted with. A payload the
// policy confined to local must fail rather than egress.
func TestPolicyForbidsCloudFallbackForSensitiveData(t *testing.T) {
	local := &fakeClient{name: "local", err: errors.New("ollama is down")}
	cloud := &fakeClient{name: "cloud", reply: "should never be reached"}
	g := newTestGateway(t, testConfig(), local, cloud)

	// A My Number is classified confidential, above the default cloud limit.
	rec, _ := postChat(t, g, "従業員の個人番号 1234 5678 9018 が登録できません")

	if cloud.calls != 0 {
		t.Fatalf("SENSITIVE DATA EGRESSED: cloud was called %d time(s) for a local-only payload", cloud.calls)
	}
	if rec.Code == 200 {
		t.Errorf("expected a failure rather than a silent cloud fallback, got 200")
	}
	if got := rec.Header().Get("X-PhiGate-Policy"); got != "" && got != "local_only" {
		t.Errorf("policy header = %q, want local_only", got)
	}
}

// TestPolicyOverridesRouterToLocal verifies the ordering: the policy constrains
// the router, not the other way round. Code normally routes to cloud, but code
// carrying a credential must not.
func TestPolicyOverridesRouterToLocal(t *testing.T) {
	local := &fakeClient{name: "local", reply: "rotate the key"}
	cloud := &fakeClient{name: "cloud", reply: "should not be called"}
	g := newTestGateway(t, testConfig(), local, cloud)

	rec, _ := postChat(t, g,
		"func connect() { db.Open(\"postgres://svc:Hx7kQ2mZpW@db1/app\") }\nwhy does this fail?")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if cloud.calls != 0 {
		t.Fatalf("credential-bearing payload reached the cloud backend (%d calls)", cloud.calls)
	}
	if rec.Header().Get("X-PhiGate-Sensitivity") != "restricted" {
		t.Errorf("sensitivity = %q, want restricted", rec.Header().Get("X-PhiGate-Sensitivity"))
	}
}

// TestPassthroughPreservesUnknownFields is the regression test for silent
// degradation: a client using tools or response_format had those dropped, and
// the request still succeeded — with the wrong semantics.
func TestPassthroughPreservesUnknownFields(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	cloud := &fakeClient{name: "cloud", reply: "ok"}
	g := newTestGateway(t, testConfig(), local, cloud)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"disk full"}],
	  "tools":[{"type":"function","function":{"name":"restart"}}],
	  "tool_choice":"auto","response_format":{"type":"json_object"},
	  "top_p":0.2,"seed":42,"stop":["END"],"n":1}`
	rec, _ := postRaw(t, g, body)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	sent := local.gotReq
	if sent == nil {
		t.Fatal("no upstream request captured")
	}
	out, err := json.Marshal(sent)
	if err != nil {
		t.Fatalf("marshal upstream: %v", err)
	}
	for _, field := range []string{"tools", "tool_choice", "response_format", "top_p", "seed", "stop"} {
		if !strings.Contains(string(out), `"`+field+`"`) {
			t.Errorf("field %q was dropped on the way upstream: %s", field, out)
		}
	}
}

func TestContentArrayMessagesAreCompressedAndPreserved(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":[
	  {"type":"text","text":"error on 10.0.0.5"},
	  {"type":"image_url","image_url":{"url":"https://example.com/a.png"}}]}]}`
	rec, _ := postRaw(t, g, body)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	out, _ := json.Marshal(local.gotReq)
	if strings.Contains(string(out), "10.0.0.5") {
		t.Errorf("raw IP leaked from an array-content message: %s", out)
	}
	if !strings.Contains(string(out), "image_url") {
		t.Errorf("non-text content part was dropped: %s", out)
	}
}

func TestNonStreamBlocksDestructive(t *testing.T) {
	local := &fakeClient{name: "local", reply: "To recover space, run:\n```sh\nrm -rf /\n```"}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	rec, resp := postChat(t, g, "disk full on 10.0.0.5")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("X-PhiGate-Blocked") == "" {
		t.Error("expected X-PhiGate-Blocked header")
	}
	if strings.Contains(resp.Choices[0].Message.Content, "rm -rf /") {
		t.Fatalf("destructive command leaked: %q", resp.Choices[0].Message.Content)
	}
	if resp.Choices[0].FinishReason != "content_filter" {
		t.Errorf("finish_reason = %q, want content_filter", resp.Choices[0].FinishReason)
	}
}

func TestAuthenticationRequired(t *testing.T) {
	cfg := testConfig()
	cfg.AllowAnonymous = false
	cfg.APIKeys = map[string]string{"secret-key": "tenant-a"}
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	g.Routes().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("unauthenticated request: status %d, want 401", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`))
	req.Header.Set("Authorization", "Bearer secret-key")
	g.Routes().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("authenticated request: status %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestDebugEndpointIsOffByDefault covers the endpoint that returned the
// plaintext of every masked value, unauthenticated, in every deployment.
func TestDebugEndpointIsOffByDefault(t *testing.T) {
	g := newTestGateway(t, testConfig(), &fakeClient{name: "local"}, &fakeClient{name: "cloud"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/debug/compress", strings.NewReader("ip 10.0.0.5"))
	g.Routes().ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Fatalf("/debug/compress status %d, want 404 when PHIGATE_DEBUG is unset", rec.Code)
	}

	cfg := testConfig()
	cfg.DebugEnabled = true
	g2 := newTestGateway(t, cfg, &fakeClient{name: "local"}, &fakeClient{name: "cloud"})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/debug/compress", strings.NewReader("ip 10.0.0.5"))
	g2.Routes().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("with PHIGATE_DEBUG=1, status %d", rec.Code)
	}
}

// TestSessionContinuityStabilisesTokens covers the multi-turn defect: the same
// value must map to the same placeholder across the turns of a conversation.
func TestSessionContinuityStabilisesTokens(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	send := func(content string) string {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":`+quote(content)+`}]}`))
		req.Header.Set("X-PhiGate-Session", "conversation-1")
		g.Routes().ServeHTTP(rec, req)
		return local.gotReq.Messages[len(local.gotReq.Messages)-1].Content
	}

	first := send("connection refused from 10.0.0.5")
	second := send("still failing for 10.0.0.5")
	tok := func(s string) string {
		i := strings.Index(s, "<V")
		if i < 0 {
			return ""
		}
		j := strings.Index(s[i:], ">")
		return s[i : i+j+1]
	}
	if a, b := tok(first), tok(second); a == "" || a != b {
		t.Fatalf("token drifted across turns: %q then %q (%q vs %q)", a, b, first, second)
	}
}

// TestTemplateCacheServesRepeatedTemplates is the cost claim as a test: two
// alerts differing only in the values they mask must collapse to one upstream
// call.
func TestTemplateCacheServesRepeatedTemplates(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	local := &fakeClient{name: "local", reply: "check the disk on <V1>"}
	g := newTestGateway(t, cfg, local, &fakeClient{name: "cloud"})

	rec1, resp1 := postChat(t, g, "disk full on 10.0.0.5")
	rec2, resp2 := postChat(t, g, "disk full on 10.9.9.9")

	if rec1.Code != 200 || rec2.Code != 200 {
		t.Fatalf("status %d / %d", rec1.Code, rec2.Code)
	}
	if local.calls != 1 {
		t.Fatalf("expected 1 upstream call for 2 same-template requests, got %d", local.calls)
	}
	if rec2.Header().Get("X-PhiGate-Cache") != "hit" {
		t.Errorf("second request should be a cache hit, headers: %v", rec2.Header())
	}
	// Critically: each request is hydrated with its own dictionary, so the
	// cached answer must not carry the first request's IP into the second.
	if got := resp1.Choices[0].Message.Content; !strings.Contains(got, "10.0.0.5") {
		t.Errorf("first answer = %q, want 10.0.0.5", got)
	}
	if got := resp2.Choices[0].Message.Content; !strings.Contains(got, "10.9.9.9") {
		t.Errorf("CACHE LEAK: second answer = %q, want 10.9.9.9", got)
	}
	if strings.Contains(resp2.Choices[0].Message.Content, "10.0.0.5") {
		t.Fatalf("CACHE LEAK: first request's value served to the second: %q",
			resp2.Choices[0].Message.Content)
	}
}

func postChatStream(t *testing.T, g *Gateway, content string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":`+quote(content)+`}]}`))
	g.Routes().ServeHTTP(rec, httpReq)
	return rec
}

// The destructive command is split across deltas to prove the guard inspects
// across chunk boundaries.
func TestStreamBlocksDestructiveCommand(t *testing.T) {
	local := &fakeClient{name: "local", stream: []string{
		"Run the following:\n", "rm -r", "f /\n", "echo done\n",
	}}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	rec := postChatStream(t, g, "please remove old temp files")
	body := rec.Body.String()

	if !strings.Contains(body, "Run the following") {
		t.Errorf("safe prefix should be streamed: %q", body)
	}
	if strings.Contains(body, "rm -rf /") {
		t.Fatalf("destructive command leaked to client: %q", body)
	}
	if !strings.Contains(body, "withheld this answer") {
		t.Errorf("expected redaction notice, got: %q", body)
	}
	if strings.Contains(body, "echo done") {
		t.Errorf("stream should be sealed after a block, got: %q", body)
	}
}

func TestStreamHydratesSafeOutput(t *testing.T) {
	local := &fakeClient{name: "local", stream: []string{"Check host <V1> ", "and retry\n"}}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	rec := postChatStream(t, g, "disk full on 10.0.0.5")
	body := rec.Body.String()

	if !strings.Contains(body, "10.0.0.5") {
		t.Fatalf("streamed output should be hydrated for operator: %q", body)
	}
	if !strings.Contains(body, "[DONE]") {
		t.Errorf("stream should terminate with [DONE]: %q", body)
	}
	for _, m := range local.gotReq.Messages {
		if strings.Contains(m.Content, "10.0.0.5") {
			t.Fatalf("raw IP leaked upstream: %q", m.Content)
		}
	}
}

func TestCodeRoutesCloud(t *testing.T) {
	local := &fakeClient{name: "local", reply: "nope"}
	cloud := &fakeClient{name: "cloud", reply: "refactor suggestion"}
	g := newTestGateway(t, testConfig(), local, cloud)

	rec, _ := postChat(t, g, "package main\nfunc handler() { doWork() }")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if local.calls != 0 || cloud.calls != 1 {
		t.Fatalf("code should route straight to cloud, local=%d cloud=%d", local.calls, cloud.calls)
	}
}

func TestStatsAndMetricsEndpoints(t *testing.T) {
	g := newTestGateway(t, testConfig(), &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})
	postChat(t, g, "disk full on 10.0.0.5")

	for _, path := range []string{"/v1/phigate/stats", "/metrics", "/v1/models", "/healthz", "/dashboard"} {
		rec := httptest.NewRecorder()
		g.Routes().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 {
			t.Errorf("GET %s: status %d", path, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	g.Routes().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(rec.Body.String(), "phigate_requests_total") {
		t.Errorf("metrics output missing request counter:\n%s", rec.Body.String())
	}
}

// TestErrorsUseOpenAIShape keeps client SDKs able to parse PhiGate's failures.
func TestErrorsUseOpenAIShape(t *testing.T) {
	g := newTestGateway(t, testConfig(), &fakeClient{name: "local"}, &fakeClient{name: "cloud"})
	rec := httptest.NewRecorder()
	g.Routes().ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[]}`)))

	var e types.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.Error.Message == "" {
		t.Fatalf("error body is not OpenAI-shaped: %s", rec.Body.String())
	}
}

// TestUpstreamErrorsAreNotLeakedToClients covers the disclosure of backend URLs
// and provider messages through the old raw-error response path.
func TestUpstreamErrorsAreNotLeakedToClients(t *testing.T) {
	secret := "https://internal-vllm.corp:8000/v1 refused: invalid key sk-abc123"
	local := &fakeClient{name: "local", err: errors.New(secret)}
	cloud := &fakeClient{name: "cloud", err: errors.New(secret)}
	g := newTestGateway(t, testConfig(), local, cloud)

	rec, _ := postChat(t, g, "disk full on 10.0.0.5")
	if strings.Contains(rec.Body.String(), "sk-abc123") || strings.Contains(rec.Body.String(), "internal-vllm") {
		t.Fatalf("internal error detail leaked to the client: %s", rec.Body.String())
	}
}
