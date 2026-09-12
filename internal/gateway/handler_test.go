package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
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
//
// The bookkeeping is mutex-guarded because the reload tests drive it from
// several goroutines at once. Sequential tests read the fields directly, which
// is safe while nothing else is running.
type fakeClient struct {
	mu sync.Mutex

	name       string
	reply      string
	replyCall  []types.ToolCall // tool calls returned alongside reply
	stream     []string         // content deltas emitted by ChatStream
	streamCall []types.ToolCall // tool-call fragments emitted after the content
	err        error
	calls      int
	gotReq     *types.ChatCompletionRequest
}

func (f *fakeClient) Name() string { return f.name }
func (f *fakeClient) Chat(_ context.Context, req *types.ChatCompletionRequest) (*types.ChatCompletionResponse, error) {
	f.mu.Lock()
	f.calls++
	f.gotReq = req
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return &types.ChatCompletionResponse{
		Choices: []types.Choice{{Message: types.Message{
			Role:      "assistant",
			Content:   f.reply,
			ToolCalls: f.replyCall,
		}}},
	}, nil
}

func (f *fakeClient) ChatStream(_ context.Context, req *types.ChatCompletionRequest, onDelta llm.StreamFunc) error {
	f.mu.Lock()
	f.calls++
	f.gotReq = req
	f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	for _, d := range f.stream {
		if err := onDelta(types.Delta{Content: d}); err != nil {
			return err
		}
	}
	// Tool-call fragments arrive as their own chunks, each with no content —
	// exactly the shape the old client dropped.
	for _, tc := range f.streamCall {
		if err := onDelta(types.Delta{ToolCalls: []types.ToolCall{tc}}); err != nil {
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

// toolCall builds an assistant tool call with the given function arguments.
func toolCall(name, args string) types.ToolCall {
	return types.ToolCall{
		ID:       "call_1",
		Type:     "function",
		Function: &types.FunctionCall{Name: name, Arguments: args},
	}
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
	if !strings.Contains(body, "⛔ PhiGate egress guardrail") {
		t.Errorf("expected a guardrail notice, got: %q", body)
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

// TestToolCallArgumentsAreMaskedUpstream is the leak test for the traffic shape
// agent frameworks actually produce.
//
// An assistant turn that invokes a tool carries no content at all — its payload
// is the JSON string in tool_calls[].function.arguments. That field rode along
// in the passthrough map, so it reached the cloud unmasked while the classifier,
// which reads Content, never saw it. README's first guarantee is that no
// personal datum leaves unmasked; for this shape it was untrue.
func TestToolCallArgumentsAreMaskedUpstream(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	cloud := &fakeClient{name: "cloud", reply: "ok"}
	g := newTestGateway(t, testConfig(), local, cloud)

	// 123456789018 is a My Number with a valid check digit; 10.0.0.5 is caught
	// by the core pack. Both are confidential/internal class, never cloud-bound
	// in the clear.
	body := `{"model":"gpt-4o","messages":[
	  {"role":"user","content":"look up this employee"},
	  {"role":"assistant","content":null,"tool_calls":[
	    {"id":"call_1","type":"function","function":{
	      "name":"lookup_employee",
	      "arguments":"{\"my_number\":\"123456789018\",\"host\":\"10.0.0.5\"}"}}]},
	  {"role":"tool","tool_call_id":"call_1","content":"found"}
	]}`
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
	for _, secret := range []string{"123456789018", "10.0.0.5"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("raw value %q left unmasked in a tool call: %s", secret, out)
		}
	}
	// Masked, not merely dropped: the call must still be usable upstream.
	var maskedArgs string
	for _, m := range sent.Messages {
		for _, tc := range m.ToolCalls {
			if tc.Function != nil {
				maskedArgs = tc.Function.Arguments
			}
		}
	}
	if maskedArgs == "" {
		t.Fatal("tool call arguments were dropped upstream rather than masked")
	}
	if !strings.Contains(maskedArgs, "<V") {
		t.Errorf("arguments carry no placeholder, so nothing was masked: %q", maskedArgs)
	}
	if !strings.Contains(maskedArgs, "my_number") {
		t.Errorf("argument structure was destroyed, tool is uncallable: %q", maskedArgs)
	}
}

// TestToolCallSensitivityReachesEgressPolicy proves the classification half.
// Masking without classification would still send the payload cloudward.
func TestToolCallSensitivityReachesEgressPolicy(t *testing.T) {
	// The default policy caps cloud egress at "internal"; a My Number is
	// confidential, so it must pin the request to the local backend.
	cfg := testConfig()
	local := &fakeClient{name: "local", reply: "ok"}
	cloud := &fakeClient{name: "cloud", reply: "ok"}
	g := newTestGateway(t, cfg, local, cloud)

	body := `{"model":"gpt-4o","messages":[
	  {"role":"assistant","content":null,"tool_calls":[
	    {"id":"call_1","type":"function","function":{
	      "name":"lookup","arguments":"{\"my_number\":\"123456789018\"}"}}]}
	]}`
	rec, _ := postRaw(t, g, body)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if cloud.calls != 0 {
		t.Fatalf("a My Number carried in tool arguments reached the cloud (%d calls)", cloud.calls)
	}
	if got := rec.Header().Get("X-PhiGate-Sensitivity"); got != "confidential" {
		t.Errorf("sensitivity = %q, want confidential — the classifier did not see the arguments", got)
	}
}

// TestToolCallArgumentsAreHydrated is the return half. A placeholder handed back
// to a client's tool is executed literally.
func TestToolCallArgumentsAreHydrated(t *testing.T) {
	local := &fakeClient{
		name:      "local",
		reply:     "",
		replyCall: []types.ToolCall{toolCall("restart_host", `{"host":"<V1>"}`)},
	}
	cloud := &fakeClient{name: "cloud", reply: "ok"}
	g := newTestGateway(t, testConfig(), local, cloud)

	rec, resp := postRaw(t, g,
		`{"model":"gpt-4o","messages":[{"role":"user","content":"disk full on 10.0.0.5"}]}`)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	calls := resp.Choices[0].Message.ToolCalls
	if len(calls) != 1 || calls[0].Function == nil {
		t.Fatalf("tool call lost on the way back: %+v", resp.Choices[0].Message)
	}
	if got := calls[0].Function.Arguments; got != `{"host":"10.0.0.5"}` {
		t.Fatalf("arguments = %q, want hydrated host — the client would call the tool with a placeholder", got)
	}
}

// TestToolCallArgumentsAreGuarded: a tool whose job is to run a command carries
// that command in its arguments. Inspecting Content alone waves through exactly
// the case the egress guard exists for.
func TestToolCallArgumentsAreGuarded(t *testing.T) {
	local := &fakeClient{
		name:      "local",
		reply:     "here you go",
		replyCall: []types.ToolCall{toolCall("run_shell", `{"cmd":"rm --force --recursive /"}`)},
	}
	cloud := &fakeClient{name: "cloud", reply: "ok"}
	g := newTestGateway(t, testConfig(), local, cloud)

	rec, resp := postChat(t, g, "clean up the disk")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-PhiGate-Blocked") == "" {
		t.Error("a destructive command in tool arguments was not blocked")
	}
	if len(resp.Choices[0].Message.ToolCalls) != 0 {
		t.Fatalf("the blocked call was still handed to the client: %+v",
			resp.Choices[0].Message.ToolCalls)
	}
	if resp.Choices[0].FinishReason != "content_filter" {
		t.Errorf("finish_reason = %q, want content_filter", resp.Choices[0].FinishReason)
	}
}

// TestToolCallAnswerSurvivesTheCache. A tool-call answer has no Content, so the
// cache's emptiness check discarded it and a hit replayed an empty message.
func TestToolCallAnswerSurvivesTheCache(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	cfg.CacheEnabled = true
	local := &fakeClient{
		name:      "local",
		replyCall: []types.ToolCall{toolCall("restart_host", `{"host":"<V1>"}`)},
	}
	cloud := &fakeClient{name: "cloud", reply: "ok"}
	g := newTestGateway(t, cfg, local, cloud)

	const body = `{"model":"gpt-4o","messages":[{"role":"user","content":"disk full on 10.0.0.5"}]}`
	if rec, _ := postRaw(t, g, body); rec.Code != 200 {
		t.Fatalf("first call: status %d", rec.Code)
	}
	rec, resp := postRaw(t, g, body)
	if rec.Code != 200 {
		t.Fatalf("second call: status %d", rec.Code)
	}
	if rec.Header().Get("X-PhiGate-Cache") != "hit" {
		t.Fatalf("second identical request did not hit the cache")
	}
	calls := resp.Choices[0].Message.ToolCalls
	if len(calls) != 1 || calls[0].Function == nil {
		t.Fatalf("cache hit replayed an answer with no tool calls: %+v", resp.Choices[0].Message)
	}
	if got := calls[0].Function.Arguments; got != `{"host":"10.0.0.5"}` {
		t.Errorf("cached arguments = %q, want hydrated with this session's dictionary", got)
	}
	if resp.Choices[0].FinishReason != "tool_calls" {
		t.Errorf("finish_reason = %q, want tool_calls — a client dispatches calls only on that reason",
			resp.Choices[0].FinishReason)
	}
}

// TestToolCallsDifferingOnlyInArgumentsDoNotShareACacheEntry: the key was built
// from message content alone, so two calls that differed only in their
// arguments — the entire content of a tool-call turn — collided on one entry and
// the second caller got an answer to a question nobody asked.
//
// The arguments here differ in values the masker does not touch. Two calls whose
// arguments differ only in a *masked* value are meant to share an entry: that
// collapse is the template cache working, and each session hydrates the shared
// pre-hydration answer with its own dictionary.
func TestToolCallsDifferingOnlyInArgumentsDoNotShareACacheEntry(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	cfg.CacheEnabled = true
	local := &fakeClient{name: "local", reply: "ok"}
	cloud := &fakeClient{name: "cloud", reply: "ok"}
	g := newTestGateway(t, cfg, local, cloud)

	mk := func(metric string) string {
		return `{"model":"gpt-4o","messages":[
		  {"role":"assistant","content":null,"tool_calls":[
		    {"id":"call_1","type":"function","function":{
		      "name":"query","arguments":"{\"metric\":\"` + metric + `\"}"}}]}]}`
	}
	if rec, _ := postRaw(t, g, mk("cpu")); rec.Code != 200 {
		t.Fatalf("first: %d", rec.Code)
	}
	rec, _ := postRaw(t, g, mk("memory"))
	if rec.Code != 200 {
		t.Fatalf("second: %d", rec.Code)
	}
	if rec.Header().Get("X-PhiGate-Cache") == "hit" {
		t.Fatal("two tool calls with different arguments shared one cache entry")
	}
}

// TestToolCallsDifferingOnlyInMaskedValuesShareACacheEntry is the other half:
// the collapse above must still happen where it is supposed to, or masking
// tool arguments would have destroyed the cache's whole cost lever for agents.
func TestToolCallsDifferingOnlyInMaskedValuesShareACacheEntry(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	cfg.CacheEnabled = true
	local := &fakeClient{name: "local", reply: "checked <V1>"}
	cloud := &fakeClient{name: "cloud", reply: "ok"}
	g := newTestGateway(t, cfg, local, cloud)

	mk := func(host string) string {
		return `{"model":"gpt-4o","messages":[
		  {"role":"assistant","content":null,"tool_calls":[
		    {"id":"call_1","type":"function","function":{
		      "name":"restart","arguments":"{\"host\":\"` + host + `\"}"}}]}]}`
	}
	if rec, _ := postRaw(t, g, mk("web-1.corp")); rec.Code != 200 {
		t.Fatalf("first: %d", rec.Code)
	}
	rec, resp := postRaw(t, g, mk("db-9.corp"))
	if rec.Code != 200 {
		t.Fatalf("second: %d", rec.Code)
	}
	if rec.Header().Get("X-PhiGate-Cache") != "hit" {
		t.Fatal("two tool calls differing only in a masked hostname missed the cache")
	}
	// The shared entry is pre-hydration, so the second caller must see its own
	// host — not the one that populated the entry.
	if got := resp.Choices[0].Message.Content; got != "checked db-9.corp" {
		t.Fatalf("content = %q, want the second session's own host", got)
	}
}

// TestToolCallRoundTripPreservesShape guards the passthrough doctrine: promoting
// tool_calls out of Extra must not start dropping what sits inside them.
func TestToolCallRoundTripPreservesShape(t *testing.T) {
	const in = `{"role":"assistant","content":null,"tool_calls":[` +
		`{"id":"call_1","type":"function","provider_ext":{"x":1},` +
		`"function":{"name":"f","arguments":"{}","strict":true}}]}`
	var m types.Message
	if err := json.Unmarshal([]byte(in), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"provider_ext"`, `"strict"`, `"content":null`, `"id":"call_1"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("round trip dropped %s: %s", want, out)
		}
	}
}

// TestStreamingToolCallArgumentsAreMaskedUpstream pins down that the leak is
// closed on both paths, not just the blocking one. Streaming shares plan(), so
// the masking applies there too — this test is what keeps that true if the two
// paths are ever allowed to build their upstream requests separately again.
func TestStreamingToolCallArgumentsAreMaskedUpstream(t *testing.T) {
	local := &fakeClient{name: "local", stream: []string{"ok"}}
	cloud := &fakeClient{name: "cloud", stream: []string{"ok"}}
	g := newTestGateway(t, testConfig(), local, cloud)

	body := `{"model":"gpt-4o","stream":true,"messages":[
	  {"role":"assistant","content":null,"tool_calls":[
	    {"id":"call_1","type":"function","function":{
	      "name":"lookup","arguments":"{\"my_number\":\"123456789018\"}"}}]}
	]}`
	rec := httptest.NewRecorder()
	g.Routes().ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body)))
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
	if strings.Contains(string(out), "123456789018") {
		t.Fatalf("raw My Number left unmasked on the streaming path: %s", out)
	}
}

// frag builds one streamed tool-call fragment for call `index`.
func frag(index int, name, args string) types.ToolCall {
	return types.ToolCall{
		Index:    &index,
		Function: &types.FunctionCall{Name: name, Arguments: args},
	}
}

// streamToolCalls pulls the tool calls out of an SSE body.
func streamToolCalls(t *testing.T, body string) []types.ToolCall {
	t.Helper()
	var out []types.ToolCall
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			continue
		}
		var chunk types.ChatCompletionChunk
		if json.Unmarshal([]byte(data), &chunk) != nil {
			continue
		}
		for _, ch := range chunk.Choices {
			out = append(out, ch.Delta.ToolCalls...)
		}
	}
	return out
}

func postStreamRaw(t *testing.T, g *Gateway, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	g.Routes().ServeHTTP(rec, httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body)))
	return rec
}

// TestStreamReassemblesAndHydratesToolCalls: the fragments a provider streams
// are reassembled by index, and the placeholder — deliberately split across two
// fragments here — is hydrated only once the whole argument string exists.
func TestStreamReassemblesAndHydratesToolCalls(t *testing.T) {
	local := &fakeClient{
		name: "local",
		streamCall: []types.ToolCall{
			{Index: intp(0), ID: "call_1", Type: "function",
				Function: &types.FunctionCall{Name: "restart_host"}},
			frag(0, "", `{"host":"<V`), // placeholder split mid-token
			frag(0, "", `1>"}`),
		},
	}
	cloud := &fakeClient{name: "cloud"}
	g := newTestGateway(t, testConfig(), local, cloud)

	rec := postChatStream(t, g, "disk full on 10.0.0.5")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	calls := streamToolCalls(t, rec.Body.String())
	if len(calls) != 1 {
		t.Fatalf("got %d tool calls, want 1 — streamed calls are being dropped: %s",
			len(calls), rec.Body.String())
	}
	if calls[0].ID != "call_1" || calls[0].Function == nil {
		t.Fatalf("call lost its identity across fragments: %+v", calls[0])
	}
	if got := calls[0].Function.Name; got != "restart_host" {
		t.Errorf("name = %q, want restart_host", got)
	}
	if got := calls[0].Function.Arguments; got != `{"host":"10.0.0.5"}` {
		t.Fatalf("arguments = %q, want hydrated — a placeholder split across "+
			"fragments must still resolve", got)
	}
}

func intp(i int) *int { return &i }

// TestStreamInterleavedToolCallsStayApart: a model emitting two calls
// interleaves their fragments, so index — not arrival order — decides which
// call a fragment belongs to.
func TestStreamInterleavedToolCallsStayApart(t *testing.T) {
	local := &fakeClient{
		name: "local",
		streamCall: []types.ToolCall{
			frag(0, "check", `{"a":`),
			frag(1, "notify", `{"b":`),
			frag(0, "", `1}`),
			frag(1, "", `2}`),
		},
	}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	rec := postChatStream(t, g, "run the checks")
	calls := streamToolCalls(t, rec.Body.String())
	if len(calls) != 2 {
		t.Fatalf("got %d calls, want 2: %s", len(calls), rec.Body.String())
	}
	if calls[0].Function.Name != "check" || calls[0].Function.Arguments != `{"a":1}` {
		t.Errorf("call 0 = %+v, fragments were mixed between calls", calls[0].Function)
	}
	if calls[1].Function.Name != "notify" || calls[1].Function.Arguments != `{"b":2}` {
		t.Errorf("call 1 = %+v, fragments were mixed between calls", calls[1].Function)
	}
}

// TestStreamGuardsToolCallArguments is the parity claim for tool calls: the
// streamed path must reach the same verdict as the blocking one, which
// TestToolCallArgumentsAreGuarded pins on the other side.
func TestStreamGuardsToolCallArguments(t *testing.T) {
	local := &fakeClient{
		name:       "local",
		streamCall: []types.ToolCall{frag(0, "run_shell", `{"cmd":"rm --force --recursive /"}`)},
	}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	rec := postChatStream(t, g, "clean up the disk")
	body := rec.Body.String()
	if calls := streamToolCalls(t, body); len(calls) != 0 {
		t.Fatalf("a destructive streamed call was handed to the client: %+v", calls)
	}
	if !strings.Contains(body, "egress guardrail withheld") {
		t.Errorf("no block notice in the stream: %s", body)
	}
	if rec.Header().Get("X-PhiGate-Blocked") == "" {
		t.Error("X-PhiGate-Blocked not set for a blocked streamed tool call")
	}
}

// TestStreamToolCallsAreNotEmittedAfterASealedStream: prose that trips the
// guard seals the stream, and the calls that prose described must not then be
// handed over — an agent executes the call, not the notice.
func TestStreamToolCallsAreNotEmittedAfterASealedStream(t *testing.T) {
	local := &fakeClient{
		name:       "local",
		stream:     []string{"run this:\n```sh\nrm --force --recursive /\n```\n"},
		streamCall: []types.ToolCall{frag(0, "restart_host", `{"host":"web-1.corp"}`)},
	}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	rec := postChatStream(t, g, "clean up the disk")
	if calls := streamToolCalls(t, rec.Body.String()); len(calls) != 0 {
		t.Fatalf("calls emitted after the stream was sealed: %+v", calls)
	}
}

// TestStreamToolCallArgumentsAreMaskedAndCached closes the loop: what is
// accumulated for the cache is the masked form, and a replayed hit is hydrated
// with the *replaying* session's dictionary.
func TestStreamToolCallArgumentsAreMaskedAndCached(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	cfg.CacheEnabled = true
	local := &fakeClient{
		name:       "local",
		streamCall: []types.ToolCall{frag(0, "restart_host", `{"host":"<V1>"}`)},
	}
	g := newTestGateway(t, cfg, local, &fakeClient{name: "cloud"})

	mk := func(host string) string {
		return `{"model":"gpt-4o","stream":true,"messages":[
		  {"role":"user","content":"disk full on ` + host + `"}]}`
	}
	if rec := postStreamRaw(t, g, mk("10.0.0.5")); rec.Code != 200 {
		t.Fatalf("first: %d", rec.Code)
	}
	rec := postStreamRaw(t, g, mk("10.9.9.9"))
	if rec.Header().Get("X-PhiGate-Cache") != "hit" {
		t.Fatalf("second identical template did not hit the cache")
	}
	calls := streamToolCalls(t, rec.Body.String())
	if len(calls) != 1 || calls[0].Function == nil {
		t.Fatalf("cache hit replayed no tool calls: %s", rec.Body.String())
	}
	if got := calls[0].Function.Arguments; got != `{"host":"10.9.9.9"}` {
		t.Fatalf("CACHE LEAK or bad hydration: arguments = %q, want the second "+
			"session's own host", got)
	}
}

// TestToolDefinitionDescriptionsAreMasked: a description is prose the model
// reads, so masking it is safe and keeps the "nothing unmasked egresses"
// invariant true for the one block that used to bypass it entirely.
func TestToolDefinitionDescriptionsAreMasked(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"help"}],
	  "tools":[{"type":"function","function":{
	    "name":"restart_host",
	    "description":"Restart a host. Runbook: wiki.corp is authoritative.",
	    "parameters":{"type":"object","properties":{
	      "host":{"type":"string","description":"for example web-1.corp"}}}}}]}`
	rec, _ := postRaw(t, g, body)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	out, err := json.Marshal(local.gotReq)
	if err != nil {
		t.Fatalf("marshal upstream: %v", err)
	}
	for _, secret := range []string{"wiki.corp", "web-1.corp"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("internal host %q left unmasked in a tool description: %s", secret, out)
		}
	}
	// The contract half must survive: masking these makes the tool uncallable.
	for _, keep := range []string{`"restart_host"`, `"host"`, `"parameters"`, `"type"`} {
		if !strings.Contains(string(out), keep) {
			t.Errorf("tool contract lost %s — the model cannot call this tool: %s", keep, out)
		}
	}
}

// TestToolDefinitionsAreClassified: masking descriptions is only half of it.
// Everything else in the block is scanned so the egress policy sees it, because
// classification is a control and `tools` was previously invisible to it.
func TestToolDefinitionsAreClassified(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	cloud := &fakeClient{name: "cloud", reply: "ok"}
	g := newTestGateway(t, testConfig(), local, cloud)

	// A credential in a default value — not a description, so it is classified
	// but deliberately left in place. The policy is what stops it egressing.
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"help"}],
	  "tools":[{"type":"function","function":{"name":"connect","parameters":
	    {"type":"object","properties":{"dsn":{"type":"string",
	      "default":"postgres://svc:Hx7kQ2mZpW@db1/app"}}}}}]}`
	rec, _ := postRaw(t, g, body)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if cloud.calls != 0 {
		t.Fatalf("a credential in a tool definition reached the cloud (%d calls)", cloud.calls)
	}
	if got := rec.Header().Get("X-PhiGate-Sensitivity"); got != "restricted" {
		t.Errorf("sensitivity = %q, want restricted — the tools block was not classified", got)
	}
}

// TestDifferentToolSetsDoNotShareACacheEntry: the same question with a
// different set of tools available has a different right answer.
func TestDifferentToolSetsDoNotShareACacheEntry(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	cfg.CacheEnabled = true
	local := &fakeClient{name: "local", reply: "ok"}
	g := newTestGateway(t, cfg, local, &fakeClient{name: "cloud"})

	mk := func(tool string) string {
		return `{"model":"gpt-4o","messages":[{"role":"user","content":"disk full"}],
		  "tools":[{"type":"function","function":{"name":"` + tool + `"}}]}`
	}
	if rec, _ := postRaw(t, g, mk("restart")); rec.Code != 200 {
		t.Fatalf("first: %d", rec.Code)
	}
	rec, _ := postRaw(t, g, mk("page_oncall"))
	if rec.Header().Get("X-PhiGate-Cache") == "hit" {
		t.Fatal("two requests offering different tools shared one cache entry")
	}
}

// TestMalformedToolsBlockIsPassedThrough: PhiGate inspects `tools`, it does not
// own it. A block it cannot parse must not turn into a client-visible failure.
func TestMalformedToolsBlockIsPassedThrough(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	rec, _ := postRaw(t, g, `{"model":"gpt-4o","messages":[{"role":"user","content":"help"}],
	  "tools":"not-an-array-but-valid-json"}`)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	out, _ := json.Marshal(local.gotReq)
	if !strings.Contains(string(out), "not-an-array-but-valid-json") {
		t.Errorf("an unexpected tools shape was dropped rather than passed through: %s", out)
	}
}

// TestToolSchemaNumbersKeepTheirPrecision: the block is decoded and re-encoded,
// and decoding numbers into float64 would silently rewrite a large schema bound.
func TestToolSchemaNumbersKeepTheirPrecision(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	rec, _ := postRaw(t, g, `{"model":"gpt-4o","messages":[{"role":"user","content":"help"}],
	  "tools":[{"type":"function","function":{"name":"f","parameters":
	    {"type":"object","properties":{"n":{"type":"integer","maximum":9007199254740993}}}}}]}`)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	out, _ := json.Marshal(local.gotReq)
	if !strings.Contains(string(out), "9007199254740993") {
		t.Errorf("schema bound lost precision on the round trip: %s", out)
	}
}

// newMultiTenantGateway builds a gateway whose "strict" tenant is held to a
// tighter egress policy than the deployment default.
func newMultiTenantGateway(t *testing.T, local, cloud llm.Client) *Gateway {
	t.Helper()
	cfg := testConfig()
	cfg.AllowAnonymous = false
	cfg.APIKeys = map[string]string{"k-open": "open", "k-strict": "strict"}
	strict, err := policy.Parse("low", "", true)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Tenants = map[string]config.Tenant{
		"strict": {Policy: &strict, RateLimitPerMin: 1, RedactPacks: []string{"jp"}},
	}
	if err := config.Validate(&cfg); err != nil {
		t.Fatalf("config: %v", err)
	}
	return newTestGateway(t, cfg, local, cloud)
}

func postAs(t *testing.T, g *Gateway, key, content string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":`+quote(content)+`}]}`))
	req.Header.Set("Authorization", "Bearer "+key)
	g.Routes().ServeHTTP(rec, req)
	return rec
}

// TestTenantPolicyIsEnforcedPerRequest: one gateway, two tenants, two egress
// limits. Before per-tenant configuration this needed two deployments.
func TestTenantPolicyIsEnforcedPerRequest(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	cloud := &fakeClient{name: "cloud", reply: "ok"}
	g := newMultiTenantGateway(t, local, cloud)

	// An internal hostname is "internal" class: the global policy lets it
	// reach the cloud, the strict tenant's does not.
	const q = "check web-1.corp for me"

	if rec := postAs(t, g, "k-open", q); rec.Header().Get("X-PhiGate-Route") != "cloud" {
		// Routing is advisory, so assert on what the policy permitted instead.
		if rec.Header().Get("X-PhiGate-Policy") != "allow" {
			t.Errorf("open tenant policy = %q, want allow", rec.Header().Get("X-PhiGate-Policy"))
		}
	}
	rec := postAs(t, g, "k-strict", q)
	if got := rec.Header().Get("X-PhiGate-Policy"); got != "local_only" {
		t.Fatalf("strict tenant policy = %q, want local_only — the tenant override "+
			"did not reach the request path", got)
	}
}

// TestTenantRateLimitIsSeparate: a tenant's own limit applies to that tenant
// and leaves the others alone.
func TestTenantRateLimitIsSeparate(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	g := newMultiTenantGateway(t, local, &fakeClient{name: "cloud"})

	if rec := postAs(t, g, "k-strict", "hello"); rec.Code != 200 {
		t.Fatalf("first strict request: %d", rec.Code)
	}
	if rec := postAs(t, g, "k-strict", "hello again"); rec.Code != 429 {
		t.Errorf("second strict request: %d, want 429 (limit is 1/min)", rec.Code)
	}
	// The unlimited tenant is untouched by its neighbour's exhaustion.
	for i := range 3 {
		if rec := postAs(t, g, "k-open", "hello"); rec.Code != 200 {
			t.Fatalf("open request %d: %d, want 200", i, rec.Code)
		}
	}
}

// TestTenantRuleSetIsSeparate: the strict tenant runs the jp pack only, so a
// value only the core pack detects is not masked for it — and the auditor
// endpoint reports the rule set that actually applies to the caller.
func TestTenantRuleSetIsSeparate(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	g := newMultiTenantGateway(t, local, &fakeClient{name: "cloud"})

	rulesFor := func(key string) map[string]any {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/v1/phigate/rules", nil)
		req.Header.Set("Authorization", "Bearer "+key)
		g.Routes().ServeHTTP(rec, req)
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode rules: %v", err)
		}
		return out
	}

	open, strict := rulesFor("k-open"), rulesFor("k-strict")
	if open["tenant"] != "open" || strict["tenant"] != "strict" {
		t.Fatalf("rules endpoint did not report the caller's tenant: %v / %v",
			open["tenant"], strict["tenant"])
	}
	if strict["tenant_overridden"] != true {
		t.Error("strict tenant not reported as overridden")
	}
	nOpen := len(open["redaction"].([]any))
	nStrict := len(strict["redaction"].([]any))
	if nStrict >= nOpen {
		t.Errorf("strict tenant has %d rules and open has %d; the jp-only override "+
			"should be the smaller set", nStrict, nOpen)
	}
	if strict["policy"] == open["policy"] {
		t.Error("both tenants reported the same policy")
	}
}

// TestReloadSwapsPolicyWithoutRestart is the SIer claim, asserted rather than
// described: the same running gateway, the same listener, a different egress
// limit on the next request.
func TestReloadSwapsPolicyWithoutRestart(t *testing.T) {
	local := &fakeClient{name: "local", reply: "ok"}
	cloud := &fakeClient{name: "cloud", reply: "ok"}
	g := newTestGateway(t, testConfig(), local, cloud)

	// An internal hostname is allowed to the cloud under the default policy.
	const q = "check web-1.corp"
	if got := postAsAnon(t, g, q).Header().Get("X-PhiGate-Policy"); got != "allow" {
		t.Fatalf("before reload: policy = %q, want allow", got)
	}

	tighter := testConfig()
	p, err := policy.Parse("low", "", true)
	if err != nil {
		t.Fatal(err)
	}
	tighter.Policy = p
	if err := g.Reload(tighter); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if got := postAsAnon(t, g, q).Header().Get("X-PhiGate-Policy"); got != "local_only" {
		t.Fatalf("after reload: policy = %q, want local_only", got)
	}
}

func postAsAnon(t *testing.T, g *Gateway, content string) *httptest.ResponseRecorder {
	t.Helper()
	rec, _ := postChat(t, g, content)
	return rec
}

// TestReloadRotatesAPIKeys: rotating a credential is the operation an SIer asks
// about most, and it used to need a restart.
func TestReloadRotatesAPIKeys(t *testing.T) {
	cfg := testConfig()
	cfg.AllowAnonymous = false
	cfg.APIKeys = map[string]string{"old-key": "t"}
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	if rec := postAs(t, g, "old-key", "hello"); rec.Code != 200 {
		t.Fatalf("old key before reload: %d", rec.Code)
	}

	rotated := cfg
	rotated.APIKeys = map[string]string{"new-key": "t"}
	if err := g.Reload(rotated); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if rec := postAs(t, g, "new-key", "hello"); rec.Code != 200 {
		t.Errorf("new key after reload: %d, want 200", rec.Code)
	}
	if rec := postAs(t, g, "old-key", "hello"); rec.Code != 401 {
		t.Errorf("revoked key after reload: %d, want 401", rec.Code)
	}
}

// TestFailedReloadChangesNothing is the property that makes reloading safe to
// do during business hours. A rule pack that does not exist must leave the
// running configuration untouched, not half-applied.
func TestFailedReloadChangesNothing(t *testing.T) {
	cfg := testConfig()
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	before := len(g.now().global.engine.Rules())

	broken := testConfig()
	broken.RedactPacks = []string{"no-such-pack"}
	p, err := policy.Parse("low", "", true)
	if err != nil {
		t.Fatal(err)
	}
	broken.Policy = p // a change that would be visible if it were applied

	if err := g.Reload(broken); err == nil {
		t.Fatal("a reload naming a rule pack that does not exist was accepted")
	}
	if got := len(g.now().global.engine.Rules()); got != before {
		t.Errorf("rule count changed from %d to %d after a failed reload", before, got)
	}
	if got := postAsAnon(t, g, "check web-1.corp").Header().Get("X-PhiGate-Policy"); got != "allow" {
		t.Fatalf("policy = %q after a failed reload; the new value was partially applied", got)
	}
}

// TestReloadPurgesTheCacheWhenRulesChange: a rule change alters what
// "compressed" means, so every key was derived under rules that no longer
// apply. Serving those entries afterwards answers the new question with the old
// question's answer.
func TestReloadPurgesTheCacheWhenRulesChange(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	cfg.CacheEnabled = true
	local := &fakeClient{name: "local", reply: "ok"}
	g := newTestGateway(t, cfg, local, &fakeClient{name: "cloud"})

	const q = "disk full on 10.0.0.5"
	postAsAnon(t, g, q)
	if rec := postAsAnon(t, g, q); rec.Header().Get("X-PhiGate-Cache") != "hit" {
		t.Fatal("the second identical request did not hit the cache")
	}

	changed := cfg
	changed.RedactPacks = []string{"core"}
	if err := g.Reload(changed); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if rec := postAsAnon(t, g, q); rec.Header().Get("X-PhiGate-Cache") == "hit" {
		t.Error("an entry keyed under the old rule set survived a rule change")
	}

	// A reload that does not touch detection must keep the cache: purging on
	// every reload would make reloading expensive enough to avoid.
	postAsAnon(t, g, q)
	untouched := changed
	untouched.RateLimitPerMin = 0
	if err := g.Reload(untouched); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if rec := postAsAnon(t, g, q); rec.Header().Get("X-PhiGate-Cache") != "hit" {
		t.Error("the cache was purged by a reload that did not change detection")
	}
}

// TestReloadDoesNotDisturbSessions: hydration depends on the session
// dictionary, so a reload that dropped sessions would break every conversation
// in progress at the moment an operator rotated a key.
func TestReloadDoesNotDisturbSessions(t *testing.T) {
	local := &fakeClient{name: "local", reply: "host <V1> again"}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})

	post := func(content string) types.ChatCompletionResponse {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":`+quote(content)+`}]}`))
		req.Header.Set("X-PhiGate-Session", "conv-1")
		g.Routes().ServeHTTP(rec, req)
		var resp types.ChatCompletionResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp
	}

	post("disk full on 10.0.0.5")
	if err := g.Reload(testConfig()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	// The dictionary from before the reload must still resolve <V1>.
	if got := post("and now?").Choices[0].Message.Content; !strings.Contains(got, "10.0.0.5") {
		t.Errorf("content = %q; the session dictionary did not survive the reload", got)
	}
}

// TestReloadUnderLoadIsRaceFree exercises the swap against live traffic, which
// is the condition it exists for and the one a data race would only ever show
// up under. Meaningful only with -race; harmless without it.
func TestReloadUnderLoadIsRaceFree(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 50
	cfg.CacheEnabled = true
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok <V1>"}, &fakeClient{name: "cloud"})

	strict := testConfig()
	p, err := policy.Parse("low", "", true)
	if err != nil {
		t.Fatal(err)
	}
	strict.Policy = p
	strict.RedactPacks = []string{"core"}

	var wg sync.WaitGroup
	done := make(chan struct{})

	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				rec, _ := postChat(t, g, "disk full on 10.0.0.5 and web-1.corp")
				if rec.Code != 200 {
					t.Errorf("request failed during reload: %d", rec.Code)
					return
				}
			}
		}()
	}

	// Flip between two configurations while those requests are in flight.
	for i := range 40 {
		next := cfg
		if i%2 == 1 {
			next = strict
		}
		if err := g.Reload(next); err != nil {
			t.Errorf("reload %d: %v", i, err)
			break
		}
	}
	close(done)
	wg.Wait()
}

// TestTokenBudgetRefusesAnExhaustedTenant. The budget bounds spend, where the
// rate limit bounds arrival rate: a hundred well-spaced requests carrying a
// megabyte each pass any rate limit and are what an unexpected invoice is made
// of.
func TestTokenBudgetRefusesAnExhaustedTenant(t *testing.T) {
	cfg := testConfig()
	cfg.AllowAnonymous = false
	cfg.APIKeys = map[string]string{"k-small": "small", "k-free": "free"}
	cfg.Tenants = map[string]config.Tenant{
		"small": {TokenBudget: 30},
	}
	if err := config.Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	// The first request is always allowed: nothing has been spent yet, and a
	// request's cost is not known until it has finished.
	first := postAs(t, g, "k-small", "disk full on 10.0.0.5, please investigate carefully")
	if first.Code != 200 {
		t.Fatalf("first request: %d", first.Code)
	}
	if first.Header().Get("X-PhiGate-Budget") != "30" {
		t.Errorf("budget header = %q, want 30", first.Header().Get("X-PhiGate-Budget"))
	}

	// Keep going until the allowance is gone. It must run out.
	var refused *httptest.ResponseRecorder
	for range 20 {
		rec := postAs(t, g, "k-small", "disk full on 10.0.0.5, please investigate carefully")
		if rec.Code == 429 {
			refused = rec
			break
		}
	}
	if refused == nil {
		t.Fatal("a 30-token budget was never exhausted over 20 requests")
	}
	if got := refused.Header().Get("X-PhiGate-Budget-Remaining"); got != "0" {
		t.Errorf("remaining header on refusal = %q, want 0", got)
	}
	if !strings.Contains(refused.Body.String(), "token_budget_exceeded") {
		t.Errorf("refusal does not name the reason: %s", refused.Body.String())
	}

	// An unbudgeted tenant is untouched by its neighbour's exhaustion.
	if rec := postAs(t, g, "k-free", "hello"); rec.Code != 200 {
		t.Errorf("unbudgeted tenant refused with %d", rec.Code)
	}
}

// TestBudgetIsNotEnforcedWithoutATenantLedger: a store that cannot answer means
// "no limit known", never "limit reached". Failing closed would turn an
// accounting outage into an outage.
func TestBudgetIsNotEnforcedWithoutATenantLedger(t *testing.T) {
	cfg := testConfig()
	cfg.AllowAnonymous = false
	cfg.APIKeys = map[string]string{"k": "t"}
	cfg.Tenants = map[string]config.Tenant{"t": {TokenBudget: 1}}
	if err := config.Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})
	g.SetLedger(plainLedger{tokens.NewLedger(tokens.NewPriceBook())})

	for i := range 5 {
		if rec := postAs(t, g, "k", "disk full on 10.0.0.5"); rec.Code != 200 {
			t.Fatalf("request %d refused with %d; a ledger that cannot report "+
				"consumption must not be read as a exhausted budget", i, rec.Code)
		}
	}
}

// plainLedger implements only the required half of the seam.
type plainLedger struct{ inner tokens.LedgerStore }

func (p plainLedger) Record(r tokens.Record, b string) { p.inner.Record(r, b) }
func (p plainLedger) Totals() tokens.Totals            { return p.inner.Totals() }

// TestBudgetDoesNotBlockTheReportingEndpoints: a tenant that has exhausted its
// allowance must still be able to find out why it is being refused.
func TestBudgetDoesNotBlockTheReportingEndpoints(t *testing.T) {
	cfg := testConfig()
	cfg.AllowAnonymous = false
	cfg.APIKeys = map[string]string{"k": "t"}
	cfg.Tenants = map[string]config.Tenant{"t": {TokenBudget: 1}}
	if err := config.Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	postAs(t, g, "k", "spend the allowance on this request")
	if rec := postAs(t, g, "k", "again"); rec.Code != 429 {
		t.Fatalf("expected the budget to be exhausted, got %d", rec.Code)
	}

	for _, path := range []string{"/v1/phigate/stats", "/v1/phigate/rules"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer k")
		g.Routes().ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("%s returned %d for a tenant over budget; it must stay readable",
				path, rec.Code)
		}
	}
}

// embeddingClient is a fakeClient that also implements llm.Embedder.
type embeddingClient struct {
	*fakeClient
	got *types.EmbeddingsRequest
}

func (e *embeddingClient) Embed(_ context.Context, req *types.EmbeddingsRequest) (*types.EmbeddingsResponse, error) {
	e.got = req
	data := make([]types.Embedding, len(req.Texts))
	for i := range req.Texts {
		data[i] = types.Embedding{Object: "embedding", Index: i, Embedding: []float64{0.1, 0.2}}
	}
	return &types.EmbeddingsResponse{
		Object: "list", Data: data, Model: req.Model,
		Usage: types.Usage{PromptTokens: 5, TotalTokens: 5},
	}, nil
}

func postEmbeddings(t *testing.T, g *Gateway, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	g.Routes().ServeHTTP(rec, httptest.NewRequest("POST", "/v1/embeddings", strings.NewReader(body)))
	return rec
}

// TestEmbeddingsAreMasked is the point of the endpoint. In a RAG deployment the
// text sent for embedding is the corpus — the tickets, the contracts, the
// notes — and it is the most sensitive traffic the gateway sees.
func TestEmbeddingsAreMasked(t *testing.T) {
	local := &embeddingClient{fakeClient: &fakeClient{name: "local"}}
	cloud := &embeddingClient{fakeClient: &fakeClient{name: "cloud"}}
	g := newTestGateway(t, testConfig(), local, cloud)

	rec := postEmbeddings(t, g, `{"model":"text-embedding-3-small",
	  "input":["従業員 1234 5678 9018 の記録","host web-1.corp is down"]}`)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}

	// A My Number is confidential, so the policy confines this to local.
	sent := local.got
	if sent == nil {
		t.Fatal("the corpus did not reach the local backend")
	}
	for _, txt := range sent.Texts {
		for _, secret := range []string{"1234 5678 9018", "web-1.corp"} {
			if strings.Contains(txt, secret) {
				t.Errorf("raw value %q was sent for embedding: %q", secret, txt)
			}
		}
	}
	if cloud.got != nil {
		t.Error("a corpus containing a My Number was embedded in the cloud")
	}
	if rec.Header().Get("X-PhiGate-Sensitivity") != "confidential" {
		t.Errorf("sensitivity = %q, want confidential", rec.Header().Get("X-PhiGate-Sensitivity"))
	}
}

// TestEmbeddingsShareTheSessionDictionary is what makes retrieval work: a
// document and a query embedded through the same session must mask the same
// value to the same placeholder, or the vectors describe different text.
func TestEmbeddingsShareTheSessionDictionary(t *testing.T) {
	local := &embeddingClient{fakeClient: &fakeClient{name: "local"}}
	cloud := &embeddingClient{fakeClient: &fakeClient{name: "cloud"}}
	g := newTestGateway(t, testConfig(), local, cloud)

	// An internal hostname is cloud-eligible under the default policy, so which
	// backend serves this is the policy's business and not what is under test.
	post := func(input string) []string {
		local.got, cloud.got = nil, nil
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/embeddings",
			strings.NewReader(`{"model":"m","input":`+quote(input)+`}`))
		req.Header.Set("X-PhiGate-Session", "corpus-1")
		g.Routes().ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		if local.got != nil {
			return local.got.Texts
		}
		if cloud.got == nil {
			t.Fatal("no backend received the request")
		}
		return cloud.got.Texts
	}

	doc := post("incident on host web-1.corp at 03:00")
	query := post("what happened on web-1.corp?")

	// Both must contain the same placeholder for the same host.
	tok := placeholderIn(doc[0])
	if tok == "" {
		t.Fatalf("the document was not masked: %q", doc[0])
	}
	if !strings.Contains(query[0], tok) {
		t.Errorf("the query masked the same host to a different token:\n doc:   %q\n query: %q",
			doc[0], query[0])
	}
}

func placeholderIn(s string) string {
	i := strings.Index(s, "<V")
	if i < 0 {
		return ""
	}
	j := strings.Index(s[i:], ">")
	if j < 0 {
		return ""
	}
	return s[i : i+j+1]
}

// TestEmbeddingsPreserveTheInputShape: a single string in must be a single
// string out. Some providers answer differently for an array, and a proxy that
// silently changed the request shape would change the answer's.
func TestEmbeddingsPreserveTheInputShape(t *testing.T) {
	local := &embeddingClient{fakeClient: &fakeClient{name: "local"}}
	cloud := &embeddingClient{fakeClient: &fakeClient{name: "cloud"}}
	g := newTestGateway(t, testConfig(), local, cloud)

	postEmbeddings(t, g, `{"model":"m","input":"従業員 1234 5678 9018 の記録"}`)
	out, err := json.Marshal(embeddedBy(t, local, cloud))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"input":"`) {
		t.Errorf("a string input was re-emitted as something else: %s", out)
	}
}

// embeddedBy returns the request whichever backend actually received it.
// Which one that is belongs to the egress policy, not to a test asserting on
// the request's shape.
func embeddedBy(t *testing.T, local, cloud *embeddingClient) *types.EmbeddingsRequest {
	t.Helper()
	if local.got != nil {
		return local.got
	}
	if cloud.got == nil {
		t.Fatal("no backend received the request")
	}
	return cloud.got
}

// TestEmbeddingsRejectABackendThatCannotEmbed says so plainly rather than
// forwarding the request to find out.
func TestEmbeddingsRejectABackendThatCannotEmbed(t *testing.T) {
	// Plain fakeClients implement Client but not Embedder.
	g := newTestGateway(t, testConfig(), &fakeClient{name: "local"}, &fakeClient{name: "cloud"})

	rec := postEmbeddings(t, g, `{"model":"m","input":"web-1.corp"}`)
	if rec.Code != 501 {
		t.Fatalf("status %d, want 501", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "embeddings_unsupported") {
		t.Errorf("the error does not name the problem: %s", rec.Body.String())
	}
}

// TestEmbeddingsPassTokenInputThrough: a pre-tokenised request has nothing to
// mask and must not be mangled.
func TestEmbeddingsPassTokenInputThrough(t *testing.T) {
	local := &embeddingClient{fakeClient: &fakeClient{name: "local"}}
	cloud := &embeddingClient{fakeClient: &fakeClient{name: "cloud"}}
	g := newTestGateway(t, testConfig(), local, cloud)

	rec := postEmbeddings(t, g, `{"model":"m","input":[1212,318,257,1332]}`)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	out, err := json.Marshal(embeddedBy(t, local, cloud))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "1212") {
		t.Errorf("token input was lost: %s", out)
	}
}

// TestCacheHitsAcrossDictionaryNumbering is the defect the corpus measurement
// found. The session dictionary numbers a value the first time it is ever seen,
// so the same payload twice in one busy session compressed to different text
// and missed a key built on that text. Measured on the eight LogHub corpora the
// README benchmarks with: 4.5% keyed on the text, 50.5% keyed on the shape.
func TestCacheHitsAcrossDictionaryNumbering(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	cfg.CacheEnabled = true
	local := &fakeClient{name: "local", reply: "restart <V1>"}
	g := newTestGateway(t, cfg, local, &fakeClient{name: "cloud"})

	post := func(content string) (*httptest.ResponseRecorder, types.ChatCompletionResponse) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/chat/completions",
			strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":`+quote(content)+`}]}`))
		// One long-lived session, which is what makes the numbering diverge.
		req.Header.Set("X-PhiGate-Session", "conv-1")
		g.Routes().ServeHTTP(rec, req)
		var resp types.ChatCompletionResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec, resp
	}

	// The first payload populates the cache under <V1>.
	post("disk full on 10.0.0.5")
	// Unrelated traffic advances the dictionary, so the next identical-shaped
	// payload gets a much higher placeholder number.
	for i := range 5 {
		post("unrelated event on 10.1.1." + strconv.Itoa(i))
	}

	rec, resp := post("disk full on 10.9.9.9")
	if rec.Header().Get("X-PhiGate-Cache") != "hit" {
		t.Fatalf("a payload of the same shape missed the cache; the key is still "+
			"built on the session's numbering (headers %v)", rec.Header())
	}
	// And the answer must be restored into *this* payload's value, not the one
	// that populated the entry.
	if got := resp.Choices[0].Message.Content; got != "restart 10.9.9.9" {
		t.Fatalf("content = %q, want \"restart 10.9.9.9\" — the canonical answer "+
			"was not mapped back into this payload's numbering", got)
	}
}

// TestShapeKeyingDoesNotMergeDifferentQuestions. Keying on shape is still exact
// matching: two payloads share a key only if they are identical once their
// placeholders are renumbered. This is the property a semantic tier would
// trade away, so it needs a test.
func TestShapeKeyingDoesNotMergeDifferentQuestions(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	cfg.CacheEnabled = true
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	postAsAnon(t, g, "disk full on 10.0.0.5")
	rec := postAsAnon(t, g, "memory exhausted on 10.0.0.5")
	if rec.Header().Get("X-PhiGate-Cache") == "hit" {
		t.Fatal("two different questions shared a cache entry")
	}
}

// TestShapeKeyingKeepsCrossSessionIsolation: the entry is stored in canonical
// form and restored per payload, so the cross-session guarantee has to survive
// the extra translation.
func TestShapeKeyingKeepsCrossSessionIsolation(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	cfg.CacheEnabled = true
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "check <V1> now"}, &fakeClient{name: "cloud"})

	_, first := postRaw(t, g,
		`{"model":"gpt-4o","messages":[{"role":"user","content":"disk full on 10.0.0.5"}]}`)
	rec, second := postRaw(t, g,
		`{"model":"gpt-4o","messages":[{"role":"user","content":"disk full on 10.9.9.9"}]}`)

	if rec.Header().Get("X-PhiGate-Cache") != "hit" {
		t.Fatal("the second request did not hit the cache")
	}
	if got := first.Choices[0].Message.Content; got != "check 10.0.0.5 now" {
		t.Errorf("first answer = %q", got)
	}
	if got := second.Choices[0].Message.Content; got != "check 10.9.9.9 now" {
		t.Fatalf("CACHE LEAK: second answer = %q, want its own host", got)
	}
}

// TestAnswerWithAnUnknownPlaceholderIsLeftAlone: a model can emit a placeholder
// that was not in its prompt, and inventing an original for it would hydrate a
// value the answer never referred to.
func TestAnswerWithAnUnknownPlaceholderIsLeftAlone(t *testing.T) {
	cfg := testConfig()
	cfg.CacheMax = 100
	cfg.CacheEnabled = true
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "see <V1> and <V99>"}, &fakeClient{name: "cloud"})

	postAsAnon(t, g, "disk full on 10.0.0.5")
	_, resp := postRaw(t, g,
		`{"model":"gpt-4o","messages":[{"role":"user","content":"disk full on 10.9.9.9"}]}`)

	got := resp.Choices[0].Message.Content
	if !strings.Contains(got, "10.9.9.9") {
		t.Errorf("content = %q, want the known placeholder restored", got)
	}
	if !strings.Contains(got, "<V99>") {
		t.Errorf("content = %q, want the unknown placeholder left as it was", got)
	}
}

// TestBlockingPathWithholdsTheCommandNotTheAnswer.
//
// The regression this exists for is measurable rather than hypothetical:
// disk-full-remediation scored 1.60 against a raw 9.00 in eval/cases.json,
// because the guard replaced a four-step remediation with a notice over the
// one step that earned the block. Disk exhaustion is the most common emergency
// an AIOps assistant is asked about, and an assistant that answers it with a
// wall is one whose guard gets switched off.
func TestBlockingPathWithholdsTheCommandNotTheAnswer(t *testing.T) {
	answer := "Here is a safe sequence to reclaim space in /var.\n" +
		"\n" +
		"### 1. Find the big consumers\n" +
		"```bash\n" +
		"du -xh /var --max-depth=2 | sort -rh | head -20\n" +
		"```\n" +
		"\n" +
		"### 2. Check for deleted-but-open files\n" +
		"```bash\n" +
		"lsof +L1 | grep /var\n" +
		"```\n" +
		"\n" +
		"### 3. Reclaim it\n" +
		"```bash\n" +
		"rm -rf /var\n" +
		"```\n" +
		"\n" +
		"Rotate logs afterwards so this does not recur.\n"

	local := &fakeClient{name: "local", reply: answer}
	g := newTestGateway(t, testConfig(), local, &fakeClient{name: "cloud"})
	rec, resp := postChat(t, g, "/var is full and the service will not start")
	if rec.Code != 200 {
		t.Fatalf("request failed: %d %s", rec.Code, rec.Body.String())
	}
	got := resp.Choices[0].Message.Content

	if strings.Contains(got, "rm -rf /var") {
		t.Fatalf("the blocked command reached the operator: %q", got)
	}
	if !strings.Contains(got, "⛔ PhiGate egress guardrail") {
		t.Errorf("no guardrail notice: %q", got)
	}
	if resp.Choices[0].FinishReason != "content_filter" {
		t.Errorf("finish_reason = %q, want content_filter", resp.Choices[0].FinishReason)
	}
	// The point of the change: the operator still gets the investigation.
	for _, keep := range []string{
		"du -xh /var",
		"lsof +L1",
		"Rotate logs afterwards",
		"### 1. Find the big consumers",
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("safe content was withheld along with the command: %q missing from:\n%s", keep, got)
		}
	}
	// X-PhiGate-Blocked must still mean a rule fired, even though the answer
	// around the offending span survived.
	if h := rec.Header().Get("X-PhiGate-Blocked"); h == "" {
		t.Error("X-PhiGate-Blocked was not set for a blocked answer")
	}
}
