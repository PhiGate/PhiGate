package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tenkan/phigate/internal/config"
	"github.com/tenkan/phigate/internal/llm"
	"github.com/tenkan/phigate/internal/router"
	"github.com/tenkan/phigate/internal/types"
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
	return config.Config{LocalModel: "phi4-mini", CloudModel: "gpt-4o", SystemPreamble: "PREAMBLE"}
}

func postChat(t *testing.T, g *Gateway, content string) (*httptest.ResponseRecorder, types.ChatCompletionResponse) {
	t.Helper()
	reqBody, _ := json.Marshal(types.ChatCompletionRequest{
		Model:    "gpt-4o",
		Messages: []types.Message{{Role: "user", Content: content}},
	})
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(string(reqBody)))
	g.Routes().ServeHTTP(rec, httpReq)

	var resp types.ChatCompletionResponse
	if rec.Code == 200 {
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	}
	return rec, resp
}

func TestDispatchLocalAndHydrate(t *testing.T) {
	local := &fakeClient{name: "local", reply: "investigate host <V1>"}
	cloud := &fakeClient{name: "cloud", reply: "should not be called"}
	g := NewGatewayWith(testConfig(), local, cloud, router.NewHeuristicRouter())

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
	// Hydration restored the real IP for the operator.
	if got := resp.Choices[0].Message.Content; got != "investigate host 10.0.0.5" {
		t.Fatalf("content = %q, want hydrated IP", got)
	}
	// The backend never saw the raw IP, and got the system preamble.
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
	g := NewGatewayWith(testConfig(), local, cloud, router.NewHeuristicRouter())

	rec, resp := postChat(t, g, "disk full on 10.0.0.5")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if local.calls != 1 || cloud.calls != 1 {
		t.Fatalf("expected fallback, local=%d cloud=%d", local.calls, cloud.calls)
	}
	if rec.Header().Get("X-PhiGate-Backend") != "cloud" {
		t.Errorf("backend header = %q, want cloud", rec.Header().Get("X-PhiGate-Backend"))
	}
	if got := resp.Choices[0].Message.Content; got != "host 10.0.0.5 is down" {
		t.Fatalf("content = %q, want hydrated", got)
	}
}

func TestNonStreamBlocksDestructive(t *testing.T) {
	local := &fakeClient{name: "local", reply: "To recover space, run: rm -rf /var/data"}
	cloud := &fakeClient{name: "cloud"}
	g := NewGatewayWith(testConfig(), local, cloud, router.NewHeuristicRouter())

	rec, resp := postChat(t, g, "disk full on 10.0.0.5")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("X-PhiGate-Blocked") == "" {
		t.Error("expected X-PhiGate-Blocked header")
	}
	if strings.Contains(resp.Choices[0].Message.Content, "rm -rf") {
		t.Fatalf("destructive command leaked: %q", resp.Choices[0].Message.Content)
	}
	if resp.Choices[0].FinishReason != "content_filter" {
		t.Errorf("finish_reason = %q, want content_filter", resp.Choices[0].FinishReason)
	}
}

func postChatStream(t *testing.T, g *Gateway, content string) *httptest.ResponseRecorder {
	t.Helper()
	reqBody, _ := json.Marshal(types.ChatCompletionRequest{
		Model:    "gpt-4o",
		Stream:   true,
		Messages: []types.Message{{Role: "user", Content: content}},
	})
	rec := httptest.NewRecorder()
	httpReq := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(string(reqBody)))
	g.Routes().ServeHTTP(rec, httpReq)
	return rec
}

// The destructive command is split across deltas ("rm -r" + "f /tmp") to prove
// the guard inspects across chunk boundaries.
func TestStreamBlocksDestructiveCommand(t *testing.T) {
	local := &fakeClient{name: "local", stream: []string{
		"Run the following:\n", "rm -r", "f /tmp/data\n", "echo done\n",
	}}
	cloud := &fakeClient{name: "cloud"}
	g := NewGatewayWith(testConfig(), local, cloud, router.NewHeuristicRouter())

	rec := postChatStream(t, g, "please remove old temp files")
	body := rec.Body.String()

	if !strings.Contains(body, "Run the following") {
		t.Errorf("safe prefix should be streamed: %q", body)
	}
	if strings.Contains(body, "rm -rf") {
		t.Fatalf("destructive command leaked to client: %q", body)
	}
	if !strings.Contains(body, "blocked a destructive command") {
		t.Errorf("expected redaction notice, got: %q", body)
	}
	if strings.Contains(body, "echo done") {
		t.Errorf("stream should be sealed after a block, got: %q", body)
	}
	if rec.Header().Get("X-PhiGate-Route") != "local" {
		t.Errorf("route header = %q, want local", rec.Header().Get("X-PhiGate-Route"))
	}
}

func TestStreamHydratesSafeOutput(t *testing.T) {
	local := &fakeClient{name: "local", stream: []string{"Check host <V1> ", "and retry\n"}}
	cloud := &fakeClient{name: "cloud"}
	g := NewGatewayWith(testConfig(), local, cloud, router.NewHeuristicRouter())

	rec := postChatStream(t, g, "disk full on 10.0.0.5")
	body := rec.Body.String()

	if !strings.Contains(body, "10.0.0.5") {
		t.Fatalf("streamed output should be hydrated for operator: %q", body)
	}
	if !strings.Contains(body, "[DONE]") {
		t.Errorf("stream should terminate with [DONE]: %q", body)
	}
	// The backend must never have seen the raw IP.
	for _, m := range local.gotReq.Messages {
		if strings.Contains(m.Content, "10.0.0.5") {
			t.Fatalf("raw IP leaked upstream: %q", m.Content)
		}
	}
}

func TestCodeRoutesCloud(t *testing.T) {
	local := &fakeClient{name: "local", reply: "nope"}
	cloud := &fakeClient{name: "cloud", reply: "refactor suggestion"}
	g := NewGatewayWith(testConfig(), local, cloud, router.NewHeuristicRouter())

	rec, _ := postChat(t, g, "package main\nfunc handler() { doWork() }")
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if local.calls != 0 || cloud.calls != 1 {
		t.Fatalf("code should route straight to cloud, local=%d cloud=%d", local.calls, cloud.calls)
	}
}
