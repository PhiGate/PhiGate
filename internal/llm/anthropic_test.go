package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phigate/phigate/internal/types"
)

// capture records the request an AnthropicClient sends, and replies with resp.
func capture(t *testing.T, provider Provider, resp string) (*AnthropicClient, *anthropicRequest, *http.Request) {
	t.Helper()
	var body anthropicRequest
	var got *http.Request

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode upstream request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)

	cfg := ProviderConfig{Name: "cloud", Provider: provider, BaseURL: srv.URL, APIKey: "k"}
	if provider == ProviderBedrock {
		cfg.Region = "us-east-1"
		cfg.AccessKeyID, cfg.SecretAccessKey = "AKIDEXAMPLE", "secret"
	}
	c, err := NewAnthropicClient(cfg, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return c, &body, got
}

const okReply = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5",
  "content":[{"type":"text","text":"restart the node"}],
  "stop_reason":"end_turn","usage":{"input_tokens":11,"output_tokens":4}}`

// TestSystemPromptBecomesATopLevelField is the difference that would break
// PhiGate specifically: the gateway prepends a preamble explaining that <V1> is
// a placeholder, and left as a message that preamble becomes a user turn the
// model answers rather than obeys.
func TestSystemPromptBecomesATopLevelField(t *testing.T) {
	c, sent, _ := capture(t, ProviderAnthropic, okReply)

	_, err := c.Chat(context.Background(), &types.ChatCompletionRequest{
		Model: "claude-opus-5",
		Messages: []types.Message{
			{Role: "system", Content: "PREAMBLE about <V1>"},
			{Role: "user", Content: "disk full on <V1>"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sent.System != "PREAMBLE about <V1>" {
		t.Errorf("system = %q, want the preamble in the top-level field", sent.System)
	}
	if len(sent.Messages) != 1 || sent.Messages[0].Role != "user" {
		t.Fatalf("messages = %+v, want the system turn removed from the list", sent.Messages)
	}
}

// TestMaxTokensIsAlwaysSent: OpenAI treats it as optional and Anthropic
// rejects a request without it, so a gateway that forwards the client's
// omission produces a 400 the client cannot explain.
func TestMaxTokensIsAlwaysSent(t *testing.T) {
	c, sent, _ := capture(t, ProviderAnthropic, okReply)

	_, err := c.Chat(context.Background(), &types.ChatCompletionRequest{
		Model:    "claude-opus-5",
		Messages: []types.Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sent.MaxTokens <= 0 {
		t.Fatalf("max_tokens = %d; Anthropic rejects a request without one", sent.MaxTokens)
	}

	// A client that does name a limit keeps it.
	want := 128
	c2, sent2, _ := capture(t, ProviderAnthropic, okReply)
	if _, err := c2.Chat(context.Background(), &types.ChatCompletionRequest{
		Model: "claude-opus-5", MaxTokens: &want,
		Messages: []types.Message{{Role: "user", Content: "hi"}},
	}); err != nil {
		t.Fatal(err)
	}
	if sent2.MaxTokens != want {
		t.Errorf("max_tokens = %d, want the client's %d", sent2.MaxTokens, want)
	}
}

// TestToolCallsSurviveBothDirections. The gateway masks tool-call arguments and
// guards the calls in an answer; a backend that dropped either would reintroduce
// the defect that work exists to fix.
func TestToolCallsSurviveBothDirections(t *testing.T) {
	const reply = `{"id":"msg_2","type":"message","role":"assistant","model":"claude-opus-5",
	  "content":[
	    {"type":"text","text":"checking"},
	    {"type":"tool_use","id":"toolu_9","name":"restart_host","input":{"host":"<V1>"}}],
	  "stop_reason":"tool_use","usage":{"input_tokens":5,"output_tokens":7}}`

	c, sent, _ := capture(t, ProviderAnthropic, reply)

	resp, err := c.Chat(context.Background(), &types.ChatCompletionRequest{
		Model: "claude-opus-5",
		Messages: []types.Message{
			{Role: "user", Content: "restart it"},
			{Role: "assistant", ToolCalls: []types.ToolCall{{
				ID: "toolu_1", Type: "function",
				Function: &types.FunctionCall{Name: "lookup", Arguments: `{"host":"<V1>"}`},
			}}},
			{Role: "tool", Content: "ok", Extra: map[string]json.RawMessage{
				"tool_call_id": json.RawMessage(`"toolu_1"`),
			}},
		},
		Extra: map[string]json.RawMessage{
			"tools": json.RawMessage(`[{"type":"function","function":{"name":"lookup",
			  "description":"look up a host","parameters":{"type":"object","properties":{}}}}]`),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Request side: the assistant tool call became a tool_use block, and the
	// tool result became a *user* turn with a tool_result block.
	if len(sent.Messages) != 3 {
		t.Fatalf("sent %d messages, want 3: %+v", len(sent.Messages), sent.Messages)
	}
	if sent.Messages[1].Content[0].Type != "tool_use" {
		t.Errorf("assistant turn = %+v, want a tool_use block", sent.Messages[1].Content[0])
	}
	// Compared semantically: Go escapes < and > when it marshals, so the bytes
	// on the wire are \u003cV1\u003e. That is the same JSON value, and the
	// model decodes it to <V1>. What must not happen is the *response* coming
	// back escaped — see TestPlaceholdersSurviveJSONEscaping.
	var gotInput map[string]string
	if err := json.Unmarshal(sent.Messages[1].Content[0].Input, &gotInput); err != nil {
		t.Fatalf("tool_use input is not an object: %s", sent.Messages[1].Content[0].Input)
	}
	if gotInput["host"] != "<V1>" {
		t.Errorf("tool_use input host = %q, want <V1>", gotInput["host"])
	}
	if sent.Messages[2].Role != "user" || sent.Messages[2].Content[0].Type != "tool_result" {
		t.Errorf("tool result turn = %+v, want a user turn with a tool_result block", sent.Messages[2])
	}
	if sent.Messages[2].Content[0].ToolUseID != "toolu_1" {
		t.Errorf("tool_use_id = %q, want toolu_1", sent.Messages[2].Content[0].ToolUseID)
	}
	if len(sent.Tools) != 1 || sent.Tools[0].Name != "lookup" {
		t.Errorf("tools = %+v, want the definition translated", sent.Tools)
	}

	// Response side: the tool_use block became an OpenAI tool call.
	msg := resp.Choices[0].Message
	if msg.Content != "checking" {
		t.Errorf("content = %q", msg.Content)
	}
	if len(msg.ToolCalls) != 1 || msg.ToolCalls[0].Function == nil {
		t.Fatalf("tool calls = %+v, want one", msg.ToolCalls)
	}
	if got := msg.ToolCalls[0].Function.Arguments; got != `{"host":"<V1>"}` {
		t.Errorf("arguments = %q, want the object re-serialised as a JSON string", got)
	}
	if resp.Choices[0].FinishReason != "tool_calls" {
		t.Errorf("finish_reason = %q, want tool_calls", resp.Choices[0].FinishReason)
	}
	if resp.Usage.PromptTokens != 5 || resp.Usage.CompletionTokens != 7 {
		t.Errorf("usage = %+v, want the token counts mapped", resp.Usage)
	}
}

// TestPlaceholdersSurviveJSONEscaping is a PhiGate-specific hazard. Every
// masked value is written <V1>, JSON encoders may escape < and >, and hydration
// searches the answer for the literal. An escaped placeholder would reach the
// caller unresolved — the tool invoked with the mask instead of the value.
func TestPlaceholdersSurviveJSONEscaping(t *testing.T) {
	const escaped = `{"id":"m","type":"message","role":"assistant","model":"claude-opus-5",
	  "content":[{"type":"tool_use","id":"t1","name":"restart",
	    "input":{"host":"<V1>","note":"a & b"}}],
	  "stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`

	c, _, _ := capture(t, ProviderAnthropic, escaped)
	resp, err := c.Chat(context.Background(), &types.ChatCompletionRequest{
		Model: "claude-opus-5", Messages: []types.Message{{Role: "user", Content: "go"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	args := resp.Choices[0].Message.ToolCalls[0].Function.Arguments
	if !strings.Contains(args, "<V1>") {
		t.Fatalf("arguments = %q; the placeholder is still escaped and hydration will miss it", args)
	}
	if strings.Contains(args, `\u003c`) || strings.Contains(args, `\u0026`) {
		t.Errorf("arguments still carry a JSON escape sequence: %q", args)
	}
	if !strings.Contains(args, "&") {
		t.Errorf("arguments = %q, want the ampersand unescaped too", args)
	}
}

// TestUnparseableToolArgumentsAreReported: dropping them would send a tool call
// with no arguments and let the model invent some.
func TestUnparseableToolArgumentsAreReported(t *testing.T) {
	c, _, _ := capture(t, ProviderAnthropic, okReply)

	_, err := c.Chat(context.Background(), &types.ChatCompletionRequest{
		Model: "claude-opus-5",
		Messages: []types.Message{
			{Role: "assistant", ToolCalls: []types.ToolCall{{
				ID: "t", Function: &types.FunctionCall{Name: "f", Arguments: "not json"},
			}}},
		},
	})
	if err == nil {
		t.Fatal("malformed tool arguments were accepted")
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("unhelpful error: %v", err)
	}
}

func TestAuthenticationUsesTheAnthropicHeader(t *testing.T) {
	var seen *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(r.Context())
		_, _ = w.Write([]byte(okReply))
	}))
	defer srv.Close()
	cl, err := NewAnthropicClient(ProviderConfig{
		Name: "cloud", Provider: ProviderAnthropic, BaseURL: srv.URL, APIKey: "sk-test",
	}, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Chat(context.Background(), &types.ChatCompletionRequest{
		Model: "claude-opus-5", Messages: []types.Message{{Role: "user", Content: "hi"}},
	}); err != nil {
		t.Fatal(err)
	}
	if seen.Header.Get("x-api-key") != "sk-test" {
		t.Errorf("x-api-key = %q, want the key", seen.Header.Get("x-api-key"))
	}
	if seen.Header.Get("Authorization") != "" {
		t.Error("Authorization: Bearer was sent; Anthropic uses x-api-key and 401s on the other")
	}
	if seen.Header.Get("anthropic-version") == "" {
		t.Error("anthropic-version header is missing")
	}
	if !strings.HasSuffix(seen.URL.Path, "/v1/messages") {
		t.Errorf("path = %q, want /v1/messages", seen.URL.Path)
	}
}

// TestStreamingParsesTextAndToolCalls covers the two SSE shapes that matter,
// including a tool call whose arguments arrive in fragments.
func TestStreamingParsesTextAndToolCalls(t *testing.T) {
	events := []string{
		`{"type":"message_start","message":{"id":"msg_3"}}`,
		`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"restart "}}`,
		`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"<V1>"}}`,
		`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_5","name":"restart_host"}}`,
		`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"host\":"}}`,
		`{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"<V1>\"}"}}`,
		`{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`,
		`{"type":"message_stop"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, e := range events {
			_, _ = w.Write([]byte("data: " + e + "\n\n"))
		}
	}))
	defer srv.Close()

	c, err := NewAnthropicClient(ProviderConfig{
		Name: "cloud", Provider: ProviderAnthropic, BaseURL: srv.URL, APIKey: "k",
	}, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}

	var text strings.Builder
	var args strings.Builder
	var name, id string
	var indices []int

	err = c.ChatStream(context.Background(), &types.ChatCompletionRequest{
		Model: "claude-opus-5", Messages: []types.Message{{Role: "user", Content: "go"}},
	}, func(d types.Delta) error {
		text.WriteString(d.Content)
		for _, tc := range d.ToolCalls {
			if tc.Index != nil {
				indices = append(indices, *tc.Index)
			}
			if tc.ID != "" {
				id = tc.ID
			}
			if tc.Function != nil {
				if tc.Function.Name != "" {
					name = tc.Function.Name
				}
				args.WriteString(tc.Function.Arguments)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if text.String() != "restart <V1>" {
		t.Errorf("text = %q", text.String())
	}
	if id != "toolu_5" || name != "restart_host" {
		t.Errorf("tool call identity lost: id=%q name=%q", id, name)
	}
	if args.String() != `{"host":"<V1>"}` {
		t.Errorf("arguments = %q, want the fragments concatenated", args.String())
	}
	for _, i := range indices {
		if i != 1 {
			t.Errorf("fragment carried index %d, want 1 — the gateway reassembles by index", i)
		}
	}
}

// TestBedrockAddressesTheModelInThePath and puts the version in the body,
// which is the whole of how it differs from the first-party API.
func TestBedrockAddressesTheModelInThePath(t *testing.T) {
	var seen *http.Request
	var body anthropicRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(r.Context())
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(okReply))
	}))
	defer srv.Close()

	c, err := NewAnthropicClient(ProviderConfig{
		Name: "cloud", Provider: ProviderBedrock, BaseURL: srv.URL,
		Region: "us-east-1", AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret",
	}, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Chat(context.Background(), &types.ChatCompletionRequest{
		Model:    "anthropic.claude-opus-5",
		Messages: []types.Message{{Role: "user", Content: "hi"}},
	}); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(seen.URL.Path, "/model/anthropic.claude-opus-5/invoke") {
		t.Errorf("path = %q, want the model in the path", seen.URL.Path)
	}
	if body.Model != "" {
		t.Errorf("body carries model=%q; Bedrock addresses it by URL", body.Model)
	}
	if body.AnthropicVersion != bedrockAnthropicVersion {
		t.Errorf("anthropic_version = %q, want %q in the body",
			body.AnthropicVersion, bedrockAnthropicVersion)
	}
	if !strings.HasPrefix(seen.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		t.Errorf("Authorization = %q, want a SigV4 signature", seen.Header.Get("Authorization"))
	}
	if seen.Header.Get("X-Amz-Date") == "" {
		t.Error("X-Amz-Date is missing; the signature cannot be verified without it")
	}
	if seen.Header.Get("anthropic-version") != "" {
		t.Error("the version header was sent to Bedrock, where it belongs in the body")
	}
}

// TestBedrockRefusesToPretendToStream. Its streaming route is a binary event
// framing, not SSE. Emitting one chunk and calling it streaming would be worse
// than saying so: the caller can fall back and get a correct answer.
func TestBedrockRefusesToPretendToStream(t *testing.T) {
	c, err := NewAnthropicClient(ProviderConfig{
		Name: "cloud", Provider: ProviderBedrock, BaseURL: "https://example.invalid",
		Region: "us-east-1", AccessKeyID: "a", SecretAccessKey: "b",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = c.ChatStream(context.Background(), &types.ChatCompletionRequest{
		Model: "anthropic.claude-opus-5", Messages: []types.Message{{Role: "user", Content: "hi"}},
	}, func(types.Delta) error { return nil })
	if err == nil {
		t.Fatal("Bedrock streaming reported success")
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("error should say plainly that it is unimplemented: %v", err)
	}
}

// TestBedrockNeedsCredentialsAtConstruction: discovering a signing problem on
// the first request would turn a configuration mistake into an upstream outage.
func TestBedrockNeedsCredentialsAtConstruction(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	if _, err := NewAnthropicClient(ProviderConfig{
		Name: "cloud", Provider: ProviderBedrock, BaseURL: "https://x", Region: "us-east-1",
	}); err == nil {
		t.Error("a Bedrock backend with no credentials was constructed")
	}
	if _, err := NewAnthropicClient(ProviderConfig{
		Name: "cloud", Provider: ProviderBedrock, BaseURL: "https://x",
		AccessKeyID: "a", SecretAccessKey: "b",
	}); err == nil {
		t.Error("a Bedrock backend with no region was constructed")
	}
}

func TestParseProviderAcceptsTheNewDialects(t *testing.T) {
	for in, want := range map[string]Provider{
		"anthropic": ProviderAnthropic, "claude": ProviderAnthropic,
		"bedrock": ProviderBedrock, "aws-bedrock": ProviderBedrock,
		"openai": ProviderOpenAI, "azure": ProviderAzure,
	} {
		got, err := ParseProvider(in)
		if err != nil {
			t.Errorf("ParseProvider(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseProvider(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseProvider("nonsense"); err == nil {
		t.Error("an unknown provider was accepted")
	}
}

func TestFinishReasonMapping(t *testing.T) {
	for in, want := range map[string]string{
		"end_turn": "stop", "stop_sequence": "stop", "max_tokens": "length",
		"tool_use": "tool_calls", "refusal": "content_filter", "": "",
	} {
		if got := finishReasonFromStop(in); got != want {
			t.Errorf("finishReasonFromStop(%q) = %q, want %q", in, got, want)
		}
	}
}
