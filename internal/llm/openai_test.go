package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phigate/phigate/internal/types"
)

func TestOpenAIClientChat(t *testing.T) {
	var gotPath, gotAuth string
	var gotReq types.ChatCompletionRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotReq)

		_ = json.NewEncoder(w).Encode(types.ChatCompletionResponse{
			ID:    "resp-1",
			Model: "phi4-mini",
			Choices: []types.Choice{{
				Message: types.Message{Role: "assistant", Content: "check <V1>"},
			}},
		})
	}))
	defer srv.Close()

	c := NewOpenAIClient("local", srv.URL+"/v1", "sk-test", WithHTTPClient(srv.Client()))
	resp, err := c.Chat(context.Background(), &types.ChatCompletionRequest{
		Model:    "phi4-mini",
		Messages: []types.Message{{Role: "user", Content: "diag <V1>"}},
		Stream:   true, // must be forced off by the client
	})
	if err != nil {
		t.Fatal(err)
	}

	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %q, want /v1/chat/completions", gotPath)
	}
	if gotAuth != "Bearer sk-test" {
		t.Errorf("auth = %q, want Bearer sk-test", gotAuth)
	}
	if gotReq.Stream {
		t.Errorf("stream must be forced off upstream")
	}
	if len(resp.Choices) != 1 || resp.Choices[0].Message.Content != "check <V1>" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestOpenAIClientChatStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.ChatCompletionRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		if !req.Stream {
			t.Errorf("stream must be forced on for ChatStream")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for _, c := range []string{"Hello ", "<V1>", " world"} {
			chunk := types.ChatCompletionChunk{
				Choices: []types.ChunkChoice{{Delta: types.Delta{Content: c}}},
			}
			b, _ := json.Marshal(chunk)
			_, _ = w.Write([]byte("data: " + string(b) + "\n\n"))
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer srv.Close()

	c := NewOpenAIClient("local", srv.URL+"/v1", "", WithHTTPClient(srv.Client()))
	var got strings.Builder
	err := c.ChatStream(context.Background(),
		&types.ChatCompletionRequest{Model: "phi4-mini"},
		func(d types.Delta) error { got.WriteString(d.Content); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "Hello <V1> world" {
		t.Fatalf("assembled deltas = %q", got.String())
	}
}

// TestOpenAIClientForwardsToolCallChunks is the regression test for the drop.
// Every tool-call chunk has an empty Content, and the client skipped chunks on
// exactly that condition, so a streamed tool call never reached the gateway.
func TestOpenAIClientForwardsToolCallChunks(t *testing.T) {
	idx := 0
	frag := func(name, args string) types.ChatCompletionChunk {
		return types.ChatCompletionChunk{Choices: []types.ChunkChoice{{
			Delta: types.Delta{ToolCalls: []types.ToolCall{{
				Index:    &idx,
				Function: &types.FunctionCall{Name: name, Arguments: args},
			}}},
		}}}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, chunk := range []types.ChatCompletionChunk{
			frag("restart", ""), frag("", `{"host":`), frag("", `"<V1>"}`),
		} {
			b, _ := json.Marshal(chunk)
			_, _ = w.Write([]byte("data: " + string(b) + "\n\n"))
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer srv.Close()

	c := NewOpenAIClient("local", srv.URL+"/v1", "", WithHTTPClient(srv.Client()))
	var seen int
	var args strings.Builder
	err := c.ChatStream(context.Background(),
		&types.ChatCompletionRequest{Model: "phi4-mini"},
		func(d types.Delta) error {
			for _, tc := range d.ToolCalls {
				seen++
				if tc.Function != nil {
					args.WriteString(tc.Function.Arguments)
				}
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if seen != 3 {
		t.Fatalf("forwarded %d tool-call fragments, want 3 — content-less chunks are being dropped", seen)
	}
	if args.String() != `{"host":"<V1>"}` {
		t.Fatalf("argument fragments = %q", args.String())
	}
}

func TestOpenAIClientErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "model not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewOpenAIClient("cloud", srv.URL+"/v1", "", WithHTTPClient(srv.Client()))
	if _, err := c.Chat(context.Background(), &types.ChatCompletionRequest{Model: "x"}); err == nil {
		t.Fatal("expected error on non-2xx status")
	}
}
