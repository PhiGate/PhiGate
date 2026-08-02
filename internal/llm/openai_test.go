package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tenkan/phigate/internal/types"
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
		func(d string) error { got.WriteString(d); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "Hello <V1> world" {
		t.Fatalf("assembled deltas = %q", got.String())
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
