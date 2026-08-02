// Package llm provides clients for the upstream model backends PhiGate routes
// to: a local SLM (Phi-4-mini via Ollama/llama.cpp) and a cloud LLM. Both speak
// the OpenAI Chat Completions protocol, so a single client implementation
// serves both — only the base URL, API key, and model name differ.
package llm

import (
	"context"

	"github.com/tenkan/phigate/internal/types"
)

// StreamFunc receives each content delta as it arrives from the backend.
// Returning an error aborts the stream.
type StreamFunc func(delta string) error

// Client is the minimal contract the gateway needs from any model backend.
type Client interface {
	// Chat sends a (already compressed/anonymized) request and returns the
	// completion. Implementations must not retry destructively.
	Chat(ctx context.Context, req *types.ChatCompletionRequest) (*types.ChatCompletionResponse, error)
	// ChatStream sends a request with streaming enabled and invokes onDelta for
	// each content delta until the stream completes.
	ChatStream(ctx context.Context, req *types.ChatCompletionRequest, onDelta StreamFunc) error
	// Name identifies the backend for logs/audit ("local" or "cloud").
	Name() string
}
