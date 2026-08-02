// Package types holds the wire structs PhiGate exchanges with clients and
// upstream LLM providers. They mirror the OpenAI Chat Completions schema so
// enterprise clients can repoint their existing base_url at PhiGate with zero
// code changes ("zero-friction integration").
package types

// Message is a single chat turn. Content is kept as a plain string in this
// first cut; multi-part/content-array messages can be added later behind the
// same field via a custom UnmarshalJSON.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	Name    string `json:"name,omitempty"`
}

// ChatCompletionRequest is the inbound POST /v1/chat/completions body.
type ChatCompletionRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature *float64  `json:"temperature,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
	MaxTokens   *int      `json:"max_tokens,omitempty"`
}

// Choice is one completion alternative.
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// Usage reports token accounting. In PhiGate this is where we will surface the
// "tokens saved" FinOps metric in later steps.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// ChatCompletionResponse is the outbound body returned to the client.
type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

// Delta is the incremental content carried by a streaming chunk.
type Delta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

// ChunkChoice is one choice within a streaming chunk.
type ChunkChoice struct {
	Index        int     `json:"index"`
	Delta        Delta   `json:"delta"`
	FinishReason *string `json:"finish_reason"`
}

// ChatCompletionChunk is a single Server-Sent Event in a streamed completion
// (OpenAI "chat.completion.chunk" object).
type ChatCompletionChunk struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Created int64         `json:"created"`
	Model   string        `json:"model"`
	Choices []ChunkChoice `json:"choices"`
}
