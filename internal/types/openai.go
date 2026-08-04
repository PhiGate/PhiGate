// Package types holds the wire structs PhiGate exchanges with clients and
// upstream LLM providers. They mirror the OpenAI Chat Completions schema so
// enterprise clients can repoint their existing base_url at PhiGate with zero
// code changes.
//
// # Why passthrough matters
//
// "Zero code changes" was not true of the first implementation. It parsed the
// request into a fixed struct and rebuilt the upstream call from five fields,
// so a client using tools, response_format, top_p, stop, seed or n had those
// silently dropped. The request still succeeded and still returned an answer —
// just not the answer the client asked for. Silent degradation is the worst
// failure mode a proxy can have, because nothing surfaces it.
//
// The structs here therefore keep every unrecognised field verbatim in Extra
// and re-emit it. PhiGate rewrites message content and the model name; it
// touches nothing else.
package types

import (
	"encoding/json"
	"fmt"
)

// knownRequestFields are the fields PhiGate models explicitly. Everything else
// is preserved through Extra.
var knownRequestFields = map[string]bool{
	"model": true, "messages": true, "temperature": true,
	"stream": true, "max_tokens": true,
}

// Message is a single chat turn.
//
// Content carries the flattened text, which is what the compression pipeline
// operates on. Raw preserves the original JSON so multi-part messages — text
// plus image_url, the shape used by vision requests — survive the round trip
// with their non-text parts untouched.
type Message struct {
	Role    string          `json:"role"`
	Content string          `json:"content"`
	Name    string          `json:"name,omitempty"`
	Raw     json.RawMessage `json:"-"`
	Extra   map[string]json.RawMessage
}

// UnmarshalJSON accepts both string content and the content-array form.
func (m *Message) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	m.Extra = map[string]json.RawMessage{}
	for k, v := range raw {
		switch k {
		case "role":
			_ = json.Unmarshal(v, &m.Role)
		case "name":
			_ = json.Unmarshal(v, &m.Name)
		case "content":
			m.Raw = append(json.RawMessage(nil), v...)
		default:
			m.Extra[k] = v
		}
	}
	if len(m.Raw) == 0 {
		return nil
	}

	// String content: the common case.
	var s string
	if err := json.Unmarshal(m.Raw, &s); err == nil {
		m.Content = s
		m.Raw = nil
		return nil
	}
	// Array content: concatenate the text parts for compression, keep the
	// original so non-text parts pass through.
	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(m.Raw, &parts); err != nil {
		return fmt.Errorf("message content is neither a string nor an array: %w", err)
	}
	text := ""
	for _, p := range parts {
		if t, ok := p["text"]; ok {
			var v string
			if json.Unmarshal(t, &v) == nil {
				if text != "" {
					text += "\n"
				}
				text += v
			}
		}
	}
	m.Content = text
	return nil
}

// MarshalJSON re-emits the message, writing Content back into whichever shape
// it arrived in.
func (m Message) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range m.Extra {
		out[k] = v
	}
	role, _ := json.Marshal(m.Role)
	out["role"] = role
	if m.Name != "" {
		n, _ := json.Marshal(m.Name)
		out["name"] = n
	}

	if len(m.Raw) == 0 {
		c, err := json.Marshal(m.Content)
		if err != nil {
			return nil, err
		}
		out["content"] = c
		return json.Marshal(out)
	}

	// Array content: replace the first text part with the (compressed) content
	// and drop any further text parts, since Content is their concatenation.
	var parts []map[string]json.RawMessage
	if err := json.Unmarshal(m.Raw, &parts); err != nil {
		return nil, err
	}
	rebuilt := make([]map[string]json.RawMessage, 0, len(parts))
	wroteText := false
	for _, p := range parts {
		if _, isText := p["text"]; isText {
			if wroteText {
				continue
			}
			c, err := json.Marshal(m.Content)
			if err != nil {
				return nil, err
			}
			p["text"] = c
			wroteText = true
		}
		rebuilt = append(rebuilt, p)
	}
	arr, err := json.Marshal(rebuilt)
	if err != nil {
		return nil, err
	}
	out["content"] = arr
	return json.Marshal(out)
}

// ChatCompletionRequest is the inbound POST /v1/chat/completions body.
type ChatCompletionRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature *float64  `json:"temperature,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
	MaxTokens   *int      `json:"max_tokens,omitempty"`

	// Extra holds every field PhiGate does not model — tools, tool_choice,
	// response_format, top_p, stop, seed, n, logprobs, user, and whatever the
	// provider adds next. It is re-emitted verbatim.
	Extra map[string]json.RawMessage `json:"-"`
}

// UnmarshalJSON parses the known fields and captures the rest.
func (r *ChatCompletionRequest) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	r.Extra = map[string]json.RawMessage{}
	for k, v := range raw {
		if !knownRequestFields[k] {
			r.Extra[k] = v
			continue
		}
		var err error
		switch k {
		case "model":
			err = json.Unmarshal(v, &r.Model)
		case "messages":
			err = json.Unmarshal(v, &r.Messages)
		case "temperature":
			err = json.Unmarshal(v, &r.Temperature)
		case "stream":
			err = json.Unmarshal(v, &r.Stream)
		case "max_tokens":
			err = json.Unmarshal(v, &r.MaxTokens)
		}
		if err != nil {
			return fmt.Errorf("field %q: %w", k, err)
		}
	}
	return nil
}

// MarshalJSON re-emits the request with Extra restored.
func (r ChatCompletionRequest) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range r.Extra {
		out[k] = v
	}
	for k, v := range map[string]any{
		"model": r.Model, "messages": r.Messages, "stream": r.Stream,
	} {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		out[k] = b
	}
	if r.Temperature != nil {
		b, _ := json.Marshal(r.Temperature)
		out["temperature"] = b
	}
	if r.MaxTokens != nil {
		b, _ := json.Marshal(r.MaxTokens)
		out["max_tokens"] = b
	}
	return json.Marshal(out)
}

// Contents returns the text of every message, for compression and hashing.
func (r ChatCompletionRequest) Contents() []string {
	out := make([]string, 0, len(r.Messages))
	for _, m := range r.Messages {
		out = append(out, m.Content)
	}
	return out
}

// Choice is one completion alternative.
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// Usage reports token accounting as the provider measured it.
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
	// PhiGate reports its own accounting alongside the provider's, so a client
	// can see the saving without scraping headers.
	PhiGate *Meta `json:"phigate,omitempty"`
}

// Meta is PhiGate's per-response report.
type Meta struct {
	Route          string   `json:"route"`
	Backend        string   `json:"backend"`
	Reason         string   `json:"reason"`
	Policy         string   `json:"policy"`
	MaxSensitivity string   `json:"max_sensitivity"`
	CacheHit       bool     `json:"cache_hit"`
	BaselineTokens int      `json:"baseline_tokens"`
	PromptTokens   int      `json:"prompt_tokens"`
	TokensSaved    int      `json:"tokens_saved"`
	SavedPercent   int      `json:"saved_percent"`
	RedactionRules []string `json:"redaction_rules,omitempty"`
	EgressRule     string   `json:"egress_rule,omitempty"`
	EgressSeverity string   `json:"egress_severity,omitempty"`
	IngressRules   []string `json:"ingress_rules,omitempty"`
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

// ChatCompletionChunk is a single Server-Sent Event in a streamed completion.
type ChatCompletionChunk struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Created int64         `json:"created"`
	Model   string        `json:"model"`
	Choices []ChunkChoice `json:"choices"`
}

// Model is one entry in a /v1/models listing.
type Model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

// ModelList is the /v1/models response.
type ModelList struct {
	Object string  `json:"object"`
	Data   []Model `json:"data"`
}

// ErrorResponse is the OpenAI-shaped error envelope. Returning this shape means
// existing client SDKs surface PhiGate's errors as ordinary API errors instead
// of failing to parse them.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody is the error detail.
type ErrorBody struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
}

// NewError builds an OpenAI-shaped error body.
func NewError(msg, typ, code string) ErrorResponse {
	return ErrorResponse{Error: ErrorBody{Message: msg, Type: typ, Code: code}}
}
