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
// and re-emit it. PhiGate rewrites message content, tool-call arguments and the
// model name; it touches nothing else.
//
// # Why tool calls are modelled rather than passed through
//
// Verbatim passthrough fixed silent dropping and introduced a worse problem.
// An assistant turn that invokes a tool carries no `content` at all — its
// payload lives in `tool_calls[].function.arguments`, a JSON string. While that
// rode along in Extra it went upstream unmasked, and the egress classifier,
// which reads Content, never saw it. A gateway whose headline guarantee is that
// no personal datum leaves unmasked cannot have a field that bypasses masking
// entirely, so tool calls are modelled here and compressed like any other text.
//
// Unknown fields *inside* a tool call still ride along in its own Extra, so
// promoting these two levels out of the passthrough does not reintroduce the
// dropping problem.
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

// FunctionCall is the invoked function of a tool call.
//
// Arguments is a JSON *string* — the provider's own encoding, not a nested
// object — and it is the field that carries caller data, so it is what the
// compression pipeline masks and hydrates.
type FunctionCall struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`

	// Extra preserves any field the provider adds inside `function`.
	Extra map[string]json.RawMessage `json:"-"`
}

// UnmarshalJSON parses the known fields and captures the rest.
func (f *FunctionCall) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	f.Extra = map[string]json.RawMessage{}
	for k, v := range raw {
		switch k {
		case "name":
			_ = json.Unmarshal(v, &f.Name)
		case "arguments":
			_ = json.Unmarshal(v, &f.Arguments)
		default:
			f.Extra[k] = v
		}
	}
	return nil
}

// MarshalJSON re-emits the function with Extra restored.
func (f FunctionCall) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range f.Extra {
		out[k] = v
	}
	if f.Name != "" {
		n, _ := json.Marshal(f.Name)
		out["name"] = n
	}
	// Arguments is emitted whenever the call has a function at all: an empty
	// string is what a streaming delta legitimately carries before any argument
	// text has arrived, and dropping it changes the shape the client sees.
	a, err := json.Marshal(f.Arguments)
	if err != nil {
		return nil, err
	}
	out["arguments"] = a
	return json.Marshal(out)
}

// ToolCall is one function invocation requested by the model, or replayed by
// the client in a later turn.
//
// Index is present only on streaming deltas, where it identifies which call a
// fragment belongs to; a pointer distinguishes "index 0" from "absent".
type ToolCall struct {
	ID       string        `json:"id,omitempty"`
	Type     string        `json:"type,omitempty"`
	Index    *int          `json:"index,omitempty"`
	Function *FunctionCall `json:"function,omitempty"`

	// Extra preserves any field the provider adds alongside these.
	Extra map[string]json.RawMessage `json:"-"`
}

// UnmarshalJSON parses the known fields and captures the rest.
func (t *ToolCall) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	t.Extra = map[string]json.RawMessage{}
	for k, v := range raw {
		switch k {
		case "id":
			_ = json.Unmarshal(v, &t.ID)
		case "type":
			_ = json.Unmarshal(v, &t.Type)
		case "index":
			_ = json.Unmarshal(v, &t.Index)
		case "function":
			var fn FunctionCall
			if err := json.Unmarshal(v, &fn); err != nil {
				return fmt.Errorf("tool_calls[].function: %w", err)
			}
			t.Function = &fn
		default:
			t.Extra[k] = v
		}
	}
	return nil
}

// MarshalJSON re-emits the tool call with Extra restored.
func (t ToolCall) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range t.Extra {
		out[k] = v
	}
	for k, s := range map[string]string{"id": t.ID, "type": t.Type} {
		if s != "" {
			b, _ := json.Marshal(s)
			out[k] = b
		}
	}
	if t.Index != nil {
		b, _ := json.Marshal(*t.Index)
		out["index"] = b
	}
	if t.Function != nil {
		b, err := json.Marshal(t.Function)
		if err != nil {
			return nil, err
		}
		out["function"] = b
	}
	return json.Marshal(out)
}

// Message is a single chat turn.
//
// Content carries the flattened text, which is what the compression pipeline
// operates on. Raw preserves the original JSON so multi-part messages — text
// plus image_url, the shape used by vision requests — survive the round trip
// with their non-text parts untouched.
//
// ToolCalls is modelled for the reason given in the package doc: its arguments
// carry caller data and must not bypass masking.
type Message struct {
	Role      string          `json:"role"`
	Content   string          `json:"content"`
	Name      string          `json:"name,omitempty"`
	ToolCalls []ToolCall      `json:"tool_calls,omitempty"`
	Raw       json.RawMessage `json:"-"`
	Extra     map[string]json.RawMessage

	// contentNull records that the turn arrived with `"content": null`, which
	// is the shape an assistant tool-call turn uses. Re-emitting it as `""`
	// makes some providers reject the replayed conversation.
	contentNull bool
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
		case "tool_calls":
			if err := json.Unmarshal(v, &m.ToolCalls); err != nil {
				return fmt.Errorf("tool_calls: %w", err)
			}
		default:
			m.Extra[k] = v
		}
	}
	if len(m.Raw) == 0 {
		return nil
	}

	// A tool-call turn carries `"content": null`. Record that so the turn is
	// re-emitted in the shape it arrived in.
	if string(m.Raw) == "null" {
		m.contentNull = true
		m.Raw = nil
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
	if len(m.ToolCalls) > 0 {
		tc, err := json.Marshal(m.ToolCalls)
		if err != nil {
			return nil, err
		}
		out["tool_calls"] = tc
	}

	if len(m.Raw) == 0 {
		if m.contentNull && m.Content == "" {
			out["content"] = json.RawMessage("null")
			return json.Marshal(out)
		}
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

// Texts returns every caller-supplied string in the message: its content, then
// the arguments of each tool call.
//
// Anything this method omits is text that escapes token accounting, the ingress
// scan and the cache key, so a field that carries caller data belongs here.
func (m Message) Texts() []string {
	out := make([]string, 0, 1+len(m.ToolCalls))
	out = append(out, m.Content)
	for _, tc := range m.ToolCalls {
		if tc.Function != nil {
			out = append(out, tc.Function.Arguments)
		}
	}
	return out
}

// Contents returns the text of every message, for compression and hashing.
//
// Tool-call arguments are included: they are part of what is sent upstream, so
// leaving them out understated the baseline and let two requests differing only
// in their arguments collide on one cache key.
func (r ChatCompletionRequest) Contents() []string {
	out := make([]string, 0, len(r.Messages))
	for _, m := range r.Messages {
		out = append(out, m.Texts()...)
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
//
// ToolCalls is modelled for the same reason as on Message, and for a second
// one: the streaming client dropped every chunk whose Content was empty, which
// is every tool-call chunk, so a streamed tool call reached the caller as
// nothing at all.
type Delta struct {
	Role      string     `json:"role,omitempty"`
	Content   string     `json:"content,omitempty"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
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

// EmbeddingsRequest is the inbound POST /v1/embeddings body.
//
// Input arrives as a string, an array of strings, or an array of token ids.
// Only the text forms carry anything to mask; a pre-tokenised request is passed
// through, and Texts reports empty so the caller can tell the difference.
type EmbeddingsRequest struct {
	Model string
	Raw   json.RawMessage // the original "input", for passthrough
	Texts []string        // the text form, when it was one

	Extra map[string]json.RawMessage
}

// UnmarshalJSON parses the known fields and captures the rest.
func (r *EmbeddingsRequest) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	r.Extra = map[string]json.RawMessage{}
	for k, v := range raw {
		switch k {
		case "model":
			_ = json.Unmarshal(v, &r.Model)
		case "input":
			r.Raw = append(json.RawMessage(nil), v...)
		default:
			r.Extra[k] = v
		}
	}
	if len(r.Raw) == 0 {
		return fmt.Errorf("input is required")
	}
	var one string
	if err := json.Unmarshal(r.Raw, &one); err == nil {
		r.Texts = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(r.Raw, &many); err == nil {
		r.Texts = many
		return nil
	}
	// Token-id input: nothing to mask, and nothing this gateway can usefully
	// say about it. It rides through untouched.
	return nil
}

// MarshalJSON re-emits the request, writing Texts back into the shape input
// arrived in.
func (r EmbeddingsRequest) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range r.Extra {
		out[k] = v
	}
	m, _ := json.Marshal(r.Model)
	out["model"] = m

	if len(r.Texts) == 0 {
		out["input"] = r.Raw
		return json.Marshal(out)
	}
	// A single string in must be a single string out: some providers return a
	// differently shaped response for an array, and a proxy that silently
	// changed the request shape would change the answer's.
	var in []byte
	var err error
	if isJSONString(r.Raw) && len(r.Texts) == 1 {
		in, err = json.Marshal(r.Texts[0])
	} else {
		in, err = json.Marshal(r.Texts)
	}
	if err != nil {
		return nil, err
	}
	out["input"] = in
	return json.Marshal(out)
}

func isJSONString(raw json.RawMessage) bool {
	var s string
	return json.Unmarshal(raw, &s) == nil
}

// Embedding is one vector in an embeddings response.
type Embedding struct {
	Object    string    `json:"object"`
	Index     int       `json:"index"`
	Embedding []float64 `json:"embedding"`
}

// EmbeddingsResponse is the outbound POST /v1/embeddings body.
type EmbeddingsResponse struct {
	Object string      `json:"object"`
	Data   []Embedding `json:"data"`
	Model  string      `json:"model"`
	Usage  Usage       `json:"usage"`
	// PhiGate reports what it did, as it does on a completion.
	PhiGate *Meta `json:"phigate,omitempty"`
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
