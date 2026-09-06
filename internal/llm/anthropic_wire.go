package llm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/phigate/phigate/internal/types"
)

// This file translates between the OpenAI Chat Completions shape the gateway
// speaks internally and Anthropic's Messages API.
//
// # Why translate rather than adopt an SDK
//
// The community edition's go.mod lists one third-party dependency, and
// ee/README.md says why that matters: it is the property a customer's security
// review actually checks. An SDK for one provider — and a second for Bedrock's
// request signing — would end that, and a backend dialect is not worth it. The
// existing OpenAI and Azure clients are already raw net/http; this is the same
// decision applied to a third dialect.
//
// # The four things that actually differ
//
//   - **System prompts are a top-level field**, not a message with role
//     "system". PhiGate always prepends a system preamble explaining its
//     placeholders, so getting this wrong would send that preamble as a user
//     turn and the model would answer it.
//   - **max_tokens is required.** OpenAI treats it as optional; Anthropic
//     rejects a request without it. A gateway that forwards the client's
//     omission produces a 400 the client cannot explain.
//   - **Content is a list of typed blocks.** Text and tool calls are blocks in
//     one assistant turn, where OpenAI puts them in two different fields.
//   - **Tool results are a user turn**, not a "tool" role.

// anthropicVersion is the API version header value. It is a date, not a
// semantic version, and pinning it is the point: the wire format below is
// written against this one.
const anthropicVersion = "2023-06-01"

// bedrockAnthropicVersion goes in the *body* on Bedrock, where the model is
// addressed by the URL and there is no version header.
const bedrockAnthropicVersion = "bedrock-2023-05-31"

// defaultMaxTokens is used when the client did not ask for a limit.
//
// It is generous on purpose. max_tokens is a ceiling, not a target — nothing is
// billed for tokens that are not generated — while a ceiling set too low
// truncates an answer mid-sentence and buys a retry that costs the whole
// prompt again.
const (
	defaultMaxTokens          = 16000
	defaultMaxTokensStreaming = 64000
)

// anthropicRequest is the Messages API request body.
type anthropicRequest struct {
	Model       string             `json:"model,omitempty"`
	MaxTokens   int                `json:"max_tokens"`
	System      string             `json:"system,omitempty"`
	Messages    []anthropicMessage `json:"messages"`
	Temperature *float64           `json:"temperature,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
	Tools       []anthropicTool    `json:"tools,omitempty"`

	// AnthropicVersion is set on Bedrock only, where it rides in the body.
	AnthropicVersion string `json:"anthropic_version,omitempty"`
}

type anthropicMessage struct {
	Role    string           `json:"role"`
	Content []anthropicBlock `json:"content"`
}

// anthropicBlock is one content block. The fields are a union discriminated by
// Type; only those belonging to the type are emitted.
type anthropicBlock struct {
	Type string `json:"type"`

	// type=="text"
	Text string `json:"text,omitempty"`

	// type=="tool_use"
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`

	// type=="tool_result"
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   string `json:"content,omitempty"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// anthropicResponse is the Messages API response body.
type anthropicResponse struct {
	ID         string           `json:"id"`
	Type       string           `json:"type"`
	Role       string           `json:"role"`
	Model      string           `json:"model"`
	Content    []anthropicBlock `json:"content"`
	StopReason string           `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// toAnthropic converts the gateway's request into a Messages API request.
//
// bedrock selects the two shape differences that platform imposes: the model is
// addressed by URL rather than by field, and the API version rides in the body.
func toAnthropic(req *types.ChatCompletionRequest, stream, bedrock bool) (*anthropicRequest, error) {
	out := &anthropicRequest{
		Temperature: req.Temperature,
		Stream:      stream,
	}
	if bedrock {
		out.AnthropicVersion = bedrockAnthropicVersion
	} else {
		out.Model = req.Model
	}

	switch {
	case req.MaxTokens != nil && *req.MaxTokens > 0:
		out.MaxTokens = *req.MaxTokens
	case stream:
		out.MaxTokens = defaultMaxTokensStreaming
	default:
		out.MaxTokens = defaultMaxTokens
	}

	var system []string
	for _, m := range req.Messages {
		switch m.Role {
		case "system":
			// Anthropic takes the system prompt as a top-level field. Left as
			// a message it would become a user turn, and PhiGate's preamble —
			// which explains that <V1> is a placeholder — would be answered
			// rather than obeyed.
			if m.Content != "" {
				system = append(system, m.Content)
			}

		case "tool":
			// A tool result is a *user* turn carrying a tool_result block.
			id, _ := extraString(m.Extra, "tool_call_id")
			out.Messages = append(out.Messages, anthropicMessage{
				Role: "user",
				Content: []anthropicBlock{{
					Type: "tool_result", ToolUseID: id, Content: m.Content,
				}},
			})

		case "assistant":
			blocks := make([]anthropicBlock, 0, 1+len(m.ToolCalls))
			if m.Content != "" {
				blocks = append(blocks, anthropicBlock{Type: "text", Text: m.Content})
			}
			for _, tc := range m.ToolCalls {
				if tc.Function == nil {
					continue
				}
				// Arguments are a JSON *string* on the wire in OpenAI's shape
				// and a JSON *object* in Anthropic's. An unparseable argument
				// string is the client's, not ours, so it is reported rather
				// than silently dropped — dropping it would send a tool call
				// with no arguments and the model would invent some.
				input := json.RawMessage(tc.Function.Arguments)
				if len(input) == 0 {
					input = json.RawMessage("{}")
				}
				if !json.Valid(input) {
					return nil, fmt.Errorf("tool call %q: arguments are not valid JSON", tc.Function.Name)
				}
				blocks = append(blocks, anthropicBlock{
					Type: "tool_use", ID: tc.ID, Name: tc.Function.Name, Input: input,
				})
			}
			if len(blocks) == 0 {
				continue // an empty assistant turn carries nothing
			}
			out.Messages = append(out.Messages, anthropicMessage{Role: "assistant", Content: blocks})

		default: // "user" and anything else
			out.Messages = append(out.Messages, anthropicMessage{
				Role:    "user",
				Content: []anthropicBlock{{Type: "text", Text: m.Content}},
			})
		}
	}
	out.System = strings.Join(system, "\n\n")

	tools, err := toAnthropicTools(req.Extra["tools"])
	if err != nil {
		return nil, err
	}
	out.Tools = tools

	if len(out.Messages) == 0 {
		return nil, fmt.Errorf("no messages to send: Anthropic requires at least one")
	}
	return out, nil
}

// toAnthropicTools converts an OpenAI tools block.
//
// A block that does not parse is dropped rather than failing the request: this
// gateway inspects `tools`, it does not own it, and refusing a request over a
// field shape we merely read would break a client for no gain. The same
// judgement the tools scanner makes.
func toAnthropicTools(raw json.RawMessage) ([]anthropicTool, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var defs []struct {
		Type     string `json:"type"`
		Function struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Parameters  json.RawMessage `json:"parameters"`
		} `json:"function"`
	}
	if err := json.Unmarshal(raw, &defs); err != nil {
		return nil, nil
	}
	out := make([]anthropicTool, 0, len(defs))
	for _, d := range defs {
		if d.Function.Name == "" {
			continue
		}
		schema := d.Function.Parameters
		if len(schema) == 0 {
			// input_schema is required; an object with no properties is the
			// honest encoding of "this tool takes nothing".
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		out = append(out, anthropicTool{
			Name: d.Function.Name, Description: d.Function.Description, InputSchema: schema,
		})
	}
	return out, nil
}

// fromAnthropic converts a Messages API response into the gateway's shape.
func fromAnthropic(in *anthropicResponse, requestedModel string) *types.ChatCompletionResponse {
	var text strings.Builder
	var calls []types.ToolCall

	for _, b := range in.Content {
		switch b.Type {
		case "text":
			text.WriteString(b.Text)
		case "tool_use":
			// Re-encoded without HTML escaping, deliberately.
			//
			// Go escapes <, > and & by default, and every value the gateway
			// masks is written <V1>. Hydration searches the answer for that
			// literal, so an argument string carrying \u003cV1\u003e would be
			// handed back to the caller with the placeholder unresolved — the
			// tool would be invoked with the mask instead of the value.
			// Normalising here makes it independent of how the upstream server
			// chose to escape its own response.
			args := normalizeJSON(b.Input)
			calls = append(calls, types.ToolCall{
				ID: b.ID, Type: "function",
				Function: &types.FunctionCall{Name: b.Name, Arguments: args},
			})
		}
		// Thinking blocks are deliberately not surfaced. They are the model's
		// reasoning, the gateway's egress guard is written against answers, and
		// forwarding them would put text through the hydration path that the
		// operator never asked to see.
	}

	model := in.Model
	if model == "" {
		model = requestedModel
	}
	return &types.ChatCompletionResponse{
		ID:     in.ID,
		Object: "chat.completion",
		Model:  model,
		Choices: []types.Choice{{
			Index: 0,
			Message: types.Message{
				Role: "assistant", Content: text.String(), ToolCalls: calls,
			},
			FinishReason: finishReasonFromStop(in.StopReason),
		}},
		Usage: types.Usage{
			PromptTokens:     in.Usage.InputTokens,
			CompletionTokens: in.Usage.OutputTokens,
			TotalTokens:      in.Usage.InputTokens + in.Usage.OutputTokens,
		},
	}
}

// normalizeJSON re-encodes a JSON value with HTML escaping off.
//
// Input that does not parse is returned unchanged: it came from the upstream
// server, and mangling it further would only make the failure harder to read.
func normalizeJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "{}"
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return string(raw)
	}
	return strings.TrimRight(b.String(), "\n")
}

// finishReasonFromStop maps Anthropic's stop_reason onto OpenAI's.
//
// "refusal" has no OpenAI counterpart and is reported as a content filter,
// which is the nearest thing a client SDK already handles — and is what it
// means to the caller: the answer was withheld by a policy, not truncated.
func finishReasonFromStop(s string) string {
	switch s {
	case "end_turn", "stop_sequence":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	case "refusal":
		return "content_filter"
	case "":
		return ""
	}
	return s
}

// extraString reads a string field out of a message's passthrough map.
func extraString(extra map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := extra[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}
