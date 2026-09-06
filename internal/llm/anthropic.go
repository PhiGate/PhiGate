package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/phigate/phigate/internal/types"
)

// AnthropicClient talks to Anthropic's Messages API, first-party or through
// Amazon Bedrock.
//
// The two differ in three places and nowhere else: the URL, how the request is
// authenticated, and whether the model is named in the body or in the path.
// They share one client because the wire format they carry is the same, and a
// second copy would be a second place for the translation to drift.
type AnthropicClient struct {
	cfg  ProviderConfig
	http *http.Client
	brk  *breaker
	// signer is set for Bedrock, where every request is SigV4-signed.
	signer *sigV4Signer
}

var _ Client = (*AnthropicClient)(nil)

// NewAnthropicClient builds a client for the first-party API or for Bedrock,
// according to cfg.Provider.
func NewAnthropicClient(cfg ProviderConfig, opts ...Option) (*AnthropicClient, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 120 * time.Second
	}
	c := &AnthropicClient{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
		brk:  newBreaker(cfg.BreakerThreshold, cfg.BreakerCooldown),
	}
	if cfg.Provider == ProviderBedrock {
		s, err := newSigV4Signer(cfg)
		if err != nil {
			return nil, err
		}
		c.signer = s
	}
	// Options are applied through the OpenAI client's option type so tests can
	// inject one http.Client for every backend dialect.
	tmp := &OpenAIClient{http: c.http}
	for _, o := range opts {
		o(tmp)
	}
	c.http = tmp.http
	return c, nil
}

// Name implements Client.
func (c *AnthropicClient) Name() string { return c.cfg.Name }

// BreakerState reports the circuit breaker state for health endpoints.
func (c *AnthropicClient) BreakerState() string { return c.brk.State() }

// Chat implements Client.
func (c *AnthropicClient) Chat(ctx context.Context, req *types.ChatCompletionRequest) (*types.ChatCompletionResponse, error) {
	if !c.brk.allow() {
		return nil, fmt.Errorf("%s backend: %w", c.cfg.Name, ErrCircuitOpen)
	}
	var out *types.ChatCompletionResponse
	err := retry(ctx, c.cfg.Retries+1, func() error {
		resp, err := c.do(ctx, req, false)
		if err != nil {
			return err
		}
		out = resp
		return nil
	})
	if err != nil {
		c.brk.failure()
		return nil, err
	}
	c.brk.success()
	return out, nil
}

func (c *AnthropicClient) do(ctx context.Context, req *types.ChatCompletionRequest, stream bool) (*types.ChatCompletionResponse, error) {
	httpReq, err := c.buildRequest(ctx, req, stream)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%s backend request failed: %w", c.cfg.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", c.cfg.Name, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &StatusError{
			Backend: c.cfg.Name, Status: resp.StatusCode,
			Body: strings.TrimSpace(string(body)),
		}
	}
	var out anthropicResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", c.cfg.Name, err)
	}
	return fromAnthropic(&out, req.Model), nil
}

// buildRequest assembles and authenticates one call.
func (c *AnthropicClient) buildRequest(ctx context.Context, req *types.ChatCompletionRequest, stream bool) (*http.Request, error) {
	bedrock := c.cfg.Provider == ProviderBedrock

	payload, err := toAnthropic(req, stream, bedrock)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(req.Model, stream), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if stream {
		httpReq.Header.Set("Accept", "text/event-stream")
	}

	if bedrock {
		// SigV4 covers the body, so it has to be signed after the body is
		// final and before anything else touches the headers.
		if err := c.signer.sign(httpReq, body); err != nil {
			return nil, err
		}
		return httpReq, nil
	}
	httpReq.Header.Set("anthropic-version", anthropicVersion)
	if c.cfg.APIKey != "" {
		// Not "Authorization: Bearer". Anthropic's own header, and sending the
		// wrong one produces a 401 that reads like a bad key.
		httpReq.Header.Set("x-api-key", c.cfg.APIKey)
	}
	return httpReq, nil
}

// endpoint returns the URL for a model.
func (c *AnthropicClient) endpoint(model string, stream bool) string {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	if c.cfg.Provider != ProviderBedrock {
		return base + "/v1/messages"
	}
	// Bedrock addresses the model in the path and has separate routes for
	// buffered and streamed invocation.
	id := c.cfg.Deployment
	if id == "" {
		id = model
	}
	if stream {
		return fmt.Sprintf("%s/model/%s/invoke-with-response-stream", base, id)
	}
	return fmt.Sprintf("%s/model/%s/invoke", base, id)
}

// ChatStream implements Client.
//
// Streaming is not retried once bytes have been delivered: the caller has
// already seen part of an answer and replaying would produce a corrupted one.
func (c *AnthropicClient) ChatStream(ctx context.Context, req *types.ChatCompletionRequest, onDelta StreamFunc) error {
	if !c.brk.allow() {
		return fmt.Errorf("%s backend: %w", c.cfg.Name, ErrCircuitOpen)
	}
	err := c.doStream(ctx, req, onDelta)
	if err != nil {
		c.brk.failure()
		return err
	}
	c.brk.success()
	return nil
}

func (c *AnthropicClient) doStream(ctx context.Context, req *types.ChatCompletionRequest, onDelta StreamFunc) error {
	if c.cfg.Provider == ProviderBedrock {
		// Bedrock's streaming route is a binary event stream, not SSE, and
		// decoding it needs a framing implementation this package does not
		// have. Saying so is better than emitting one long chunk and calling
		// it streaming: the caller can fall back to a buffered request and
		// get a correct answer.
		return fmt.Errorf("%s backend: streaming is not implemented for Bedrock "+
			"(its event stream is a binary framing, not SSE); set stream=false", c.cfg.Name)
	}

	httpReq, err := c.buildRequest(ctx, req, true)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%s backend stream failed: %w", c.cfg.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return &StatusError{
			Backend: c.cfg.Name, Status: resp.StatusCode,
			Body: strings.TrimSpace(string(b)),
		}
	}
	return parseAnthropicSSE(resp.Body, onDelta)
}

// parseAnthropicSSE turns the Messages API event stream into the gateway's
// deltas.
//
// The two shapes that matter:
//
//   - text arrives as content_block_delta with delta.type "text_delta";
//   - a tool call opens with content_block_start carrying its id and name, then
//     its arguments arrive as input_json_delta fragments to be concatenated.
//
// The block index is carried through as the tool call's Index, which is what
// the gateway's accumulator reassembles fragments by — a model emitting two
// calls interleaves them, and arrival order is not enough.
func parseAnthropicSSE(r io.Reader, onDelta StreamFunc) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" {
			continue
		}

		var ev struct {
			Type         string `json:"type"`
			Index        int    `json:"index"`
			ContentBlock struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
			Delta struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
			Error struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			continue // tolerate keep-alives and comments
		}

		switch ev.Type {
		case "error":
			return fmt.Errorf("upstream stream error: %s: %s", ev.Error.Type, ev.Error.Message)

		case "content_block_start":
			if ev.ContentBlock.Type != "tool_use" {
				continue
			}
			idx := ev.Index
			if err := onDelta(types.Delta{ToolCalls: []types.ToolCall{{
				Index: &idx, ID: ev.ContentBlock.ID, Type: "function",
				Function: &types.FunctionCall{Name: ev.ContentBlock.Name},
			}}}); err != nil {
				return err
			}

		case "content_block_delta":
			switch ev.Delta.Type {
			case "text_delta":
				if ev.Delta.Text == "" {
					continue
				}
				if err := onDelta(types.Delta{Content: ev.Delta.Text}); err != nil {
					return err
				}
			case "input_json_delta":
				if ev.Delta.PartialJSON == "" {
					continue
				}
				idx := ev.Index
				if err := onDelta(types.Delta{ToolCalls: []types.ToolCall{{
					Index:    &idx,
					Function: &types.FunctionCall{Arguments: ev.Delta.PartialJSON},
				}}}); err != nil {
					return err
				}
			}
			// thinking_delta and any future delta type are skipped: the
			// gateway forwards answers, not reasoning.
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s stream: %w", "anthropic", err)
	}
	return nil
}

// Probe checks that the backend is reachable, for the readiness endpoint.
//
// There is no cheap listing endpoint to call on either platform, so this sends
// the smallest possible completion. A 4xx that is not an auth failure still
// proves the endpoint is there and answering, which is what readiness asks.
func (c *AnthropicClient) Probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	one := 1
	_, err := c.do(ctx, &types.ChatCompletionRequest{
		Model:     c.cfg.Model,
		MaxTokens: &one,
		Messages:  []types.Message{{Role: "user", Content: "ping"}},
	}, false)

	var se *StatusError
	if errors.As(err, &se) && se.Status != http.StatusUnauthorized && se.Status != http.StatusForbidden {
		return nil
	}
	return err
}
