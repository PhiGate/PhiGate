package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tenkan/phigate/internal/types"
)

// OpenAIClient talks to any OpenAI-compatible /chat/completions endpoint. It is
// used both for the local Ollama backend and for cloud providers; the only
// difference is BaseURL, APIKey, and the model requested.
type OpenAIClient struct {
	name    string
	baseURL string // e.g. http://localhost:11434/v1  or  https://api.openai.com/v1
	apiKey  string
	http    *http.Client
}

// Option configures an OpenAIClient.
type Option func(*OpenAIClient)

// WithHTTPClient injects a custom *http.Client (used in tests).
func WithHTTPClient(h *http.Client) Option {
	return func(c *OpenAIClient) { c.http = h }
}

// NewOpenAIClient builds a client. name is a label ("local"/"cloud"); baseURL
// must include the version prefix (".../v1"); apiKey may be empty (Ollama).
func NewOpenAIClient(name, baseURL, apiKey string, opts ...Option) *OpenAIClient {
	c := &OpenAIClient{
		name:    name,
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 120 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name implements Client.
func (c *OpenAIClient) Name() string { return c.name }

// Chat implements Client by POSTing to {baseURL}/chat/completions. Streaming is
// forced off in this step; the streaming egress sandbox arrives in Step 3.
func (c *OpenAIClient) Chat(ctx context.Context, req *types.ChatCompletionRequest) (*types.ChatCompletionResponse, error) {
	payload := *req
	payload.Stream = false

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%s backend request failed: %w", c.name, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", c.name, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s backend status %d: %s", c.name, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out types.ChatCompletionResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", c.name, err)
	}
	return &out, nil
}

// ChatStream implements Client by POSTing with stream=true and parsing the
// Server-Sent Events stream, invoking onDelta for each content delta. It stops
// on the "[DONE]" sentinel or end of body.
func (c *OpenAIClient) ChatStream(ctx context.Context, req *types.ChatCompletionRequest, onDelta StreamFunc) error {
	payload := *req
	payload.Stream = true

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%s backend stream failed: %w", c.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return fmt.Errorf("%s backend status %d: %s", c.name, resp.StatusCode, strings.TrimSpace(string(b)))
	}

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			break
		}
		var chunk types.ChatCompletionChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue // tolerate keep-alives / non-JSON comments
		}
		for _, ch := range chunk.Choices {
			if ch.Delta.Content == "" {
				continue
			}
			if err := onDelta(ch.Delta.Content); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read %s stream: %w", c.name, err)
	}
	return nil
}
