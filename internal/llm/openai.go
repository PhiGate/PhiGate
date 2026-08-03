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

	"github.com/phigate/phigate/internal/types"
)

// OpenAIClient talks to an OpenAI-compatible or Azure OpenAI
// /chat/completions endpoint. It serves both the local SLM and the cloud
// backend; only the provider config differs.
type OpenAIClient struct {
	cfg  ProviderConfig
	http *http.Client
	brk  *breaker
}

// Option configures an OpenAIClient.
type Option func(*OpenAIClient)

// WithHTTPClient injects a custom *http.Client (used in tests).
func WithHTTPClient(h *http.Client) Option {
	return func(c *OpenAIClient) { c.http = h }
}

// NewOpenAIClient builds a client for a plain OpenAI-compatible endpoint.
// name is a label ("local"/"cloud"); baseURL must include the version prefix
// (".../v1"); apiKey may be empty (Ollama ignores it).
func NewOpenAIClient(name, baseURL, apiKey string, opts ...Option) *OpenAIClient {
	return NewClient(ProviderConfig{
		Name: name, Provider: ProviderOpenAI, BaseURL: baseURL, APIKey: apiKey,
	}, opts...)
}

// NewClient builds a client from a full provider config.
func NewClient(cfg ProviderConfig, opts ...Option) *OpenAIClient {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 120 * time.Second
	}
	c := &OpenAIClient{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
		brk:  newBreaker(cfg.BreakerThreshold, cfg.BreakerCooldown),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Name implements Client.
func (c *OpenAIClient) Name() string { return c.cfg.Name }

// BreakerState reports the circuit breaker state for health endpoints.
func (c *OpenAIClient) BreakerState() string { return c.brk.State() }

// Chat implements Client by POSTing to the provider's chat completions
// endpoint, with bounded retries and circuit breaking.
func (c *OpenAIClient) Chat(ctx context.Context, req *types.ChatCompletionRequest) (*types.ChatCompletionResponse, error) {
	if !c.brk.allow() {
		return nil, fmt.Errorf("%s backend: %w", c.cfg.Name, ErrCircuitOpen)
	}

	var out *types.ChatCompletionResponse
	err := retry(ctx, c.cfg.Retries+1, func() error {
		resp, err := c.doChat(ctx, req)
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

func (c *OpenAIClient) doChat(ctx context.Context, req *types.ChatCompletionRequest) (*types.ChatCompletionResponse, error) {
	payload := *req
	payload.Stream = false
	// Azure addresses the model by deployment in the URL; sending a model
	// field too is harmless on OpenAI and ignored on Azure.
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.endpoint(req.Model), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	c.cfg.authorize(httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%s backend request failed: %w", c.cfg.Name, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", c.cfg.Name, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &StatusError{
			Backend: c.cfg.Name, Status: resp.StatusCode,
			Body: strings.TrimSpace(string(respBody)),
		}
	}

	var out types.ChatCompletionResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", c.cfg.Name, err)
	}
	return &out, nil
}

// ChatStream implements Client by POSTing with stream=true and parsing the
// Server-Sent Events stream, invoking onDelta for each content delta.
//
// Streaming is not retried once bytes have been delivered: the client has
// already seen part of an answer, and replaying would produce a corrupted one.
func (c *OpenAIClient) ChatStream(ctx context.Context, req *types.ChatCompletionRequest, onDelta StreamFunc) error {
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

func (c *OpenAIClient) doStream(ctx context.Context, req *types.ChatCompletionRequest, onDelta StreamFunc) error {
	payload := *req
	payload.Stream = true

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.endpoint(req.Model), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	c.cfg.authorize(httpReq)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%s backend stream failed: %w", c.cfg.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return &StatusError{
			Backend: c.cfg.Name, Status: resp.StatusCode,
			Body: strings.TrimSpace(string(b)),
		}
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
		return fmt.Errorf("read %s stream: %w", c.cfg.Name, err)
	}
	return nil
}

// Probe checks that the backend is reachable, for the readiness endpoint.
// It lists models where the provider supports it and falls back to a HEAD on
// the base URL otherwise.
func (c *OpenAIClient) Probe(ctx context.Context) error {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	url := base + "/models"
	if c.cfg.Provider == ProviderAzure {
		url = base + "/openai/models?api-version=" + c.apiVersion()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	c.cfg.authorize(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s backend unreachable: %w", c.cfg.Name, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 500 {
		return &StatusError{Backend: c.cfg.Name, Status: resp.StatusCode}
	}
	return nil
}

func (c *OpenAIClient) apiVersion() string {
	if c.cfg.APIVersion != "" {
		return c.cfg.APIVersion
	}
	return DefaultAzureAPIVersion
}
