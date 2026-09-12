// SPDX-License-Identifier: BUSL-1.1

// Package tracing exports OpenTelemetry spans for the gateway.
//
// # What it is for
//
// A request that reaches PhiGate has already crossed the caller's own systems,
// and the question an SRE asks when it is slow is which hop owns the latency.
// Without a trace the gateway is a black box between the AIOps tool and the
// model, and the answer is guesswork. With one, the gateway hop appears in the
// enterprise's existing traces — it does not need a new tool, it needs PhiGate
// to be in the trace it already has.
//
// # What a span carries, and what it must never carry
//
// Metadata only: which backend answered, whether the cache hit, how many tokens
// were avoided, what the egress policy decided. All of it is already on the
// X-PhiGate-* response headers, which is why this package reads spans out of
// the response rather than reaching into the request path.
//
// Never the payload. Not the prompt, not the answer, not a masked placeholder,
// not a dictionary entry. A tracing backend is a third system with its own
// retention, its own access control and its own breach surface, and a gateway
// that anonymises a log on the way out and then writes it to a span has moved
// the leak rather than closed it. TestSpansCarryNoPayload asserts it.
//
// # Why this is in the enterprise edition
//
// The OpenTelemetry SDK, its OTLP exporter and gRPC bring a dependency tree
// that `make ce-purity` exists to keep out of the community edition. Nothing
// about the community edition changes; the instrumentation attaches through
// two seams it already exposes — an exported Routes() handler and
// llm.WithHTTPClient — so CE does not know this package exists.
package tracing

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config describes where spans go.
type Config struct {
	// Endpoint is the OTLP/HTTP collector, host:port. Empty disables tracing
	// entirely and Init returns a no-op shutdown.
	Endpoint string
	// Insecure sends over plain HTTP. Only for a collector on a network the
	// operator controls.
	Insecure bool
	// ServiceName identifies the gateway in the trace. Defaults to "phigate".
	ServiceName string
	// Version labels the deployment.
	Version string
	// SampleRatio is the head sampling fraction. Zero means sample everything,
	// which is the right default for a gateway handling AIOps traffic —
	// volumes are low and the traces that matter are the slow ones.
	SampleRatio float64
}

// Enabled reports whether tracing is configured.
func (c Config) Enabled() bool { return c.Endpoint != "" }

// Init installs a global tracer provider and returns its shutdown.
//
// Shutdown flushes pending spans and should be deferred: a gateway that exits
// without it loses the trace of whatever it was doing when it was asked to
// stop, which is exactly the trace someone wanted.
func Init(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	if !cfg.Enabled() {
		return noop, nil
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "phigate"
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(cfg.Endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return noop, fmt.Errorf("tracing: exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(cfg.ServiceName),
		semconv.ServiceVersion(cfg.Version),
	))
	if err != nil {
		return noop, fmt.Errorf("tracing: resource: %w", err)
	}

	sampler := sdktrace.AlwaysSample()
	if cfg.SampleRatio > 0 && cfg.SampleRatio < 1 {
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRatio)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	otel.SetTracerProvider(tp)
	// W3C trace context, so the gateway joins the caller's trace instead of
	// starting its own. Baggage travels with it for the same reason.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	return tp.Shutdown, nil
}

// Middleware wraps the gateway's handler.
//
// otelhttp does the span and the W3C context extraction; the wrapper around it
// copies PhiGate's own decisions onto the span afterwards. Reading them from
// the response headers rather than from inside the gateway is what keeps this
// package out of the community edition's way — those headers are a published
// interface, and an instrumentation that reached past them would have to be
// revised every time the request path moved.
func Middleware(service string, next http.Handler) http.Handler {
	annotated := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		span := trace.SpanFromContext(r.Context())
		if !span.IsRecording() {
			return
		}
		span.SetAttributes(attributesFrom(w.Header())...)
	})
	return otelhttp.NewHandler(annotated, service)
}

// headerAttrs maps a response header to the span attribute it becomes.
//
// The list is explicit rather than "every X-PhiGate-* header", so a header
// added later cannot start exporting something it should not. Nothing here
// carries payload: they are routing decisions, counts and verdicts.
var headerAttrs = []struct {
	header string
	key    string
}{
	{"X-PhiGate-Route", "phigate.route"},
	{"X-PhiGate-Backend", "phigate.backend"},
	{"X-PhiGate-Cache", "phigate.cache"},
	{"X-PhiGate-Policy", "phigate.policy"},
	{"X-PhiGate-Sensitivity", "phigate.sensitivity"},
	{"X-PhiGate-Blocked", "phigate.egress_blocked_rule"},
	{"X-PhiGate-Budget", "phigate.budget"},
}

// numericHeaderAttrs are the ones worth having as numbers, so a backend can
// aggregate rather than group by string.
var numericHeaderAttrs = []struct {
	header string
	key    string
}{
	{"X-PhiGate-Tokens-Saved", "phigate.tokens_saved"},
	{"X-PhiGate-Compression", "phigate.compression_percent"},
}

func attributesFrom(h http.Header) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(headerAttrs)+len(numericHeaderAttrs))
	for _, m := range headerAttrs {
		if v := h.Get(m.header); v != "" {
			out = append(out, attribute.String(m.key, v))
		}
	}
	for _, m := range numericHeaderAttrs {
		v := h.Get(m.header)
		if v == "" {
			continue
		}
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			out = append(out, attribute.Float64(m.key, n))
			continue
		}
		out = append(out, attribute.String(m.key, v))
	}
	return out
}

// InstrumentClient returns an HTTP client whose requests are spans.
//
// It is handed to llm.WithHTTPClient so the call to the model appears as a
// child of the gateway's own span. That is the split an SRE is actually after:
// a slow request is either PhiGate's pipeline or the model, and one number for
// the pair answers neither question.
func InstrumentClient(base *http.Client) *http.Client {
	if base == nil {
		base = &http.Client{Timeout: 120 * time.Second}
	}
	cp := *base
	rt := cp.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	cp.Transport = otelhttp.NewTransport(rt)
	return &cp
}
