// SPDX-License-Identifier: BUSL-1.1

package tracing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// recorder installs an in-memory tracer provider and returns the spans it
// collected.
func recorder(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})
	return exp
}

// gatewayLike answers the way PhiGate does: the decisions on headers, the
// payload in the body.
func gatewayLike() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("X-PhiGate-Route", "local")
		h.Set("X-PhiGate-Backend", "local")
		h.Set("X-PhiGate-Cache", "hit")
		h.Set("X-PhiGate-Policy", "allow")
		h.Set("X-PhiGate-Sensitivity", "internal")
		h.Set("X-PhiGate-Tokens-Saved", "1184")
		h.Set("X-PhiGate-Compression", "64.2")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"check 10.24.8.19 and api.internal.corp"}}]}`))
	})
}

func serve(t *testing.T, h http.Handler, mutate func(*http.Request)) {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"messages":[{"role":"user","content":"password=hunter2 on 10.24.8.19"}]}`))
	if mutate != nil {
		mutate(req)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
}

func TestDisabledTracingIsANoOp(t *testing.T) {
	shutdown, err := Init(context.Background(), Config{})
	if err != nil {
		t.Fatalf("disabled tracing returned an error: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// TestSpansCarryTheGatewaysDecisions. Without these a span says only that an
// HTTP request happened, which the caller's own tracing already knew.
func TestSpansCarryTheGatewaysDecisions(t *testing.T) {
	exp := recorder(t)
	serve(t, Middleware("phigate", gatewayLike()), nil)

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("no span was recorded")
	}
	got := map[string]string{}
	for _, a := range spans[0].Attributes {
		got[string(a.Key)] = a.Value.String()
	}
	for key, want := range map[string]string{
		"phigate.route":       "local",
		"phigate.backend":     "local",
		"phigate.cache":       "hit",
		"phigate.policy":      "allow",
		"phigate.sensitivity": "internal",
	} {
		if got[key] != want {
			t.Errorf("attribute %s = %q, want %q", key, got[key], want)
		}
	}
	if got["phigate.tokens_saved"] != "1184" {
		t.Errorf("tokens_saved = %q, want the number 1184", got["phigate.tokens_saved"])
	}
}

// TestSpansCarryNoPayload is the one that matters.
//
// A tracing backend is a third system with its own retention, access control
// and breach surface. A gateway that anonymises a log on the way out and then
// writes the same text to a span has moved the leak, not closed it — and it
// would be leaking to a system chosen by the observability team rather than
// the one the security review looked at.
func TestSpansCarryNoPayload(t *testing.T) {
	exp := recorder(t)
	serve(t, Middleware("phigate", gatewayLike()), nil)

	var blob strings.Builder
	for _, s := range exp.GetSpans() {
		blob.WriteString(s.Name)
		for _, a := range s.Attributes {
			blob.WriteString(" " + string(a.Key) + "=" + a.Value.String())
		}
		for _, e := range s.Events {
			blob.WriteString(" " + e.Name)
			for _, a := range e.Attributes {
				blob.WriteString(" " + string(a.Key) + "=" + a.Value.String())
			}
		}
	}
	for _, forbidden := range []string{
		"hunter2", "password=", // the request body
		"10.24.8.19", "api.internal.corp", // the answer body
		"<V1>", // even a placeholder is payload shape
	} {
		if strings.Contains(blob.String(), forbidden) {
			t.Errorf("a span carried payload: %q found in\n%s", forbidden, blob.String())
		}
	}
}

// TestTheGatewayJoinsTheCallersTrace. The ask is not a new tracing tool, it is
// for PhiGate to appear in the trace the enterprise already has.
func TestTheGatewayJoinsTheCallersTrace(t *testing.T) {
	exp := recorder(t)
	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	serve(t, Middleware("phigate", gatewayLike()), func(r *http.Request) {
		r.Header.Set("traceparent", "00-"+traceID+"-00f067aa0ba902b7-01")
	})

	spans := exp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("no span was recorded")
	}
	if got := spans[0].SpanContext.TraceID().String(); got != traceID {
		t.Errorf("the gateway started its own trace %s instead of joining %s", got, traceID)
	}
	if !spans[0].Parent.IsValid() {
		t.Error("the span has no parent; the caller's hop was dropped")
	}
}

// TestUpstreamCallsAreTheirOwnSpan. A slow request is either the pipeline or
// the model, and one number for the pair answers neither question.
func TestUpstreamCallsAreTheirOwnSpan(t *testing.T) {
	exp := recorder(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	client := InstrumentClient(nil)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	if len(exp.GetSpans()) == 0 {
		t.Fatal("the upstream call produced no span")
	}
}

func TestInstrumentClientKeepsTheCallersSettings(t *testing.T) {
	base := &http.Client{Timeout: 42}
	got := InstrumentClient(base)
	if got.Timeout != 42 {
		t.Errorf("timeout = %v, want 42", got.Timeout)
	}
	if got == base {
		t.Error("the caller's client was mutated rather than copied")
	}
}
