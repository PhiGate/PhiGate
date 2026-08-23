// Package audit emits PhiGate's compliance record.
//
// `log.Printf` to stderr does not survive an ISMS / JIS Q 27001 review. An
// auditor asks: who sent what class of data, where did it go, which controls
// fired, and can you prove the record was not edited afterwards. This package
// answers those questions in structured JSON.
//
// # The rule that shapes everything here
//
// An audit log is a permanent, widely-replicated, long-retention artifact. It is
// exactly the wrong place for the data PhiGate exists to protect. So the Event
// type has no field capable of carrying a raw value: it records rule *names*,
// category *counts*, and content *hashes*. If you find yourself wanting to add
// "the text that matched", add its hash instead — two events carrying the same
// hash prove recurrence without disclosing the value even once.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Event is one auditable gateway decision.
//
// Every field is either a name, a count, a classification, or a hash. None can
// hold a customer value.
type Event struct {
	// Request identity.
	RequestID string
	SessionID string
	Tenant    string
	ClientIP  string

	// What was asked. PromptHash identifies the compressed payload without
	// disclosing it, so recurring incidents can be correlated.
	Model      string
	PromptHash string

	// Redaction: how much sensitive data was found and of what classes.
	// Values are never recorded, only counts and the rules that fired.
	Classifications map[string]int
	RedactionRules  []string
	MaxSensitivity  string

	// Routing and policy.
	Route          string
	Backend        string
	RouteReason    string
	PolicyAction   string
	PolicyReason   string
	CacheHit       bool
	FellBackCloud  bool
	UpstreamStatus string

	// Guardrails.
	EgressBlocked   bool
	EgressRule      string
	EgressSeverity  string
	EgressFindings  []string
	IngressRules    []string
	EnumerationStop bool

	// Accounting.
	PromptTokens     int
	CompletionTokens int
	BaselineTokens   int
	LatencyMS        int64

	// Outcome.
	Status int
	Error  string
}

// Sink is the seam audit destinations plug into.
//
// The community edition writes JSON lines to a file or stderr. An ISMS or APPI
// audit generally asks for more than that — append-only storage with a
// retention proof, or delivery into the customer's SIEM — and those substitute
// here without the request path changing.
type Sink interface {
	// Log writes one event. Implementations must not block the request path;
	// an audit destination that stalls must drop or buffer, never wait.
	Log(e Event)
	// Enabled reports whether events are being written, which /readyz and the
	// dashboard surface so a deployment cannot quietly lose its audit trail.
	Enabled() bool
}

// Compile-time proof that the file logger satisfies the seam.
var _ Sink = (*Logger)(nil)

// Nop is a Sink that discards events. It is the gateway's default, so a
// Gateway constructed without an audit destination reports honestly that
// auditing is off rather than panicking on the first request.
type Nop struct{}

// Log discards the event.
func (Nop) Log(Event) {}

// Enabled reports false: nothing is being written.
func (Nop) Enabled() bool { return false }

// Logger writes audit events.
type Logger struct {
	log     *slog.Logger
	enabled bool
	seq     atomic.Uint64
}

// Options configures the audit logger.
type Options struct {
	// Path is the destination file. Empty means stderr.
	Path string
	// Disabled turns auditing off entirely. Auditing defaults to on: an
	// enterprise deployment without an audit trail is not deployable, so
	// switching it off has to be a deliberate act.
	Disabled bool
}

// New opens the audit logger.
func New(opts Options) (*Logger, io.Closer, error) {
	if opts.Disabled {
		return &Logger{enabled: false}, nopCloser{}, nil
	}
	var (
		w      io.Writer = os.Stderr
		closer io.Closer = nopCloser{}
	)
	if opts.Path != "" {
		f, err := os.OpenFile(opts.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, err
		}
		w, closer = f, f
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	return &Logger{log: slog.New(h), enabled: true}, closer, nil
}

// Enabled reports whether events are being written.
func (l *Logger) Enabled() bool { return l != nil && l.enabled }

// Log writes one event.
func (l *Logger) Log(e Event) {
	if !l.Enabled() {
		return
	}
	attrs := []any{
		slog.String("event", "gateway.request"),
		slog.Uint64("seq", l.seq.Add(1)),
		slog.String("ts", time.Now().UTC().Format(time.RFC3339Nano)),
		slog.String("request_id", e.RequestID),
		slog.String("session_id", e.SessionID),
		slog.String("model", e.Model),
		slog.String("prompt_sha256", e.PromptHash),
		slog.String("route", e.Route),
		slog.String("backend", e.Backend),
		slog.String("route_reason", e.RouteReason),
		slog.String("policy_action", e.PolicyAction),
		slog.String("policy_reason", e.PolicyReason),
		slog.String("max_sensitivity", e.MaxSensitivity),
		slog.Bool("cache_hit", e.CacheHit),
		slog.Bool("cloud_fallback", e.FellBackCloud),
		slog.Bool("egress_blocked", e.EgressBlocked),
		slog.Int("prompt_tokens", e.PromptTokens),
		slog.Int("completion_tokens", e.CompletionTokens),
		slog.Int("baseline_tokens", e.BaselineTokens),
		slog.Int64("latency_ms", e.LatencyMS),
		slog.Int("status", e.Status),
	}
	if e.Tenant != "" {
		attrs = append(attrs, slog.String("tenant", e.Tenant))
	}
	if e.ClientIP != "" {
		attrs = append(attrs, slog.String("client_ip", e.ClientIP))
	}
	if len(e.Classifications) > 0 {
		attrs = append(attrs, slog.Any("classifications", e.Classifications))
	}
	if len(e.RedactionRules) > 0 {
		attrs = append(attrs, slog.String("redaction_rules", strings.Join(e.RedactionRules, ",")))
	}
	if e.EgressRule != "" {
		attrs = append(attrs,
			slog.String("egress_rule", e.EgressRule),
			slog.String("egress_severity", e.EgressSeverity))
	}
	if len(e.EgressFindings) > 0 {
		attrs = append(attrs, slog.String("egress_findings", strings.Join(e.EgressFindings, ",")))
	}
	if len(e.IngressRules) > 0 {
		attrs = append(attrs, slog.String("ingress_rules", strings.Join(e.IngressRules, ",")))
	}
	if e.EnumerationStop {
		attrs = append(attrs, slog.Bool("enumeration_blocked", true))
	}
	if e.UpstreamStatus != "" {
		attrs = append(attrs, slog.String("upstream_status", e.UpstreamStatus))
	}
	if e.Error != "" {
		attrs = append(attrs, slog.String("error", e.Error))
	}
	l.log.Info("phigate", attrs...)
}

// Hash returns the hex SHA-256 of s, for correlating payloads without storing
// them. Use it anywhere you are tempted to log content.
func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
