// Package router hosts PhiGate's Intelligent Routing Layer: given a compressed,
// anonymized request it decides whether a locally deployed Phi-4-mini can
// resolve it (cloud cost = 0) or whether it must be escalated to a cloud LLM.
//
// The decision is deterministic and explainable — every verdict carries a
// human-readable reason for audit logs. The guiding policy:
//
//   - Known / simple single-component infrastructure errors -> LOCAL.
//   - Complex, multi-component anomalies or code-bearing snippets -> CLOUD.
package router

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// Target identifies where a request should be sent.
type Target int

const (
	// TargetLocal routes to the local SLM (Phi-4-mini via Ollama/llama.cpp).
	TargetLocal Target = iota
	// TargetCloud forwards to a cloud LLM provider.
	TargetCloud
)

func (t Target) String() string {
	if t == TargetLocal {
		return "local"
	}
	return "cloud"
}

// Decision is the routing verdict plus a reason for audit logs.
type Decision struct {
	Target Target
	Reason string
}

// Router decides the destination for a compressed prompt.
type Router interface {
	Route(ctx context.Context, compressed string) (Decision, error)
}

// HeuristicRouter is a deterministic, dependency-free classifier. It favours the
// local SLM for cheap, well-understood errors and escalates anything large,
// multi-template, or code-bearing to the cloud.
type HeuristicRouter struct {
	maxLocalLines int // distinct template lines above which we escalate
	maxLocalRunes int // payload size (runes) above which we escalate
}

// NewHeuristicRouter returns a router with default thresholds.
func NewHeuristicRouter() *HeuristicRouter {
	return &HeuristicRouter{maxLocalLines: 3, maxLocalRunes: 400}
}

// codeMarkers indicate an AST-pruned code/config snippet (handled best by a
// cloud model). The placeholders are emitted by the compressor's ASTPruner.
var codeMarkers = regexp.MustCompile(`<id>|<type>|<str>|\b(func|def|class|return|import)\b`)

// simpleSignals are well-known single-component infrastructure errors that a
// local SLM can confidently triage and map to an automation runbook.
var simpleSignals = regexp.MustCompile(`(?i)\b(connection refused|timed? out|timeout|disk (is )?full|no space left|out of memory|oomkilled|permission denied|no such file|cannot connect|refused to connect|502|503|504|gateway timeout|connection reset)\b`)

// Route classifies the compressed payload.
func (r *HeuristicRouter) Route(_ context.Context, compressed string) (Decision, error) {
	trimmed := strings.TrimSpace(compressed)

	// 1. Code/config structure is escalated — it usually needs deeper reasoning.
	if codeMarkers.MatchString(trimmed) {
		return Decision{TargetCloud, "code/config structure detected"}, nil
	}

	// 2. Large or multi-template payloads imply a multi-component anomaly.
	lines := nonEmptyLines(trimmed)
	if len(lines) > r.maxLocalLines {
		return Decision{TargetCloud, "multi-template payload (" + strconv.Itoa(len(lines)) + " lines)"}, nil
	}
	if runes := len([]rune(trimmed)); runes > r.maxLocalRunes {
		return Decision{TargetCloud, "large payload (" + strconv.Itoa(runes) + " runes)"}, nil
	}

	// 3. A recognised simple infra error on a small payload -> local SLM.
	if simpleSignals.MatchString(trimmed) {
		return Decision{TargetLocal, "known simple infrastructure error"}, nil
	}

	// 4. Default: small, single-component, unrecognised -> try local first
	//    (cheapest path; the gateway may fall back to cloud on failure).
	return Decision{TargetLocal, "small single-component payload"}, nil
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}
