// Package compressor implements PhiGate's Compression & Anonymization Layer:
// the deterministic pre-processing that turns raw enterprise logs and code
// snippets into masked, structurally-pruned templates before any prompt leaves
// the gateway boundary for a cloud LLM.
//
// The layer is a composable pipeline of Stages run in order:
//
//	Masker  -> Drain -> RefDict -> ASTPrune
//
//   - Masker   replaces high-cardinality variables (IPs, UUIDs, timestamps, …)
//     with <V1>, <V2> tokens.
//   - Drain    clusters near-identical log lines into a single template.
//   - RefDict  folds repetitive long strings (package paths) into #REF tokens.
//   - ASTPrune strips business values from code snippets, keeping only logical
//     structure and error nodes (via tree-sitter).
//
// Every substitution is recorded in the Session's Dictionary so the gateway can
// re-hydrate the LLM's answer for the human operator.
package compressor

// Stage is one composable step of the compression pipeline. Implementations
// must be safe to reuse across sessions; all mutable per-request state lives on
// the passed Session.
type Stage interface {
	Name() string
	Process(input string, s *Session) (string, error)
}

// Pipeline runs a fixed, ordered list of Stages.
type Pipeline struct {
	stages []Stage
}

// NewPipeline builds the default PhiGate compression pipeline.
func NewPipeline() *Pipeline {
	return &Pipeline{
		stages: []Stage{
			NewMasker(),
			NewDrain(),
			NewRefDict(),
			NewASTPruner(),
		},
	}
}

// NewPipelineWith builds a pipeline from an explicit stage list (used in tests).
func NewPipelineWith(stages ...Stage) *Pipeline {
	return &Pipeline{stages: stages}
}

// Compress runs every stage in order, threading the output of one into the
// next. The Session accumulates the dictionary needed for later hydration.
func (p *Pipeline) Compress(input string, s *Session) (string, error) {
	out := input
	for _, st := range p.stages {
		var err error
		out, err = st.Process(out, s)
		if err != nil {
			return "", err
		}
	}
	return out, nil
}

// Stages returns the configured stages (for introspection/debug output).
func (p *Pipeline) Stages() []Stage { return p.stages }
