// SPDX-License-Identifier: BUSL-1.1

package slm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/phigate/phigate/internal/llm"
	"github.com/phigate/phigate/internal/types"
)

// ModelRecognizer adjudicates candidates with a local model.
//
// # Which model, and where it runs
//
// The local one. A detector whose job is to find personal data cannot send the
// text it is inspecting to a cloud provider in order to decide whether it
// contains personal data — that is the exfiltration the gateway exists to
// prevent, performed by the gateway. Callers pass the local client and nothing
// here selects a backend.
//
// # What it asks
//
// Not "find the names", but "which of these spans is a person". The gazetteer
// has already located the candidates, so the model answers a bounded
// multiple-choice question rather than an open extraction one. That is
// deliberate: the answer is a set of indices, which cannot be malformed in a way
// that produces a wrong *span*, only in a way that produces a wrong *decision*.
// An open extraction returning offsets would put the model in a position to
// point anywhere in the text, and a detector that trusted those offsets would
// be masking wherever the model said.
type ModelRecognizer struct {
	client llm.Client
	model  string
}

var _ Recognizer = (*ModelRecognizer)(nil)

// NewModelRecognizer returns a recognizer backed by client.
func NewModelRecognizer(client llm.Client, model string) *ModelRecognizer {
	return &ModelRecognizer{client: client, model: model}
}

const systemPrompt = `You identify Japanese personal names.
You are given a text and a numbered list of candidate spans taken from it.
For each candidate, decide whether it is being used as a person's name in this
sentence — not a place, company, product, or ordinary word that happens to share
the characters.
Reply with JSON only: {"names":[<indices of the candidates that are people>]}.
Reply {"names":[]} if none are. Do not explain. Do not repeat the text.`

// Names asks the model which candidates are people.
func (m *ModelRecognizer) Names(ctx context.Context, text string, candidates []Span) ([]Span, error) {
	if len(candidates) == 0 {
		return nil, nil
	}

	var b strings.Builder
	b.WriteString("TEXT:\n")
	b.WriteString(text)
	b.WriteString("\n\nCANDIDATES:\n")
	for i, c := range candidates {
		fmt.Fprintf(&b, "%d. %s\n", i, text[c.Start:c.End])
	}

	temp := 0.0
	resp, err := m.client.Chat(ctx, &types.ChatCompletionRequest{
		Model:       m.model,
		Temperature: &temp,
		Messages: []types.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: b.String()},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("slm: recognizer returned no choices")
	}

	idx, err := parseIndices(resp.Choices[0].Message.Content)
	if err != nil {
		return nil, err
	}
	out := make([]Span, 0, len(idx))
	for _, i := range idx {
		// An index outside the list is the model answering a question it was
		// not asked. Dropping it costs recall; trusting it would mask an
		// arbitrary span.
		if i < 0 || i >= len(candidates) {
			continue
		}
		out = append(out, candidates[i])
	}
	return out, nil
}

// parseIndices reads the model's reply.
//
// Models wrap JSON in prose and in code fences however firmly they are asked
// not to, so the object is located rather than assumed to be the whole reply. A
// reply with no object at all is an error and degrades to CE-only detection,
// which is the right outcome: a recognizer that cannot be understood has not
// said anything, and guessing on its behalf is how a detector starts masking at
// random.
func parseIndices(reply string) ([]int, error) {
	start := strings.IndexByte(reply, '{')
	end := strings.LastIndexByte(reply, '}')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("slm: recognizer reply contains no JSON object")
	}
	var doc struct {
		Names []int `json:"names"`
	}
	if err := json.Unmarshal([]byte(reply[start:end+1]), &doc); err != nil {
		return nil, fmt.Errorf("slm: recognizer reply is not the expected shape: %w", err)
	}
	return doc.Names, nil
}
