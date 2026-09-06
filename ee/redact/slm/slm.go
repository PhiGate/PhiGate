// SPDX-License-Identifier: BUSL-1.1

// Package slm adds model-backed detection of Japanese personal names to the
// community edition's regex engine.
//
// # The gap it closes
//
// jp.json disables its own `jp_name_kanji` rule by default and says why: "free-form
// kanji names cannot be detected reliably by pattern alone". That is not a
// missing rule, it is a class of value a regex cannot decide. 田中 is a surname,
// a place, and part of ordinary words; whether a given occurrence is a person
// depends on the sentence around it. internal/redact's own Detector doc names
// this as the reason the seam exists: "a regex can only buy recall by
// over-masking ordinary text."
//
// # Composition, never replacement
//
// This detector runs CE's engine first and keeps every finding it produces. A
// model-backed finding is accepted only where CE claimed nothing. Two
// consequences, both deliberate:
//
//   - EE can never detect *less* than CE. The leak corpus CE's guarantee is
//     written against passes here unchanged, and there is a test asserting it
//     rather than a comment hoping so.
//   - A conflict is resolved in favour of the deterministic, reviewable,
//     check-digit-validated rule. If the regex says a twelve-digit string is a
//     My Number and the model says it is part of a name, the regex wins.
//
// # Two stages, because inference is not free
//
// A gazetteer of surnames finds candidates; the model decides which are people.
// Asking a model about every span of every request would put an inference in
// the request path for text that contains no name at all, which is most text.
// The gazetteer is high-recall and low-precision on purpose — it is a filter,
// not a detector, and masking on its output alone would be exactly the
// over-masking jp.json declined to ship.
//
// # Degrading
//
// If the model is unavailable or slow, detection falls back to CE's engine
// alone and the request succeeds. Detection degrading is acceptable; a request
// failing because a name detector timed out is not, and the payload is no less
// protected than it was under the community edition.
package slm

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/phigate/phigate/internal/redact"
)

// RuleName is what the layer is called in Rules(), and therefore in
// /v1/phigate/rules and every audit record it fires on.
//
// It is named rather than anonymous because that endpoint is what an auditor
// reads to confirm what is enforced, and a detector that contributed findings
// without appearing in the list would be a control nobody could see.
const RuleName = "jp_name_slm"

// Span is a range of text a Recognizer believes is a personal name.
type Span struct {
	Start, End int
}

// Recognizer decides which candidate spans are personal names.
//
// It is an interface so the adjudicating model is substitutable — and so the
// tests can assert this package's composition and fallback behaviour without a
// model, which is where the interesting failures are.
type Recognizer interface {
	// Names returns the spans of text that are personal names. candidates are
	// the gazetteer's suggestions, in order; an implementation may return a
	// subset, and must not return a span outside the text.
	Names(ctx context.Context, text string, candidates []Span) ([]Span, error)
}

// Options configures a Detector.
type Options struct {
	// Engine is the community detector. Required: this composes with it.
	Engine *redact.Engine
	// Recognizer adjudicates candidates. Nil disables the layer entirely,
	// which leaves exactly CE's behaviour.
	Recognizer Recognizer
	// Gazetteer overrides the built-in surname list.
	Gazetteer []string
	// Timeout bounds one adjudication. Zero uses a default.
	Timeout time.Duration
	// MaxCandidates bounds how many spans are sent for adjudication, so a
	// pathological payload cannot turn one request into an unbounded prompt.
	MaxCandidates int
}

// Detector is a redact.Detector composing CE's engine with a name recognizer.
type Detector struct {
	engine     *redact.Engine
	recognizer Recognizer
	gaz        *gazetteer
	timeout    time.Duration
	maxCands   int

	// degraded counts adjudications that failed or timed out, so an operator
	// can tell "no names in this traffic" from "the recognizer is down".
	mu       sync.Mutex
	degraded int64
	adjudged int64
}

var _ redact.Detector = (*Detector)(nil)

const (
	defaultTimeout       = 2 * time.Second
	defaultMaxCandidates = 64
)

// New composes a detector.
func New(opts Options) (*Detector, error) {
	if opts.Engine == nil {
		return nil, errNoEngine
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.MaxCandidates <= 0 {
		opts.MaxCandidates = defaultMaxCandidates
	}
	words := opts.Gazetteer
	if words == nil {
		words = DefaultSurnames()
	}
	return &Detector{
		engine:     opts.Engine,
		recognizer: opts.Recognizer,
		gaz:        newGazetteer(words),
		timeout:    opts.Timeout,
		maxCands:   opts.MaxCandidates,
	}, nil
}

type detectorError string

func (e detectorError) Error() string { return string(e) }

const errNoEngine = detectorError("slm: Engine is required; this detector composes with it, it does not replace it")

// Rules reports CE's rules plus this layer, so /v1/phigate/rules describes what
// is actually enforced.
func (d *Detector) Rules() []redact.Rule {
	rules := d.engine.Rules()
	if d.recognizer == nil {
		return rules
	}
	out := make([]redact.Rule, 0, len(rules)+1)
	out = append(out, rules...)
	out = append(out, redact.Rule{
		Name:     RuleName,
		Category: redact.CategoryPII,
		Priority: 0, // never outranks a CE rule; see the merge below
		Description: "Japanese personal name in free text, found by a surname " +
			"gazetteer and confirmed by a model. Falls back to no name detection " +
			"when the model is unavailable.",
	})
	return out
}

// Redact masks every span CE finds, plus the names the recognizer confirms in
// what CE left alone.
func (d *Detector) Redact(text string, replace func(redact.Finding) string) (string, []redact.Finding) {
	base := d.engine.Detect(text)
	extra := d.names(text, base)
	if len(extra) == 0 {
		// Identical to CE, down to the single-pass replacement, when there is
		// nothing to add.
		return d.engine.Redact(text, replace)
	}

	found := merge(base, extra)
	var b strings.Builder
	b.Grow(len(text))
	last := 0
	for _, f := range found {
		b.WriteString(text[last:f.Start])
		b.WriteString(replace(f))
		last = f.End
	}
	b.WriteString(text[last:])
	return b.String(), found
}

// Stats reports how the layer has been behaving.
type Stats struct {
	// Adjudicated is how many requests were sent for adjudication.
	Adjudicated int64
	// Degraded is how many of those failed or timed out and fell back to CE
	// alone. A rising count means names are not being detected.
	Degraded int64
}

// Stats returns a snapshot.
func (d *Detector) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Stats{Adjudicated: d.adjudged, Degraded: d.degraded}
}

// names finds candidate spans CE did not claim and asks the recognizer which
// are people.
func (d *Detector) names(text string, base []redact.Finding) []redact.Finding {
	if d.recognizer == nil {
		return nil
	}
	cands := d.gaz.candidates(text)
	cands = dropOverlapping(cands, base)
	if len(cands) == 0 {
		return nil
	}
	if len(cands) > d.maxCands {
		cands = cands[:d.maxCands]
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	d.mu.Lock()
	d.adjudged++
	d.mu.Unlock()

	spans, err := d.recognizer.Names(ctx, text, cands)
	if err != nil {
		// Detection degrades; the request does not fail. The payload is no
		// less protected than it was under the community edition.
		d.mu.Lock()
		d.degraded++
		d.mu.Unlock()
		return nil
	}

	out := make([]redact.Finding, 0, len(spans))
	for _, s := range spans {
		// A recognizer is an untrusted component: a span outside the text, or
		// inverted, would panic the slicing below.
		if s.Start < 0 || s.End > len(text) || s.Start >= s.End {
			continue
		}
		out = append(out, redact.Finding{
			Start: s.Start, End: s.End, Text: text[s.Start:s.End],
			Rule: RuleName, Category: redact.CategoryPII,
		})
	}
	return dropOverlapping2(out, base)
}

// merge combines CE's findings with the extra ones into a sorted,
// non-overlapping set.
//
// CE's are already resolved among themselves and are never dropped, which is
// what makes the superset property structural rather than a matter of care.
func merge(base, extra []redact.Finding) []redact.Finding {
	out := make([]redact.Finding, 0, len(base)+len(extra))
	out = append(out, base...)
	out = append(out, extra...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].End > out[j].End
	})

	// A final sweep, because two extras could overlap each other even though
	// neither overlaps a CE finding.
	kept := out[:0]
	lastEnd := -1
	for _, f := range out {
		if f.Start < lastEnd {
			continue
		}
		kept = append(kept, f)
		lastEnd = f.End
	}
	return kept
}

// dropOverlapping removes candidate spans that touch a CE finding.
func dropOverlapping(cands []Span, base []redact.Finding) []Span {
	if len(base) == 0 {
		return cands
	}
	out := cands[:0]
	for _, c := range cands {
		if !overlapsAny(c.Start, c.End, base) {
			out = append(out, c)
		}
	}
	return out
}

// dropOverlapping2 is the same check applied to findings rather than spans.
func dropOverlapping2(extra, base []redact.Finding) []redact.Finding {
	if len(base) == 0 {
		return extra
	}
	out := extra[:0]
	for _, f := range extra {
		if !overlapsAny(f.Start, f.End, base) {
			out = append(out, f)
		}
	}
	return out
}

func overlapsAny(start, end int, base []redact.Finding) bool {
	for _, b := range base {
		if start < b.End && b.Start < end {
			return true
		}
	}
	return false
}
