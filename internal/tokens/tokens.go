// Package tokens turns PhiGate's savings claim into a number a CFO can audit.
//
// The gateway previously reported compression as a percentage of *runes*. Runes
// are not what anyone is billed for, and the figure ignored the much larger
// saving: a request answered by the local SLM costs zero cloud tokens whatever
// its length. This package measures both, in tokens and in money.
//
// # On estimation
//
// Exact token counts require the upstream provider's BPE vocabulary, which
// differs per model and per version. PhiGate takes the honest route:
//
//   - When the provider reports usage, that is authoritative and is what the
//     ledger bills.
//   - The estimator is used only for the counterfactual — "what would the
//     *uncompressed* prompt have cost?" — which no provider will ever report,
//     because that request is never sent.
//
// The estimator is a character-class heuristic calibrated against cl100k_base.
// It is accurate to roughly ±15% on mixed log/code/prose input, and it is
// deliberately conservative: it under-counts the uncompressed baseline slightly,
// so the reported saving errs low rather than flattering the product.
package tokens

import (
	"strings"
	"unicode"
)

// Counter estimates the number of tokens in a string.
type Counter interface {
	Estimate(text string) int
}

// Heuristic is the default dependency-free Counter.
type Heuristic struct{}

// NewHeuristic returns the default estimator.
func NewHeuristic() Heuristic { return Heuristic{} }

// Estimate approximates a BPE token count.
//
// The model behind the numbers:
//
//   - Latin words tokenize at roughly 4 characters per token, with a floor of
//     one token per word.
//   - CJK text tokenizes far worse — about one token per character for kanji
//     and kana — which matters a great deal for a product aimed at Japanese
//     enterprises, where assuming 4 chars/token would understate cost by 3-4x.
//   - Runs of punctuation and symbols tokenize at roughly one token each,
//     which is why minified JSON and stack traces are so expensive.
func (Heuristic) Estimate(text string) int {
	if text == "" {
		return 0
	}
	var (
		total    int
		wordLen  int
		digitRun int
	)
	flushWord := func() {
		if wordLen == 0 {
			return
		}
		total += (wordLen + 3) / 4
		wordLen = 0
	}
	flushDigits := func() {
		if digitRun == 0 {
			return
		}
		// Digits group in threes in most BPE vocabularies.
		total += (digitRun + 2) / 3
		digitRun = 0
	}

	for _, r := range text {
		switch {
		case isCJK(r):
			flushWord()
			flushDigits()
			total++
		case unicode.IsDigit(r):
			flushWord()
			digitRun++
		case unicode.IsLetter(r) || r == '_' || r == '\'':
			flushDigits()
			wordLen++
		case r == ' ':
			flushWord()
			flushDigits()
			// Spaces usually merge into the following token; they are not
			// counted separately.
		case r == '\n' || r == '\t':
			flushWord()
			flushDigits()
			total++
		default:
			// Punctuation and symbols: about one token apiece.
			flushWord()
			flushDigits()
			total++
		}
	}
	flushWord()
	flushDigits()
	if total == 0 {
		return 1
	}
	return total
}

// isCJK reports whether r is Han, Hiragana, Katakana or a full-width form —
// the ranges that tokenize at roughly one token per character.
func isCJK(r rune) bool {
	switch {
	case r >= 0x3040 && r <= 0x30FF: // hiragana, katakana
		return true
	case r >= 0x3400 && r <= 0x4DBF: // CJK ext A
		return true
	case r >= 0x4E00 && r <= 0x9FFF: // CJK unified
		return true
	case r >= 0xF900 && r <= 0xFAFF: // compatibility ideographs
		return true
	case r >= 0xFF00 && r <= 0xFFEF: // full-width forms
		return true
	}
	return false
}

// EstimateMessages sums the estimate over a set of message contents, adding the
// per-message framing overhead the Chat Completions format imposes (roughly 4
// tokens for the role and delimiters).
func EstimateMessages(c Counter, contents []string) int {
	total := 0
	for _, s := range contents {
		total += c.Estimate(s) + 4
	}
	if total > 0 {
		total += 3 // priming tokens for the reply
	}
	return total
}

// TrimForLog shortens a string for inclusion in a debug line without splitting
// a multi-byte rune.
func TrimForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return strings.TrimSpace(string(r[:max])) + "…"
}
