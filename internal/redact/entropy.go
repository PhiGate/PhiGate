package redact

import (
	"math"
	"strings"
	"unicode"
)

// EntropyDetector is the safety net beneath the pattern rules.
//
// Pattern rules only catch credentials someone anticipated. Every enterprise
// has at least one bespoke token format — an internal service's session key, a
// legacy system's licence blob — that no shipped pack knows about. Those are
// exactly the values whose leakage is an incident.
//
// The detector flags whitespace-delimited tokens that *look* like key material:
// long, drawn from a key-like alphabet, and with high Shannon entropy. It is
// deliberately conservative, because a false positive here costs answer quality
// (a real identifier gets masked) while a false negative costs a credential.
type EntropyDetector struct {
	// MinLen is the shortest token considered. Below ~24 characters the
	// entropy estimate is too noisy to separate keys from ordinary words.
	MinLen int
	// MinEntropy is the Shannon entropy in bits per character above which a
	// token is treated as key material. Base64-encoded random data sits near
	// 5.5-6.0; English prose and dotted identifiers sit near 3.0-4.0.
	MinEntropy float64
	// RequireMixed demands at least two of {lowercase, uppercase, digit},
	// which excludes long lowercase words and long hex-looking IDs already
	// covered by dedicated rules.
	RequireMixed bool
}

// NewEntropyDetector returns the default detector, tuned so that realistic
// secrets (AWS secret access keys, 32+ byte base64 tokens) are caught while
// stack frames, URLs, and long dotted identifiers are not.
func NewEntropyDetector() *EntropyDetector {
	return &EntropyDetector{MinLen: 24, MinEntropy: 4.0, RequireMixed: true}
}

// detect scans text for high-entropy tokens and returns them as secret findings.
func (d *EntropyDetector) detect(text string) []Finding {
	if d == nil || d.MinLen <= 0 {
		return nil
	}
	var out []Finding
	start := -1
	for i := 0; i <= len(text); i++ {
		atEnd := i == len(text)
		if !atEnd && !isTokenBoundary(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			// In "KEY=value" form only the value can be secret. Scoring the
			// whole token makes the key's letters inflate the entropy estimate,
			// which is how "AWS_REGION=ap-northeast-1" used to be flagged.
			vs := start + valueOffset(text[start:i])
			tok := text[vs:i]
			if d.isSecret(tok) {
				out = append(out, Finding{
					Start: vs, End: i, Text: tok,
					Rule: "entropy_secret", Category: CategorySecret,
				})
			}
			start = -1
		}
	}
	return out
}

// valueOffset returns the index within tok where its value begins.
//
// It splits after the last '=' that is followed by any non-'=' character. That
// rule keeps base64 padding intact ("AccountKey=Zm9v...==" yields "Zm9v...==")
// while stripping the assignment key from "AWS_REGION=ap-northeast-1".
func valueOffset(tok string) int {
	off := 0
	for i := 0; i < len(tok); i++ {
		if tok[i] != '=' {
			continue
		}
		rest := tok[i+1:]
		if strings.Trim(rest, "=") != "" {
			off = i + 1
		}
	}
	return off
}

// isTokenBoundary splits on whitespace and the punctuation that normally
// delimits a value in a log line or config file. '/' , '+' , '=' , '-' and '_'
// are *not* boundaries because they occur inside base64 and URL-safe base64.
func isTokenBoundary(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"', '\'', '`', ',', ';', '(', ')', '[', ']',
		'{', '}', '<', '>', '|', '\\':
		return true
	}
	return false
}

// isSecret applies the length, alphabet, mixing and entropy tests in increasing
// order of cost.
func (d *EntropyDetector) isSecret(tok string) bool {
	tok = strings.Trim(tok, ".:=")
	if len(tok) < d.MinLen {
		return false
	}
	var lower, upper, digit, other int
	for i := 0; i < len(tok); i++ {
		c := rune(tok[i])
		switch {
		case unicode.IsLower(c):
			lower++
		case unicode.IsUpper(c):
			upper++
		case unicode.IsDigit(c):
			digit++
		case strings.ContainsRune("+/=_-", c):
			other++
		default:
			return false // not key-like material
		}
	}
	if d.RequireMixed {
		classes := 0
		for _, n := range []int{lower, upper, digit} {
			if n > 0 {
				classes++
			}
		}
		if classes < 2 {
			return false
		}
	}
	// A token that is mostly separators is a path or a dotted identifier.
	if other*3 > len(tok) {
		return false
	}
	return shannon(tok) >= d.MinEntropy
}

// shannon returns the Shannon entropy of s in bits per character.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
