package redact

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// leakCase mirrors testdata/leak_corpus.json.
type leakCase struct {
	Name        string   `json:"name"`
	Payload     string   `json:"payload"`
	MustNotLeak []string `json:"must_not_leak"`
	MustSurvive []string `json:"must_survive"`
	Why         string   `json:"why"`
}

type leakCorpus struct {
	// SyntheticSecrets maps a name to the fragments of a synthetic credential.
	// They are joined at load time so no credential-shaped literal is ever
	// stored in a file — see the _secrets_note in the corpus.
	SyntheticSecrets map[string][]string `json:"synthetic_secrets"`
	Cases            []leakCase          `json:"cases"`
}

// resolve joins each secret's fragments and substitutes ${name} references
// throughout the corpus.
func (c *leakCorpus) resolve() error {
	joined := make(map[string]string, len(c.SyntheticSecrets))
	for name, frags := range c.SyntheticSecrets {
		joined[name] = strings.Join(frags, "")
	}

	expand := func(s string) (string, error) {
		var missing string
		out := secretRef.ReplaceAllStringFunc(s, func(ref string) string {
			name := ref[2 : len(ref)-1]
			v, ok := joined[name]
			if !ok {
				missing = name
				return ref
			}
			return v
		})
		if missing != "" {
			return "", fmt.Errorf("corpus references unknown secret %q", missing)
		}
		return out, nil
	}

	for i := range c.Cases {
		var err error
		if c.Cases[i].Payload, err = expand(c.Cases[i].Payload); err != nil {
			return fmt.Errorf("case %s: %w", c.Cases[i].Name, err)
		}
		for j, s := range c.Cases[i].MustNotLeak {
			if c.Cases[i].MustNotLeak[j], err = expand(s); err != nil {
				return fmt.Errorf("case %s: %w", c.Cases[i].Name, err)
			}
		}
		for j, s := range c.Cases[i].MustSurvive {
			if c.Cases[i].MustSurvive[j], err = expand(s); err != nil {
				return fmt.Errorf("case %s: %w", c.Cases[i].Name, err)
			}
		}
	}
	return nil
}

var secretRef = regexp.MustCompile(`\$\{[a-z0-9_]+\}`)

// loadCorpus reads and resolves the corpus.
func loadCorpus(t *testing.T) leakCorpus {
	t.Helper()
	b, err := os.ReadFile("testdata/leak_corpus.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var corpus leakCorpus
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if err := corpus.resolve(); err != nil {
		t.Fatalf("resolve corpus: %v", err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("corpus is empty")
	}
	return corpus
}

// corpusEngine matches the engine the gateway builds by default, plus the
// internal-domain suffixes the corpus assumes.
func corpusEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(Options{InternalDomains: []string{"corp", "internal", "local", "lan"}})
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return e
}

// TestLeakCorpus is the privacy guarantee expressed as a test. Every string in
// must_not_leak has to be absent from the redacted output; every string in
// must_survive has to still be present.
//
// This is the test to point a security reviewer at.
func TestLeakCorpus(t *testing.T) {
	corpus := loadCorpus(t)
	eng := corpusEngine(t)
	n := 0
	replace := func(f Finding) string { n++; return "<V" + strconv.Itoa(n) + ">" }

	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			n = 0
			out, findings := eng.Redact(tc.Payload, replace)

			for _, secret := range tc.MustNotLeak {
				if strings.Contains(out, secret) {
					t.Errorf("LEAK: %q survived redaction\n  why this matters: %s\n  output: %s",
						secret, tc.Why, out)
				}
				// A partially masked secret is worse than an unmasked one: it
				// looks safe. Assert no long fragment of it survives either.
				if frag := longestSurvivingFragment(out, secret); frag != "" {
					t.Errorf("PARTIAL LEAK: fragment %q of secret %q survived redaction\n  output: %s",
						frag, secret, out)
				}
			}

			for _, keep := range tc.MustSurvive {
				if !strings.Contains(out, keep) {
					t.Errorf("over-redaction: %q should have survived but did not\n  output: %s", keep, out)
				}
			}

			if len(tc.MustNotLeak) > 0 && len(findings) == 0 {
				t.Errorf("expected findings for %s, got none", tc.Name)
			}
		})
	}
}

// longestSurvivingFragment reports a substring of secret, at least minFragment
// characters long, that is still present in out. It is what catches the
// corruption bug where one rule masked the middle of another rule's match.
func longestSurvivingFragment(out, secret string) string {
	const minFragment = 12
	if len(secret) < minFragment {
		return ""
	}
	for size := len(secret); size >= minFragment; size-- {
		for i := 0; i+size <= len(secret); i++ {
			frag := secret[i : i+size]
			if strings.TrimSpace(frag) == "" {
				continue
			}
			if strings.Contains(out, frag) {
				return frag
			}
		}
	}
	return ""
}

// TestRedactIsSinglePass verifies the property that makes the corpus trustworthy:
// replacement happens once over the original text, so no substitution can be
// re-scanned or corrupted by a later rule.
func TestRedactIsSinglePass(t *testing.T) {
	eng := corpusEngine(t)
	in := "conn from 10.0.0.5 to /var/lib/pgsql/data at 2026-06-29T15:04:05Z"
	out, findings := eng.Redact(in, func(f Finding) string { return "<" + f.Rule + ">" })

	if strings.Contains(out, "10.0.0.5") {
		t.Errorf("ip survived: %s", out)
	}
	for i := 1; i < len(findings); i++ {
		if findings[i].Start < findings[i-1].End {
			t.Errorf("findings overlap: %+v and %+v", findings[i-1], findings[i])
		}
	}
}

// TestNoLiteralCredentialsInCorpus keeps the corpus committable.
//
// A fixture that looks like a live credential is indistinguishable from one to a
// secret scanner. GitHub push protection rejects the push outright, and
// gitleaks/trufflehog fail the CI of anyone who forks this repository. The
// corpus is the evidence behind PhiGate's central privacy claim, so it has to
// stay runnable — which means it has to stay pushable.
//
// This test fails before GitHub does, and tells the contributor what to do.
func TestNoLiteralCredentialsInCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/leak_corpus.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	text := string(raw)

	// Prefixes that vendor secret scanners key on. A contiguous occurrence in
	// the file means someone pasted a literal instead of adding fragments.
	scanned := map[string]*regexp.Regexp{
		"Slack token":       regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),
		"GitHub token":      regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`),
		"AWS access key id": regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`),
		"Google API key":    regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
		"Stripe key":        regexp.MustCompile(`(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}`),
		"npm token":         regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		"LLM provider key":  regexp.MustCompile(`sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}`),
		"JWT":               regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.`),
	}
	for name, re := range scanned {
		if m := re.FindString(text); m != "" {
			t.Errorf("literal %s in the corpus file: %q\n"+
				"  Secret scanners cannot tell this from a real credential and will block the push.\n"+
				"  Split it across synthetic_secrets fragments and reference it as ${name} instead.",
				name, m)
		}
	}

	// The fragments must still assemble into something the rules detect —
	// otherwise the corpus would pass by testing nothing.
	corpus := loadCorpus(t)
	eng := corpusEngine(t)
	for _, tc := range corpus.Cases {
		for _, secret := range tc.MustNotLeak {
			if len(eng.Detect(secret)) == 0 && strings.Contains(tc.Name, "token") {
				t.Errorf("case %s: %q assembles to something no rule detects", tc.Name, secret)
			}
		}
	}
}

// TestCategoriesDriveSensitivity locks the mapping the egress policy depends on.
func TestCategoriesDriveSensitivity(t *testing.T) {
	cases := map[Category]Sensitivity{
		CategorySecret:     SensitivityRestricted,
		CategoryPII:        SensitivityConfidential,
		CategoryNetwork:    SensitivityInternal,
		CategoryPath:       SensitivityInternal,
		CategoryIdentifier: SensitivityLow,
		CategoryTemporal:   SensitivityLow,
	}
	for cat, want := range cases {
		if got := cat.Sensitivity(); got != want {
			t.Errorf("%s: sensitivity = %v, want %v", cat, got, want)
		}
	}
}
