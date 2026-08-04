package redact

import (
	"strings"
	"testing"
)

func TestMyNumberCheckDigit(t *testing.T) {
	// Valid numbers computed with the official 総務省令 formula.
	valid := []string{"123456789018", "111122223333"}
	invalid := []string{
		"123456789012", // wrong check digit
		"000000000000", // placeholder run
		"12345678901",  // too short
	}
	for _, s := range valid {
		if !validMyNumber(s) {
			t.Errorf("validMyNumber(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validMyNumber(s) {
			t.Errorf("validMyNumber(%q) = true, want false", s)
		}
	}
}

func TestCorporateNumberCheckDigit(t *testing.T) {
	if !validCorporateNumber("9234567890123") {
		t.Error("expected 9234567890123 to be a valid 法人番号")
	}
	if validCorporateNumber("1234567890123") {
		t.Error("expected 1234567890123 to be rejected")
	}
}

func TestLuhn(t *testing.T) {
	valid := []string{"4111111111111111", "4111-1111-1111-1111", "5500 0000 0000 0004"}
	invalid := []string{"4111111111111112", "1234567890123456", "1111111111111111"}
	for _, s := range valid {
		if !validLuhn(s) {
			t.Errorf("validLuhn(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validLuhn(s) {
			t.Errorf("validLuhn(%q) = true, want false", s)
		}
	}
}

func TestPlausibleSecretRejectsPlaceholders(t *testing.T) {
	for _, s := range []string{"changeme", "<your-token>", "${DB_PASSWORD}", "****", "xxxx", "null"} {
		if plausibleSecret(s) {
			t.Errorf("plausibleSecret(%q) = true; placeholders should not enter the dictionary", s)
		}
	}
	for _, s := range []string{"Tr0ub4dor&3", "hunter2xyz"} {
		if !plausibleSecret(s) {
			t.Errorf("plausibleSecret(%q) = false, want true", s)
		}
	}
}

// TestOverlapResolutionPrefersSpecificRule is the regression test for the
// corruption bug: a low-priority path rule must never claim bytes that a
// credential rule also matched.
func TestOverlapResolutionPrefersSpecificRule(t *testing.T) {
	eng := MustEngine(Options{})
	in := `aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
	_, findings := eng.Redact(in, func(f Finding) string { return "<X>" })

	if len(findings) != 1 {
		t.Fatalf("want exactly 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Category != CategorySecret {
		t.Errorf("category = %s, want secret", findings[0].Category)
	}
	if findings[0].Text != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("masked span = %q; the whole key must be claimed, not part of it", findings[0].Text)
	}
}

func TestEntropyDetectorPrecision(t *testing.T) {
	d := NewEntropyDetector()
	secrets := []string{
		"k3JqZ8vN2pXwT7bR5yL1cM9fH4dG6sA0eU8iO2nP4zQ",
		"AbCdEf1234GhIjKl5678MnOpQr90StUvWx",
	}
	benign := []string{
		"ap-northeast-1",
		"org.springframework.web.servlet.DispatcherServlet",
		"connectionpoolexhaustedexception",
		"/var/lib/postgresql/data/pg_wal",
	}
	for _, s := range secrets {
		if !d.isSecret(s) {
			t.Errorf("isSecret(%q) = false, want true (entropy %.2f)", s, shannon(s))
		}
	}
	for _, s := range benign {
		if d.isSecret(s) {
			t.Errorf("isSecret(%q) = true, want false (entropy %.2f)", s, shannon(s))
		}
	}
}

func TestUnknownPackIsAnError(t *testing.T) {
	// A typo in PHIGATE_REDACT_PACKS must fail loudly. Silently loading no
	// rules would disable credential detection while looking healthy.
	if _, err := NewEngine(Options{Packs: []string{"secrets", "typo"}}); err == nil {
		t.Fatal("expected an error for an unknown pack name")
	}
}

func TestBadCustomRuleIsAnError(t *testing.T) {
	_, err := NewEngine(Options{ExtraRules: []Rule{{
		Name: "broken", Category: CategoryPII, Pattern: "([unclosed",
	}}})
	if err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("expected the error to name the offending rule, got %v", err)
	}
}

func TestInternalDomainsAreOptIn(t *testing.T) {
	withOut := MustEngine(Options{})
	if _, f := withOut.Redact("host db-01.internal.corp down", nil2); len(f) != 0 {
		t.Errorf("without configured domains, hostnames should not be masked: %+v", f)
	}
	withIn := MustEngine(Options{InternalDomains: []string{"corp"}})
	out, f := withIn.Redact("host db-01.internal.corp down", nil2)
	if len(f) == 0 || strings.Contains(out, "db-01.internal.corp") {
		t.Errorf("configured internal domain not masked: %q", out)
	}
}

// TestMyNumberIsClassifiedAsPII matters beyond masking: the egress policy keys
// off Category, and a My Number caught only by the generic large_integer rule
// would be classified "identifier" (low) instead of "pii" (confidential) and
// would therefore be allowed to leave for a cloud backend.
func TestMyNumberIsClassifiedAsPII(t *testing.T) {
	eng := MustEngine(Options{})
	_, findings := eng.Redact("従業員の個人番号 1234 5678 9018 が登録できません", nil2)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(findings), findings)
	}
	if findings[0].Rule != "jp_mynumber" {
		t.Errorf("rule = %q, want jp_mynumber (a My Number caught only as a generic integer "+
			"would be misclassified and allowed to egress)", findings[0].Rule)
	}
	if findings[0].Sensitivity() != SensitivityConfidential {
		t.Errorf("sensitivity = %v, want confidential", findings[0].Sensitivity())
	}
}

func nil2(Finding) string { return "<V>" }

// TestCreditCardDoesNotFireOnLogIdentifiers is a regression test drawn from
// real data: benchmarking against the public LogHub corpora showed the rule
// firing 674 times across 16,000 lines of system logs, entirely on Hadoop block
// ids and process ids that happen to satisfy Luhn.
//
// It matters beyond noise. A card is PII, PII is confidential, and confidential
// payloads are confined to the local model — so each false positive silently
// stopped an ordinary infrastructure log from reaching the cloud backend.
func TestCreditCardDoesNotFireOnLogIdentifiers(t *testing.T) {
	eng := MustEngine(Options{})
	fired := func(s string) bool {
		for _, f := range eng.Detect(s) {
			if f.Rule == "credit_card" {
				return true
			}
		}
		return false
	}

	// Verbatim from LogHub HDFS/BGL samples; all pass Luhn.
	for _, s := range []string{
		"blk_6952295868487656571",
		"blk_-4980916519894289629",
		"081109 204453 34 INFO dfs.DataNode: receiving block",
		"081109 205409 28 INFO dfs.FSNamesystem: BLOCK* ask",
	} {
		if fired(s) {
			t.Errorf("FALSE POSITIVE: credit_card fired on log data %q; this would "+
				"misclassify the payload as PII and confine it to the local model", s)
		}
	}

	// Real card formats must still be caught, including JCB — the dominant
	// domestic brand in Japan.
	for _, s := range []string{
		"card 4111111111111111",
		"card 4111-1111-1111-1111",
		"card 5500 0000 0000 0004",
		"amex 3782 822463 10005",
		"jcb 3530111333300000",
	} {
		if !fired(s) {
			t.Errorf("MISSED: credit_card did not fire on %q", s)
		}
	}
}
