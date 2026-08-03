package policy

import (
	"testing"

	"github.com/phigate/phigate/internal/redact"
)

func TestDefaultKeepsPersonalDataLocal(t *testing.T) {
	p := Default()
	cases := map[redact.Sensitivity]Action{
		redact.SensitivityLow:          ActionAllow,
		redact.SensitivityInternal:     ActionAllow,
		redact.SensitivityConfidential: ActionLocalOnly,
		redact.SensitivityRestricted:   ActionLocalOnly,
	}
	for sens, want := range cases {
		if got := p.Evaluate(sens); got.Action != want {
			t.Errorf("%v: action = %v, want %v (%s)", sens, got.Action, want, got.Reason)
		}
	}
}

// TestLocalOnlyNeverFallsBackToCloud is the property that makes PhiGate a
// control rather than an optimisation.
func TestLocalOnlyNeverFallsBackToCloud(t *testing.T) {
	p := Default()
	p.AllowCloudFallback = true // even with fallback enabled globally

	sensitive := p.Evaluate(redact.SensitivityConfidential)
	if p.CloudFallbackAllowed(sensitive) {
		t.Fatal("a local-only payload must never be permitted to fall back to the cloud")
	}

	ordinary := p.Evaluate(redact.SensitivityLow)
	if !p.CloudFallbackAllowed(ordinary) {
		t.Error("a cloud-eligible payload should be allowed to fall back")
	}
}

func TestDenyThresholdIsOptIn(t *testing.T) {
	p := Default()
	if got := p.Evaluate(redact.SensitivityRestricted); got.Action == ActionDeny {
		t.Error("deny must be opt-in; default policy should confine, not refuse")
	}

	strict, err := Parse("low", "confidential", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := strict.Evaluate(redact.SensitivityRestricted); got.Action != ActionDeny {
		t.Errorf("action = %v, want deny once DenyAbove is configured", got.Action)
	}
}

func TestParseRejectsTypos(t *testing.T) {
	// A typo must fail loudly. Silently falling back to a permissive default
	// would widen what may leave the network while the config looks correct.
	if _, err := Parse("confidentail", "", true); err == nil {
		t.Error("expected an error for a misspelled sensitivity level")
	}
	if _, err := Parse("", "nonsense", true); err == nil {
		t.Error("expected an error for a misspelled deny threshold")
	}
}

func TestEveryDecisionIsExplainable(t *testing.T) {
	p := Default()
	for _, s := range []redact.Sensitivity{
		redact.SensitivityLow, redact.SensitivityInternal,
		redact.SensitivityConfidential, redact.SensitivityRestricted,
	} {
		if d := p.Evaluate(s); d.Reason == "" {
			t.Errorf("%v: verdict carries no reason; an auditor cannot act on that", s)
		}
	}
}
