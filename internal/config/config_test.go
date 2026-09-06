package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phigate/phigate/internal/redact"
)

// write drops a config file in a temp dir and points PHIGATE_CONFIG at it.
func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "phigate.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func load(t *testing.T, body string, env map[string]string) (Config, error) {
	t.Helper()
	t.Setenv("PHIGATE_CONFIG", write(t, body))
	for k, v := range env {
		t.Setenv(k, v)
	}
	return FromEnv()
}

// TestFileSuppliesConfiguration is the base case: a file alone is enough.
func TestFileSuppliesConfiguration(t *testing.T) {
	c, err := load(t, `{
	  "addr": ":9999",
	  "api_keys": {"k1": "team-sre"},
	  "cache": {"ttl": "1m", "max": 7},
	  "policy": {"cloud_max_sensitivity": "low"}
	}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":9999" {
		t.Errorf("addr = %q", c.Addr)
	}
	if c.APIKeys["k1"] != "team-sre" {
		t.Errorf("api_keys = %v", c.APIKeys)
	}
	if c.CacheMax != 7 || c.CacheTTL.String() != "1m0s" {
		t.Errorf("cache = %d / %s", c.CacheMax, c.CacheTTL)
	}
	if c.Policy.CloudMaxSensitivity != redact.SensitivityLow {
		t.Errorf("policy = %v", c.Policy.CloudMaxSensitivity)
	}
}

// TestEnvironmentOverridesFile pins the precedence down. An operator tightening
// a control during an incident must not be overruled by a checked-in file.
func TestEnvironmentOverridesFile(t *testing.T) {
	c, err := load(t,
		`{"api_keys": {"k1": "t"}, "policy": {"cloud_max_sensitivity": "internal"}}`,
		map[string]string{"PHIGATE_CLOUD_MAX_SENSITIVITY": "low"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Policy.CloudMaxSensitivity != redact.SensitivityLow {
		t.Fatalf("cloud max = %v, want the environment's value to win", c.Policy.CloudMaxSensitivity)
	}
}

// TestFileValuesSurviveUnsetEnvironment: the environment layer must override
// only where a variable is actually present. Reverting a file setting to a
// built-in default because a variable happens to be unset would make the file
// useless.
func TestFileValuesSurviveUnsetEnvironment(t *testing.T) {
	c, err := load(t, `{"api_keys": {"k1": "t"}, "session": {"header": "X-Conv"},
	  "cache": {"enabled": false}, "dashboard": false}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.SessionHeader != "X-Conv" {
		t.Errorf("session header = %q", c.SessionHeader)
	}
	if c.CacheEnabled || c.CacheMax != 0 {
		t.Errorf("cache should be off: enabled=%v max=%d", c.CacheEnabled, c.CacheMax)
	}
	if c.DashboardOn {
		t.Error("dashboard should be off")
	}
}

// TestUnknownKeyIsAnError is the "fail loudly" rule applied to files. A
// misspelled key accepted and ignored is a control an auditor was told is
// enforced, silently doing nothing.
func TestUnknownKeyIsAnError(t *testing.T) {
	_, err := load(t, `{"api_keys":{"k":"t"},"policy":{"cloud_max_sensitvity":"low"}}`, nil)
	if err == nil {
		t.Fatal("a misspelled key was accepted")
	}
	if !strings.Contains(err.Error(), "cloud_max_sensitvity") {
		t.Errorf("error does not name the offending key: %v", err)
	}
}

func TestMalformedDurationIsAnError(t *testing.T) {
	_, err := load(t, `{"api_keys":{"k":"t"},"cache":{"ttl":"fifteen minutes"}}`, nil)
	if err == nil {
		t.Fatal("a malformed duration was accepted")
	}
	if !strings.Contains(err.Error(), "cache.ttl") {
		t.Errorf("error does not name the field: %v", err)
	}
}

// TestTenantNarrowsPolicy is the per-tenant feature's point: one gateway can
// hold a finance team to a stricter egress limit than an SRE team.
func TestTenantNarrowsPolicy(t *testing.T) {
	c, err := load(t, `{
	  "api_keys": {"k-sre": "team-sre", "k-fin": "team-finance"},
	  "policy": {"cloud_max_sensitivity": "internal"},
	  "tenants": {"team-finance": {"policy": {"cloud_max_sensitivity": "low"}}}
	}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.PolicyFor("team-finance").CloudMaxSensitivity; got != redact.SensitivityLow {
		t.Errorf("finance cloud max = %v, want low", got)
	}
	if got := c.PolicyFor("team-sre").CloudMaxSensitivity; got != redact.SensitivityInternal {
		t.Errorf("sre cloud max = %v, want the global internal", got)
	}
	// A tenant block naming only one field must not reset the others.
	if !c.PolicyFor("team-finance").AllowCloudFallback {
		t.Error("the tenant's policy lost the inherited fallback setting")
	}
}

// TestTenantCannotWidenPolicy: the global policy is a ceiling. If a tenant
// could raise it, the setting an operator believes bounds the deployment would
// bound nothing.
func TestTenantCannotWidenPolicy(t *testing.T) {
	_, err := load(t, `{
	  "api_keys": {"k": "t"},
	  "policy": {"cloud_max_sensitivity": "low"},
	  "tenants": {"t": {"policy": {"cloud_max_sensitivity": "confidential"}}}
	}`, nil)
	if err == nil {
		t.Fatal("a tenant was allowed to widen the global egress limit")
	}
	if !strings.Contains(err.Error(), "never widen") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestTenantWithNoKeyIsAnError catches the likeliest configuration mistake: a
// typo in the label leaves the tenant silently on the global policy it was
// meant to be narrowed away from.
func TestTenantWithNoKeyIsAnError(t *testing.T) {
	_, err := load(t, `{
	  "api_keys": {"k": "team-sre"},
	  "tenants": {"team-sr": {"rate_limit_per_min": 10}}
	}`, nil)
	if err == nil {
		t.Fatal("a tenant block with no matching API key was accepted")
	}
	if !strings.Contains(err.Error(), "team-sr") {
		t.Errorf("error does not name the tenant: %v", err)
	}
}

func TestRateLimitAndRedactionResolvePerTenant(t *testing.T) {
	c, err := load(t, `{
	  "api_keys": {"k1": "a", "k2": "b"},
	  "redact": {"packs": ["core", "jp", "secrets"]},
	  "serving": {"rate_limit_per_min": 100},
	  "tenants": {"b": {"rate_limit_per_min": 5, "redact_packs": ["jp"]}}
	}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if perMin, _ := c.RateLimitFor("a"); perMin != 100 {
		t.Errorf("tenant a limit = %d, want the global 100", perMin)
	}
	if perMin, _ := c.RateLimitFor("b"); perMin != 5 {
		t.Errorf("tenant b limit = %d, want its own 5", perMin)
	}
	if packs, _, _ := c.RedactionFor("a"); len(packs) != 3 {
		t.Errorf("tenant a packs = %v, want the global three", packs)
	}
	if packs, _, _ := c.RedactionFor("b"); len(packs) != 1 || packs[0] != "jp" {
		t.Errorf("tenant b packs = %v, want [jp]", packs)
	}
}

// TestNoFileBehavesAsBefore: the environment-only path must be unchanged, since
// that is what every existing deployment uses.
func TestNoFileBehavesAsBefore(t *testing.T) {
	t.Setenv("PHIGATE_CONFIG", "")
	t.Setenv("PHIGATE_API_KEYS", "k1:team-a,k2")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.APIKeys["k1"] != "team-a" || c.APIKeys["k2"] != "default" {
		t.Errorf("api keys = %v", c.APIKeys)
	}
	if c.Addr != ":8080" || c.SessionHeader != "X-PhiGate-Session" || c.CacheMax != 5000 {
		t.Errorf("defaults drifted: addr=%s header=%s cacheMax=%d",
			c.Addr, c.SessionHeader, c.CacheMax)
	}
}

// TestMissingCredentialsStillRefused: the open-relay guard must survive the
// introduction of a file that could have supplied the keys and did not.
func TestMissingCredentialsStillRefused(t *testing.T) {
	_, err := load(t, `{"addr": ":8080"}`, nil)
	if err == nil {
		t.Fatal("a gateway with no credentials and no anonymous opt-in was accepted")
	}
}

// TestReloadRereadsTheFile is what the hot-reload path depends on: the same
// path, read again, with no reference to the running configuration's values.
func TestReloadRereadsTheFile(t *testing.T) {
	path := write(t, `{"api_keys":{"k":"t"},"cache":{"max":11}}`)
	t.Setenv("PHIGATE_CONFIG", path)
	first, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if first.CacheMax != 11 {
		t.Fatalf("cache max = %d", first.CacheMax)
	}

	if err := os.WriteFile(path, []byte(`{"api_keys":{"k":"t"},"cache":{"max":22}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Reload(first)
	if err != nil {
		t.Fatal(err)
	}
	if second.CacheMax != 22 {
		t.Errorf("reloaded cache max = %d, want 22", second.CacheMax)
	}
	if first.CacheMax != 11 {
		t.Error("Reload mutated the configuration it was handed")
	}
}

// TestReloadOfABrokenFileChangesNothing: a bad edit must be a no-op, not a
// partially-applied configuration. The caller keeps what it has because Reload
// returns an error rather than a half-built Config it has already installed.
func TestReloadOfABrokenFileChangesNothing(t *testing.T) {
	path := write(t, `{"api_keys":{"k":"t"},"policy":{"cloud_max_sensitivity":"low"}}`)
	t.Setenv("PHIGATE_CONFIG", path)
	live, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(`{"api_keys":{"k":"t"},"policy":{"cloud_max_sensitivity":"nonsense"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Reload(live); err == nil {
		t.Fatal("a policy threshold that does not exist was accepted on reload")
	}
	if live.Policy.CloudMaxSensitivity != redact.SensitivityLow {
		t.Error("the live configuration was modified by a failed reload")
	}
}
