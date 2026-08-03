// Package config loads PhiGate's runtime configuration from the environment.
//
// Two principles govern the defaults:
//
//   - **Safe by default.** Anything that could widen what leaves the network is
//     off unless switched on. The debug endpoint, which discloses raw values, is
//     the clearest case: it now requires an explicit opt-in, because shipping it
//     enabled meant every deployment exposed an unauthenticated endpoint that
//     printed the plaintext of everything it had masked.
//   - **Fail loudly.** A malformed policy threshold or an unknown rule pack is a
//     startup error, never a silent fallback. A typo must not quietly disable a
//     control that an auditor was told is enforced.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/phigate/phigate/internal/llm"
	"github.com/phigate/phigate/internal/policy"
	"github.com/phigate/phigate/internal/sandbox"
)

// Backend is the configuration of one upstream model provider.
type Backend struct {
	Provider   llm.Provider
	BaseURL    string
	Model      string
	APIKey     string
	APIVersion string
	Deployment string
	Timeout    time.Duration
}

// Config holds every setting for the gateway.
type Config struct {
	Addr string

	// Local SLM (Ollama / llama.cpp / vLLM).
	Local Backend
	// Cloud LLM (OpenAI-compatible or Azure OpenAI).
	Cloud Backend

	// SystemPreamble is prepended to every upstream request so the model
	// knows that <V1> / #REF1 are anonymized placeholders.
	SystemPreamble string

	// --- Access control ---

	// APIKeys are the credentials clients must present. Empty means the
	// gateway is unauthenticated, which is refused unless AllowAnonymous is
	// set: an open proxy in front of a paid API key is a billing incident
	// waiting to happen.
	APIKeys map[string]string // key -> tenant label
	// AllowAnonymous permits running with no API keys configured.
	AllowAnonymous bool
	// TrustedProxyHeader names a header to read the client IP from, e.g.
	// X-Forwarded-For. Empty means use the socket address.
	TrustedProxyHeader string

	// --- Redaction ---

	RedactPacks     []string
	RedactRuleDir   string
	DisableRules    []string
	InternalDomains []string
	DisableEntropy  bool

	// --- Egress policy ---

	Policy policy.Policy

	// --- Guardrails ---

	GuardOverrides map[string]sandbox.Severity
	IngressScan    bool
	Enumeration    sandbox.EnumerationThreshold

	// --- Sessions and cache ---

	SessionTTL      time.Duration
	SessionMax      int
	SessionHeader   string
	CacheTTL        time.Duration
	CacheMax        int
	CacheEnabled    bool
	CacheAcrossTurn bool

	// --- Accounting ---

	PriceBookPath string
	LocalCostPerM float64

	// --- Observability ---

	AuditPath     string
	AuditDisabled bool
	MetricsPath   string
	DebugEnabled  bool
	DashboardOn   bool

	// --- Serving ---

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownGrace     time.Duration
	MaxBodyBytes      int64
	RateLimitPerMin   int
	RateLimitBurst    int
	Retries           int
	BreakerThreshold  int
	BreakerCooldown   time.Duration
}

// DefaultSystemPreamble explains PhiGate's anonymization convention to the
// upstream model so it preserves placeholders verbatim in its answer.
const DefaultSystemPreamble = "You are an IT operations and SRE assistant. " +
	"The user's logs and code have been anonymized by a gateway: tokens such as " +
	"<V1>, <V2>, #REF1 and placeholders like <id>, <str>, <int> stand in for real " +
	"values that were removed for security. Reason about the structure and refer to " +
	"these tokens verbatim in your answer; they will be restored before the operator " +
	"sees your response. Do not invent the hidden values, and never list or enumerate " +
	"placeholder tokens that the user did not ask about."

// FromEnv builds a Config from environment variables, applying defaults.
// It returns an error rather than falling back when a value is malformed.
func FromEnv() (Config, error) {
	c := Config{
		Addr:           envOr("PHIGATE_ADDR", ":8080"),
		SystemPreamble: envOr("PHIGATE_SYSTEM_PREAMBLE", DefaultSystemPreamble),
	}

	var err error
	if c.Local, err = backendFromEnv("LOCAL", "http://localhost:11434/v1", "phi4-mini"); err != nil {
		return c, err
	}
	if c.Cloud, err = backendFromEnv("CLOUD", "https://api.openai.com/v1", "gpt-4o"); err != nil {
		return c, err
	}
	if c.Cloud.APIKey == "" {
		c.Cloud.APIKey = os.Getenv("OPENAI_API_KEY")
	}

	// --- Access control ---
	c.APIKeys = parseAPIKeys(os.Getenv("PHIGATE_API_KEYS"))
	c.AllowAnonymous = envBool("PHIGATE_ALLOW_ANONYMOUS", false)
	c.TrustedProxyHeader = os.Getenv("PHIGATE_TRUSTED_PROXY_HEADER")
	if len(c.APIKeys) == 0 && !c.AllowAnonymous {
		return c, fmt.Errorf(
			"no client credentials configured: set PHIGATE_API_KEYS=\"key:tenant,...\" " +
				"or set PHIGATE_ALLOW_ANONYMOUS=true to accept that anyone who can reach " +
				"this port can spend your upstream API quota")
	}

	// --- Redaction ---
	c.RedactPacks = splitList(os.Getenv("PHIGATE_REDACT_PACKS"))
	c.RedactRuleDir = os.Getenv("PHIGATE_REDACT_RULE_DIR")
	c.DisableRules = splitList(os.Getenv("PHIGATE_REDACT_DISABLE"))
	c.InternalDomains = splitList(envOr("PHIGATE_INTERNAL_DOMAINS", "internal,corp,local,lan,intra"))
	c.DisableEntropy = envBool("PHIGATE_REDACT_DISABLE_ENTROPY", false)

	// --- Egress policy ---
	c.Policy, err = policy.Parse(
		os.Getenv("PHIGATE_CLOUD_MAX_SENSITIVITY"),
		os.Getenv("PHIGATE_DENY_ABOVE_SENSITIVITY"),
		envBool("PHIGATE_ALLOW_CLOUD_FALLBACK", true),
	)
	if err != nil {
		return c, err
	}

	// --- Guardrails ---
	if c.GuardOverrides, err = parseGuardOverrides(os.Getenv("PHIGATE_GUARD_SEVERITY")); err != nil {
		return c, err
	}
	c.IngressScan = envBool("PHIGATE_INGRESS_SCAN", true)
	c.Enumeration = sandbox.DefaultEnumerationThreshold()
	if v := envInt("PHIGATE_ENUMERATION_MIN_DICT", c.Enumeration.MinDictionary); v > 0 {
		c.Enumeration.MinDictionary = v
	}

	// --- Sessions and cache ---
	c.SessionTTL = envDuration("PHIGATE_SESSION_TTL", 30*time.Minute)
	c.SessionMax = envInt("PHIGATE_SESSION_MAX", 10000)
	c.SessionHeader = envOr("PHIGATE_SESSION_HEADER", "X-PhiGate-Session")
	c.CacheEnabled = envBool("PHIGATE_CACHE_ENABLED", true)
	c.CacheTTL = envDuration("PHIGATE_CACHE_TTL", 15*time.Minute)
	c.CacheMax = envInt("PHIGATE_CACHE_MAX", 5000)
	if !c.CacheEnabled {
		c.CacheMax = 0
	}

	// --- Accounting ---
	c.PriceBookPath = os.Getenv("PHIGATE_PRICE_BOOK")
	c.LocalCostPerM = envFloat("PHIGATE_LOCAL_COST_PER_MTOK", 0)

	// --- Observability ---
	c.AuditPath = os.Getenv("PHIGATE_AUDIT_LOG")
	c.AuditDisabled = envBool("PHIGATE_AUDIT_DISABLED", false)
	c.MetricsPath = envOr("PHIGATE_METRICS_PATH", "/metrics")
	c.DebugEnabled = envBool("PHIGATE_DEBUG", false)
	c.DashboardOn = envBool("PHIGATE_DASHBOARD", true)

	// --- Serving ---
	c.ReadHeaderTimeout = envDuration("PHIGATE_READ_HEADER_TIMEOUT", 10*time.Second)
	c.ReadTimeout = envDuration("PHIGATE_READ_TIMEOUT", 60*time.Second)
	c.WriteTimeout = envDuration("PHIGATE_WRITE_TIMEOUT", 0) // 0: streaming responses need an unbounded write
	c.IdleTimeout = envDuration("PHIGATE_IDLE_TIMEOUT", 120*time.Second)
	c.ShutdownGrace = envDuration("PHIGATE_SHUTDOWN_GRACE", 20*time.Second)
	c.MaxBodyBytes = int64(envInt("PHIGATE_MAX_BODY_BYTES", 4<<20))
	c.RateLimitPerMin = envInt("PHIGATE_RATE_LIMIT_PER_MIN", 0)
	c.RateLimitBurst = envInt("PHIGATE_RATE_LIMIT_BURST", 0)
	c.Retries = envInt("PHIGATE_UPSTREAM_RETRIES", 2)
	c.BreakerThreshold = envInt("PHIGATE_BREAKER_THRESHOLD", 5)
	c.BreakerCooldown = envDuration("PHIGATE_BREAKER_COOLDOWN", 30*time.Second)

	return c, nil
}

// backendFromEnv reads one backend's settings under the PHIGATE_<prefix>_ family.
func backendFromEnv(prefix, defBaseURL, defModel string) (Backend, error) {
	p, err := llm.ParseProvider(os.Getenv("PHIGATE_" + prefix + "_PROVIDER"))
	if err != nil {
		return Backend{}, fmt.Errorf("PHIGATE_%s_PROVIDER: %w", prefix, err)
	}
	return Backend{
		Provider:   p,
		BaseURL:    envOr("PHIGATE_"+prefix+"_BASE_URL", defBaseURL),
		Model:      envOr("PHIGATE_"+prefix+"_MODEL", defModel),
		APIKey:     os.Getenv("PHIGATE_" + prefix + "_API_KEY"),
		APIVersion: os.Getenv("PHIGATE_" + prefix + "_API_VERSION"),
		Deployment: os.Getenv("PHIGATE_" + prefix + "_DEPLOYMENT"),
		Timeout:    envDuration("PHIGATE_"+prefix+"_TIMEOUT", 120*time.Second),
	}, nil
}

// parseAPIKeys reads "key1:tenantA,key2:tenantB". A bare key gets the tenant
// label "default".
func parseAPIKeys(s string) map[string]string {
	out := map[string]string{}
	for _, part := range splitList(s) {
		key, tenant, ok := strings.Cut(part, ":")
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if !ok || strings.TrimSpace(tenant) == "" {
			tenant = "default"
		}
		out[key] = strings.TrimSpace(tenant)
	}
	return out
}

// parseGuardOverrides reads "rule=severity,rule=severity".
func parseGuardOverrides(s string) (map[string]sandbox.Severity, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	out := map[string]sandbox.Severity{}
	for _, part := range splitList(s) {
		name, sev, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("PHIGATE_GUARD_SEVERITY: %q is not rule=severity", part)
		}
		s, ok := sandbox.ParseSeverity(sev)
		if !ok {
			return nil, fmt.Errorf("PHIGATE_GUARD_SEVERITY: unknown severity %q (want info|warn|block)", sev)
		}
		out[strings.TrimSpace(name)] = s
	}
	return out, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envFloat(key string, def float64) float64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
