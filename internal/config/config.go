// Package config loads PhiGate's runtime configuration.
//
// Three principles govern it:
//
//   - **Safe by default.** Anything that could widen what leaves the network is
//     off unless switched on. The debug endpoint, which discloses raw values, is
//     the clearest case: it now requires an explicit opt-in, because shipping it
//     enabled meant every deployment exposed an unauthenticated endpoint that
//     printed the plaintext of everything it had masked.
//   - **Fail loudly.** A malformed policy threshold or an unknown rule pack is a
//     startup error, never a silent fallback. A typo must not quietly disable a
//     control that an auditor was told is enforced. The file loader goes further
//     and rejects unknown keys outright, because a misspelled key in a file is
//     the same failure as a misspelled rule name.
//   - **One source of truth per value.** Settings come from defaults, then a
//     file, then the environment, in that order — see FromEnv.
//
// # Why the file is JSON
//
// The community edition's go.mod lists one third-party dependency and that is
// the property a customer's security review checks, so a configuration format
// is not worth a YAML parser. JSON is also already this project's format for
// rule packs and the price book, so the file loader adds no new convention.
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

// Tenant overrides global settings for the clients holding one tenant's API
// keys.
//
// Before this existed the tenant label was only that — a label, used for rate
// limiting and the audit record. Every control was global, so an SIer running
// one gateway for a customer's finance department and its SRE team had to
// deploy two gateways to give them different egress policies.
//
// Only the fields a tenant may narrow are here. A tenant cannot be given its
// own backends or its own audit destination: those are the operator's, and a
// per-tenant audit sink would let one tenant's configuration decide whether its
// own actions are recorded.
type Tenant struct {
	// Policy replaces the global egress policy for this tenant. Nil inherits.
	Policy *policy.Policy

	// RateLimitPerMin and RateLimitBurst replace the global limits. Zero
	// inherits; a tenant cannot raise a limit it was not granted, which
	// validate enforces.
	RateLimitPerMin int
	RateLimitBurst  int

	// RedactPacks, DisableRules and InternalDomains replace the global
	// detection settings. Empty inherits.
	RedactPacks     []string
	DisableRules    []string
	InternalDomains []string

	// TokenBudget caps the tokens this tenant may spend in a budget period.
	// Zero means unlimited.
	//
	// It bounds spend, where RateLimitPerMin bounds arrival rate. They are not
	// substitutes: a hundred well-spaced requests carrying a megabyte each
	// pass any rate limit and are what an unexpected invoice is made of.
	TokenBudget int64
}

// Config holds every setting for the gateway.
type Config struct {
	Addr string

	// Path is the configuration file this was loaded from, empty when the
	// configuration came from the environment alone. Reload reads it again.
	Path string

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

	// Tenants holds per-tenant overrides, keyed by the tenant label APIKeys
	// maps to. A label with no entry here uses the global settings.
	Tenants map[string]Tenant

	// BudgetPeriod is how often token budgets reset: "daily" or "monthly".
	BudgetPeriod string
	// BudgetTimezone is the zone period boundaries are computed in.
	//
	// It defaults to Asia/Tokyo rather than UTC because a budget period is a
	// billing period, and a Japanese customer's month ends at midnight JST. A
	// month that rolled over at 09:00 local time would put nine hours of every
	// month-end in the wrong month.
	BudgetTimezone string

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

	// StreamMode selects how much of a streaming answer the egress scanner
	// releases before the answer ends. The default releases prose as it
	// arrives and holds anything whose verdict is unsettled; "strict" holds
	// the whole answer and inspects it once, giving up streaming entirely.
	StreamMode sandbox.Mode
	// StreamMaxBuffer bounds the text held for an unterminated code fence.
	StreamMaxBuffer int

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

// Defaults returns the configuration PhiGate runs with when nothing is set.
//
// It is separated from FromEnv so that both the file and the environment layer
// onto the same base, and so a reload starts from the same place a cold start
// does rather than from whatever the running process happens to hold.
func Defaults() Config {
	return Config{
		Addr:           ":8080",
		SystemPreamble: DefaultSystemPreamble,

		Local: Backend{
			BaseURL: "http://localhost:11434/v1",
			Model:   "phi4-mini",
			Timeout: 120 * time.Second,
		},
		Cloud: Backend{
			BaseURL: "https://api.openai.com/v1",
			Model:   "gpt-4o",
			Timeout: 120 * time.Second,
		},

		APIKeys:         map[string]string{},
		Tenants:         map[string]Tenant{},
		InternalDomains: []string{"internal", "corp", "local", "lan", "intra"},

		Policy: policy.Default(),

		BudgetPeriod:   "monthly",
		BudgetTimezone: "Asia/Tokyo",

		IngressScan:     true,
		Enumeration:     sandbox.DefaultEnumerationThreshold(),
		StreamMaxBuffer: sandbox.DefaultMaxBuffer,

		SessionTTL:    30 * time.Minute,
		SessionMax:    10000,
		SessionHeader: "X-PhiGate-Session",
		CacheEnabled:  true,
		CacheTTL:      15 * time.Minute,
		CacheMax:      5000,

		MetricsPath: "/metrics",
		DashboardOn: true,

		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      0, // streaming responses need an unbounded write
		IdleTimeout:       120 * time.Second,
		ShutdownGrace:     20 * time.Second,
		MaxBodyBytes:      4 << 20,
		Retries:           2,
		BreakerThreshold:  5,
		BreakerCooldown:   30 * time.Second,
	}
}

// FromEnv builds a Config from defaults, then the file named by PHIGATE_CONFIG
// if one is set, then the environment.
//
// # Why the environment wins
//
// The file is the declared state: version-controlled, reviewed, the thing an
// auditor reads. The environment is where a container's secrets live and where
// an operator reaches during an incident. Letting the file win would mean an
// emergency `PHIGATE_CLOUD_MAX_SENSITIVITY=low` was silently ignored because a
// checked-in file said otherwise, which is the wrong way round for a control
// that exists to be tightened in a hurry.
func FromEnv() (Config, error) {
	c := Defaults()

	if path := strings.TrimSpace(os.Getenv("PHIGATE_CONFIG")); path != "" {
		if err := ApplyFile(&c, path); err != nil {
			return c, err
		}
		c.Path = path
	}
	if err := applyEnv(&c); err != nil {
		return c, err
	}
	return c, Validate(&c)
}

// Reload re-reads the configuration a running gateway was started with,
// producing a fresh Config without touching the live one.
//
// The caller swaps it in only if it is returned without error, which is what
// makes a malformed edit a no-op rather than a partially-applied change: the
// whole configuration is built and validated before any of it takes effect.
func Reload(current Config) (Config, error) {
	c := Defaults()
	if current.Path != "" {
		if err := ApplyFile(&c, current.Path); err != nil {
			return c, err
		}
		c.Path = current.Path
	}
	if err := applyEnv(&c); err != nil {
		return c, err
	}
	return c, Validate(&c)
}

// Validate rejects a configuration that would run but should not.
func Validate(c *Config) error {
	if len(c.APIKeys) == 0 && !c.AllowAnonymous {
		return fmt.Errorf(
			"no client credentials configured: set PHIGATE_API_KEYS=\"key:tenant,...\" " +
				"(or api_keys in the config file) or set PHIGATE_ALLOW_ANONYMOUS=true to " +
				"accept that anyone who can reach this port can spend your upstream API quota")
	}

	// Every tenant named in the tenants block must be reachable by some key,
	// or its overrides are settings nobody is subject to — most likely a typo
	// in the label, which would silently leave that tenant on the global
	// policy it was meant to be narrowed away from.
	labels := map[string]bool{}
	for _, tenant := range c.APIKeys {
		labels[tenant] = true
	}
	if c.AllowAnonymous {
		labels["anonymous"] = true
	}
	for name := range c.Tenants {
		if !labels[name] {
			return fmt.Errorf("tenant %q has overrides but no API key maps to it", name)
		}
	}

	// Normalise before checking. A Config assembled in code rather than loaded
	// from a file or the environment — which is how the tests and the
	// enterprise binary build one — should not have to restate a default in
	// order to be valid.
	if c.BudgetPeriod == "" {
		c.BudgetPeriod = "monthly"
	}
	if c.BudgetTimezone == "" {
		c.BudgetTimezone = "Asia/Tokyo"
	}
	switch c.BudgetPeriod {
	case "daily", "monthly":
	default:
		return fmt.Errorf("budget_period %q is not daily or monthly", c.BudgetPeriod)
	}
	if _, err := time.LoadLocation(c.BudgetTimezone); err != nil {
		return fmt.Errorf("budget_timezone %q: %w", c.BudgetTimezone, err)
	}

	// A tenant may narrow what it can reach, never widen it. Otherwise the
	// global policy stops being the ceiling an operator thinks it is.
	for name, t := range c.Tenants {
		if t.Policy == nil {
			continue
		}
		if t.Policy.CloudMaxSensitivity > c.Policy.CloudMaxSensitivity {
			return fmt.Errorf(
				"tenant %q sets cloud_max_sensitivity=%s, above the global limit of %s: "+
					"a tenant may narrow what may leave the network, never widen it",
				name, t.Policy.CloudMaxSensitivity, c.Policy.CloudMaxSensitivity)
		}
	}
	return nil
}

// BudgetFor returns a tenant's token budget, or zero when it has none.
func (c *Config) BudgetFor(tenant string) int64 {
	if t, ok := c.Tenants[tenant]; ok {
		return t.TokenBudget
	}
	return 0
}

// AnyBudget reports whether any tenant is budgeted at all, so a deployment
// with none pays for no bookkeeping.
func (c *Config) AnyBudget() bool {
	for _, t := range c.Tenants {
		if t.TokenBudget > 0 {
			return true
		}
	}
	return false
}

// PeriodStart returns the beginning of the budget period containing now.
//
// The period is closed at its start and open at its end, so a request landing
// exactly on the boundary belongs to the new period. That is the direction a
// customer expects a monthly limit to reset in.
func (c *Config) PeriodStart(now time.Time) time.Time {
	zone := c.BudgetTimezone
	if zone == "" {
		zone = "Asia/Tokyo"
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		// Validate rejects an unknown zone at startup, so this is unreachable
		// from a configured gateway. Falling back to UTC rather than panicking
		// keeps a budget bounded by *something* if it ever is reached.
		loc = time.UTC
	}
	t := now.In(loc)
	if c.BudgetPeriod == "daily" {
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
	}
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, loc)
}

// PolicyFor returns the egress policy in force for a tenant.
func (c *Config) PolicyFor(tenant string) policy.Policy {
	if t, ok := c.Tenants[tenant]; ok && t.Policy != nil {
		return *t.Policy
	}
	return c.Policy
}

// RateLimitFor returns the per-minute limit and burst in force for a tenant.
func (c *Config) RateLimitFor(tenant string) (perMin, burst int) {
	perMin, burst = c.RateLimitPerMin, c.RateLimitBurst
	if t, ok := c.Tenants[tenant]; ok {
		if t.RateLimitPerMin > 0 {
			perMin = t.RateLimitPerMin
		}
		if t.RateLimitBurst > 0 {
			burst = t.RateLimitBurst
		}
	}
	return perMin, burst
}

// RedactionFor returns the detection settings in force for a tenant.
func (c *Config) RedactionFor(tenant string) (packs, disable, domains []string) {
	packs, disable, domains = c.RedactPacks, c.DisableRules, c.InternalDomains
	if t, ok := c.Tenants[tenant]; ok {
		if len(t.RedactPacks) > 0 {
			packs = t.RedactPacks
		}
		if len(t.DisableRules) > 0 {
			disable = t.DisableRules
		}
		if len(t.InternalDomains) > 0 {
			domains = t.InternalDomains
		}
	}
	return packs, disable, domains
}

// TenantLabels returns every tenant label an API key maps to, plus "anonymous"
// when anonymous access is permitted. The gateway builds one detection engine
// per label from this.
func (c *Config) TenantLabels() []string {
	seen := map[string]bool{}
	var out []string
	for _, tenant := range c.APIKeys {
		if !seen[tenant] {
			seen[tenant] = true
			out = append(out, tenant)
		}
	}
	if c.AllowAnonymous && !seen["anonymous"] {
		out = append(out, "anonymous")
	}
	return out
}

// applyEnv overrides c wherever an environment variable is present.
//
// Absence and emptiness both mean "leave what is there", so a file setting is
// not wiped by an unset variable, and the behaviour with no file is identical
// to what the environment alone produced before files existed.
func applyEnv(c *Config) error {
	setStr(&c.Addr, "PHIGATE_ADDR")
	setStr(&c.SystemPreamble, "PHIGATE_SYSTEM_PREAMBLE")

	if err := backendFromEnv(&c.Local, "LOCAL"); err != nil {
		return err
	}
	if err := backendFromEnv(&c.Cloud, "CLOUD"); err != nil {
		return err
	}
	if c.Cloud.APIKey == "" {
		c.Cloud.APIKey = os.Getenv("OPENAI_API_KEY")
	}

	// --- Access control ---
	if v, ok := os.LookupEnv("PHIGATE_API_KEYS"); ok && strings.TrimSpace(v) != "" {
		c.APIKeys = parseAPIKeys(v)
	}
	setBool(&c.AllowAnonymous, "PHIGATE_ALLOW_ANONYMOUS")
	setStr(&c.TrustedProxyHeader, "PHIGATE_TRUSTED_PROXY_HEADER")

	// --- Redaction ---
	setList(&c.RedactPacks, "PHIGATE_REDACT_PACKS")
	setStr(&c.RedactRuleDir, "PHIGATE_REDACT_RULE_DIR")
	setList(&c.DisableRules, "PHIGATE_REDACT_DISABLE")
	setList(&c.InternalDomains, "PHIGATE_INTERNAL_DOMAINS")
	setBool(&c.DisableEntropy, "PHIGATE_REDACT_DISABLE_ENTROPY")

	// --- Egress policy ---
	// Parse takes all three together, so the current values stand in for any
	// variable that is unset rather than resetting the policy to its default.
	cloudMax, denyAbove := "", ""
	if v, ok := os.LookupEnv("PHIGATE_CLOUD_MAX_SENSITIVITY"); ok {
		cloudMax = v
	} else {
		cloudMax = c.Policy.CloudMaxSensitivity.String()
	}
	if v, ok := os.LookupEnv("PHIGATE_DENY_ABOVE_SENSITIVITY"); ok {
		denyAbove = v
	} else if c.Policy.DenyAbove != policy.Default().DenyAbove {
		denyAbove = c.Policy.DenyAbove.String()
	}
	fallback := c.Policy.AllowCloudFallback
	setBool(&fallback, "PHIGATE_ALLOW_CLOUD_FALLBACK")

	p, err := policy.Parse(cloudMax, denyAbove, fallback)
	if err != nil {
		return err
	}
	c.Policy = p

	// --- Guardrails ---
	if v, ok := os.LookupEnv("PHIGATE_GUARD_SEVERITY"); ok && strings.TrimSpace(v) != "" {
		o, err := parseGuardOverrides(v)
		if err != nil {
			return err
		}
		c.GuardOverrides = o
	}
	setBool(&c.IngressScan, "PHIGATE_INGRESS_SCAN")
	setInt(&c.Enumeration.MinDictionary, "PHIGATE_ENUMERATION_MIN_DICT")
	if s := os.Getenv("PHIGATE_STREAM_MODE"); s != "" {
		m, ok := sandbox.ParseMode(s)
		if !ok {
			return fmt.Errorf("invalid stream mode %q (want commit|strict)", s)
		}
		c.StreamMode = m
	}
	setInt(&c.StreamMaxBuffer, "PHIGATE_STREAM_MAX_BUFFER")

	// --- Sessions and cache ---
	setDuration(&c.SessionTTL, "PHIGATE_SESSION_TTL")
	setInt(&c.SessionMax, "PHIGATE_SESSION_MAX")
	setStr(&c.SessionHeader, "PHIGATE_SESSION_HEADER")
	setBool(&c.CacheEnabled, "PHIGATE_CACHE_ENABLED")
	setDuration(&c.CacheTTL, "PHIGATE_CACHE_TTL")
	setInt(&c.CacheMax, "PHIGATE_CACHE_MAX")
	if !c.CacheEnabled {
		c.CacheMax = 0
	}

	// --- Accounting ---
	setStr(&c.PriceBookPath, "PHIGATE_PRICE_BOOK")
	setFloat(&c.LocalCostPerM, "PHIGATE_LOCAL_COST_PER_MTOK")

	// --- Observability ---
	setStr(&c.AuditPath, "PHIGATE_AUDIT_LOG")
	setBool(&c.AuditDisabled, "PHIGATE_AUDIT_DISABLED")
	setStr(&c.MetricsPath, "PHIGATE_METRICS_PATH")
	setBool(&c.DebugEnabled, "PHIGATE_DEBUG")
	setBool(&c.DashboardOn, "PHIGATE_DASHBOARD")

	// --- Serving ---
	setDuration(&c.ReadHeaderTimeout, "PHIGATE_READ_HEADER_TIMEOUT")
	setDuration(&c.ReadTimeout, "PHIGATE_READ_TIMEOUT")
	setDuration(&c.WriteTimeout, "PHIGATE_WRITE_TIMEOUT")
	setDuration(&c.IdleTimeout, "PHIGATE_IDLE_TIMEOUT")
	setDuration(&c.ShutdownGrace, "PHIGATE_SHUTDOWN_GRACE")
	if v, ok := os.LookupEnv("PHIGATE_MAX_BODY_BYTES"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			c.MaxBodyBytes = int64(n)
		}
	}
	setStr(&c.BudgetPeriod, "PHIGATE_BUDGET_PERIOD")
	setStr(&c.BudgetTimezone, "PHIGATE_BUDGET_TIMEZONE")
	setInt(&c.RateLimitPerMin, "PHIGATE_RATE_LIMIT_PER_MIN")
	setInt(&c.RateLimitBurst, "PHIGATE_RATE_LIMIT_BURST")
	setInt(&c.Retries, "PHIGATE_UPSTREAM_RETRIES")
	setInt(&c.BreakerThreshold, "PHIGATE_BREAKER_THRESHOLD")
	setDuration(&c.BreakerCooldown, "PHIGATE_BREAKER_COOLDOWN")

	return nil
}

// backendFromEnv overrides one backend from the PHIGATE_<prefix>_ family.
func backendFromEnv(b *Backend, prefix string) error {
	if v, ok := os.LookupEnv("PHIGATE_" + prefix + "_PROVIDER"); ok && strings.TrimSpace(v) != "" {
		p, err := llm.ParseProvider(v)
		if err != nil {
			return fmt.Errorf("PHIGATE_%s_PROVIDER: %w", prefix, err)
		}
		b.Provider = p
	}
	setStr(&b.BaseURL, "PHIGATE_"+prefix+"_BASE_URL")
	setStr(&b.Model, "PHIGATE_"+prefix+"_MODEL")
	setStr(&b.APIKey, "PHIGATE_"+prefix+"_API_KEY")
	setStr(&b.APIVersion, "PHIGATE_"+prefix+"_API_VERSION")
	setStr(&b.Deployment, "PHIGATE_"+prefix+"_DEPLOYMENT")
	setDuration(&b.Timeout, "PHIGATE_"+prefix+"_TIMEOUT")
	return nil
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

// The setters below all leave the destination alone when the variable is absent
// or empty, and — preserving the behaviour these replace — when it is present
// but malformed.

func setStr(dst *string, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}

func setBool(dst *bool, key string) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return
	}
	if b, err := strconv.ParseBool(v); err == nil {
		*dst = b
	}
}

func setInt(dst *int, key string) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return
	}
	if n, err := strconv.Atoi(v); err == nil {
		*dst = n
	}
}

func setFloat(dst *float64, key string) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		*dst = f
	}
}

func setDuration(dst *time.Duration, key string) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return
	}
	if d, err := time.ParseDuration(v); err == nil {
		*dst = d
	}
}

func setList(dst *[]string, key string) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return
	}
	*dst = splitList(v)
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
