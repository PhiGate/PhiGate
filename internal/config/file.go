package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/phigate/phigate/internal/llm"
	"github.com/phigate/phigate/internal/policy"
	"github.com/phigate/phigate/internal/sandbox"
)

// ApplyFile reads a JSON configuration file and overrides c wherever it
// specifies a value.
//
// # Every field is a pointer
//
// A configuration file has to distinguish "set this to false" from "did not
// mention it". With plain values it cannot: `cache.enabled` omitted and
// `cache.enabled: false` both decode to false, so writing a file to change one
// setting would silently switch off every boolean the author left out. Pointers
// make absence its own value, which is why the shapes below look the way they
// do rather than reusing Config directly.
//
// Unknown keys are an error. The package doc's "fail loudly" rule exists
// because a typo must not quietly disable a control an auditor was told is
// enforced, and `"cloud_max_sensitvity": "low"` accepted and ignored is exactly
// that failure.
func ApplyFile(c *Config, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	var f fileConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return fmt.Errorf("parse config file %s: %w", path, err)
	}
	return f.apply(c, path)
}

type fileConfig struct {
	Addr           *string `json:"addr"`
	SystemPreamble *string `json:"system_preamble"`

	Local *fileBackend `json:"local"`
	Cloud *fileBackend `json:"cloud"`

	APIKeys            map[string]string `json:"api_keys"`
	AllowAnonymous     *bool             `json:"allow_anonymous"`
	TrustedProxyHeader *string           `json:"trusted_proxy_header"`

	Tenants map[string]fileTenant `json:"tenants"`

	Redact *fileRedact `json:"redact"`
	Policy *filePolicy `json:"policy"`
	Guard  *fileGuard  `json:"guard"`

	Session *fileSession `json:"session"`
	Cache   *fileCache   `json:"cache"`

	PriceBook     *string  `json:"price_book"`
	LocalCostPerM *float64 `json:"local_cost_per_mtok"`

	Audit     *fileAudit `json:"audit"`
	Metrics   *string    `json:"metrics_path"`
	Debug     *bool      `json:"debug"`
	Dashboard *bool      `json:"dashboard"`

	Serving *fileServing `json:"serving"`

	BudgetPeriod   *string `json:"budget_period"`
	BudgetTimezone *string `json:"budget_timezone"`
}

type fileBackend struct {
	Provider   *string `json:"provider"`
	BaseURL    *string `json:"base_url"`
	Model      *string `json:"model"`
	APIKey     *string `json:"api_key"`
	APIVersion *string `json:"api_version"`
	Deployment *string `json:"deployment"`
	Timeout    *string `json:"timeout"`
}

type filePolicy struct {
	CloudMaxSensitivity  *string `json:"cloud_max_sensitivity"`
	DenyAboveSensitivity *string `json:"deny_above_sensitivity"`
	AllowCloudFallback   *bool   `json:"allow_cloud_fallback"`
}

type fileRedact struct {
	Packs           []string `json:"packs"`
	RuleDir         *string  `json:"rule_dir"`
	Disable         []string `json:"disable"`
	InternalDomains []string `json:"internal_domains"`
	DisableEntropy  *bool    `json:"disable_entropy"`
}

type fileGuard struct {
	Severity           map[string]string `json:"severity"`
	IngressScan        *bool             `json:"ingress_scan"`
	EnumerationMinDict *int              `json:"enumeration_min_dictionary"`
	StreamMode         *string           `json:"stream_mode"`
	StreamMaxBuffer    *int              `json:"stream_max_buffer"`
}

type fileSession struct {
	TTL    *string `json:"ttl"`
	Max    *int    `json:"max"`
	Header *string `json:"header"`
}

type fileCache struct {
	Enabled *bool   `json:"enabled"`
	TTL     *string `json:"ttl"`
	Max     *int    `json:"max"`
}

type fileAudit struct {
	Path     *string `json:"path"`
	Disabled *bool   `json:"disabled"`
}

type fileServing struct {
	ReadHeaderTimeout *string `json:"read_header_timeout"`
	ReadTimeout       *string `json:"read_timeout"`
	WriteTimeout      *string `json:"write_timeout"`
	IdleTimeout       *string `json:"idle_timeout"`
	ShutdownGrace     *string `json:"shutdown_grace"`
	MaxBodyBytes      *int64  `json:"max_body_bytes"`
	RateLimitPerMin   *int    `json:"rate_limit_per_min"`
	RateLimitBurst    *int    `json:"rate_limit_burst"`
	Retries           *int    `json:"upstream_retries"`
	BreakerThreshold  *int    `json:"breaker_threshold"`
	BreakerCooldown   *string `json:"breaker_cooldown"`
}

type fileTenant struct {
	Policy          *filePolicy `json:"policy"`
	RateLimitPerMin *int        `json:"rate_limit_per_min"`
	RateLimitBurst  *int        `json:"rate_limit_burst"`
	RedactPacks     []string    `json:"redact_packs"`
	DisableRules    []string    `json:"redact_disable"`
	InternalDomains []string    `json:"internal_domains"`
	TokenBudget     *int64      `json:"token_budget"`
}

func (f fileConfig) apply(c *Config, path string) error {
	assign(&c.Addr, f.Addr)
	assign(&c.SystemPreamble, f.SystemPreamble)

	if err := f.Local.apply(&c.Local, "local"); err != nil {
		return err
	}
	if err := f.Cloud.apply(&c.Cloud, "cloud"); err != nil {
		return err
	}

	if f.APIKeys != nil {
		c.APIKeys = map[string]string{}
		for key, tenant := range f.APIKeys {
			if tenant == "" {
				tenant = "default"
			}
			c.APIKeys[key] = tenant
		}
	}
	assign(&c.AllowAnonymous, f.AllowAnonymous)
	assign(&c.TrustedProxyHeader, f.TrustedProxyHeader)

	if f.Redact != nil {
		assignList(&c.RedactPacks, f.Redact.Packs)
		assign(&c.RedactRuleDir, f.Redact.RuleDir)
		assignList(&c.DisableRules, f.Redact.Disable)
		assignList(&c.InternalDomains, f.Redact.InternalDomains)
		assign(&c.DisableEntropy, f.Redact.DisableEntropy)
	}

	if f.Policy != nil {
		p, err := f.Policy.parse(c.Policy, "policy")
		if err != nil {
			return err
		}
		c.Policy = p
	}

	if f.Guard != nil {
		if f.Guard.Severity != nil {
			out := map[string]sandbox.Severity{}
			for rule, sev := range f.Guard.Severity {
				s, ok := sandbox.ParseSeverity(sev)
				if !ok {
					return fmt.Errorf("guard.severity[%q]: unknown severity %q (want info|warn|block)", rule, sev)
				}
				out[rule] = s
			}
			c.GuardOverrides = out
		}
		assign(&c.IngressScan, f.Guard.IngressScan)
		assign(&c.Enumeration.MinDictionary, f.Guard.EnumerationMinDict)
		if f.Guard.StreamMode != nil {
			m, ok := sandbox.ParseMode(*f.Guard.StreamMode)
			if !ok {
				return fmt.Errorf("guard.stream_mode: %q is not commit|strict", *f.Guard.StreamMode)
			}
			c.StreamMode = m
		}
		assign(&c.StreamMaxBuffer, f.Guard.StreamMaxBuffer)
	}

	if f.Session != nil {
		if err := assignDuration(&c.SessionTTL, f.Session.TTL, "session.ttl"); err != nil {
			return err
		}
		assign(&c.SessionMax, f.Session.Max)
		assign(&c.SessionHeader, f.Session.Header)
	}

	if f.Cache != nil {
		assign(&c.CacheEnabled, f.Cache.Enabled)
		if err := assignDuration(&c.CacheTTL, f.Cache.TTL, "cache.ttl"); err != nil {
			return err
		}
		assign(&c.CacheMax, f.Cache.Max)
	}

	assign(&c.BudgetPeriod, f.BudgetPeriod)
	assign(&c.BudgetTimezone, f.BudgetTimezone)
	assign(&c.PriceBookPath, f.PriceBook)
	assign(&c.LocalCostPerM, f.LocalCostPerM)

	if f.Audit != nil {
		assign(&c.AuditPath, f.Audit.Path)
		assign(&c.AuditDisabled, f.Audit.Disabled)
	}
	assign(&c.MetricsPath, f.Metrics)
	assign(&c.DebugEnabled, f.Debug)
	assign(&c.DashboardOn, f.Dashboard)

	if s := f.Serving; s != nil {
		for _, d := range []struct {
			dst  *time.Duration
			src  *string
			name string
		}{
			{&c.ReadHeaderTimeout, s.ReadHeaderTimeout, "serving.read_header_timeout"},
			{&c.ReadTimeout, s.ReadTimeout, "serving.read_timeout"},
			{&c.WriteTimeout, s.WriteTimeout, "serving.write_timeout"},
			{&c.IdleTimeout, s.IdleTimeout, "serving.idle_timeout"},
			{&c.ShutdownGrace, s.ShutdownGrace, "serving.shutdown_grace"},
			{&c.BreakerCooldown, s.BreakerCooldown, "serving.breaker_cooldown"},
		} {
			if err := assignDuration(d.dst, d.src, d.name); err != nil {
				return err
			}
		}
		assign(&c.MaxBodyBytes, s.MaxBodyBytes)
		assign(&c.RateLimitPerMin, s.RateLimitPerMin)
		assign(&c.RateLimitBurst, s.RateLimitBurst)
		assign(&c.Retries, s.Retries)
		assign(&c.BreakerThreshold, s.BreakerThreshold)
	}

	if f.Tenants != nil {
		c.Tenants = map[string]Tenant{}
		for name, ft := range f.Tenants {
			t := Tenant{
				RedactPacks:     ft.RedactPacks,
				DisableRules:    ft.DisableRules,
				InternalDomains: ft.InternalDomains,
			}
			assign(&t.RateLimitPerMin, ft.RateLimitPerMin)
			assign(&t.RateLimitBurst, ft.RateLimitBurst)
			assign(&t.TokenBudget, ft.TokenBudget)
			if ft.Policy != nil {
				// A tenant's policy starts from the global one, so a block that
				// names only cloud_max_sensitivity does not silently reset the
				// tenant's deny threshold and fallback rule to their defaults.
				p, err := ft.Policy.parse(c.Policy, "tenants."+name+".policy")
				if err != nil {
					return err
				}
				t.Policy = &p
			}
			c.Tenants[name] = t
		}
	}

	// Relative paths in a config file are resolved against nothing in
	// particular today; recording where the file came from at least lets an
	// error message name it.
	_ = path
	return nil
}

func (b *fileBackend) apply(dst *Backend, name string) error {
	if b == nil {
		return nil
	}
	if b.Provider != nil {
		p, err := llm.ParseProvider(*b.Provider)
		if err != nil {
			return fmt.Errorf("%s.provider: %w", name, err)
		}
		dst.Provider = p
	}
	assign(&dst.BaseURL, b.BaseURL)
	assign(&dst.Model, b.Model)
	assign(&dst.APIKey, b.APIKey)
	assign(&dst.APIVersion, b.APIVersion)
	assign(&dst.Deployment, b.Deployment)
	return assignDuration(&dst.Timeout, b.Timeout, name+".timeout")
}

// parse turns a file policy block into a policy, starting from base so an
// omitted field keeps what it inherited rather than reverting to a default.
func (p *filePolicy) parse(base policy.Policy, name string) (policy.Policy, error) {
	cloudMax := base.CloudMaxSensitivity.String()
	if p.CloudMaxSensitivity != nil {
		cloudMax = *p.CloudMaxSensitivity
	}
	denyAbove := ""
	if base.DenyAbove != policy.Default().DenyAbove {
		denyAbove = base.DenyAbove.String()
	}
	if p.DenyAboveSensitivity != nil {
		denyAbove = *p.DenyAboveSensitivity
	}
	fallback := base.AllowCloudFallback
	if p.AllowCloudFallback != nil {
		fallback = *p.AllowCloudFallback
	}
	out, err := policy.Parse(cloudMax, denyAbove, fallback)
	if err != nil {
		return base, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

func assign[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

func assignList(dst *[]string, src []string) {
	if src != nil {
		*dst = src
	}
}

func assignDuration(dst *time.Duration, src *string, name string) error {
	if src == nil {
		return nil
	}
	d, err := time.ParseDuration(*src)
	if err != nil {
		return fmt.Errorf("%s: %q is not a duration (e.g. \"15m\", \"30s\"): %w", name, *src, err)
	}
	*dst = d
	return nil
}
