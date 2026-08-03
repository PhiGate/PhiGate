// Package policy decides whether a payload is allowed to leave the building.
//
// Routing and policy are different questions and PhiGate keeps them apart:
//
//   - The router asks "which backend answers this best and cheapest?"
//   - The policy asks "which backends is this payload *permitted* to reach?"
//
// The router's answer is advice. The policy's answer is binding. That ordering
// is what makes PhiGate a control rather than an optimisation: an enterprise can
// state "anything containing a My Number never reaches a cloud provider", and no
// cost heuristic, fallback path, or retry can override it.
//
// The old gateway had exactly that hole. Its local backend failing caused a
// silent retry against the cloud, carrying whatever the local model had been
// trusted with.
package policy

import (
	"fmt"
	"strings"

	"github.com/phigate/phigate/internal/redact"
)

// Action is the verdict for one payload.
type Action int

const (
	// ActionAllow permits any backend, cloud included.
	ActionAllow Action = iota
	// ActionLocalOnly permits only the local SLM. If local cannot serve the
	// request, it fails — it does not fall back.
	ActionLocalOnly
	// ActionDeny refuses the request outright.
	ActionDeny
)

// String renders an Action for logs and audit records.
func (a Action) String() string {
	switch a {
	case ActionLocalOnly:
		return "local_only"
	case ActionDeny:
		return "deny"
	default:
		return "allow"
	}
}

// Decision is a policy verdict with the reason that produced it. Every verdict
// is explainable, because "the gateway blocked it" is not an answer an auditor
// accepts.
type Decision struct {
	Action Action
	// Reason is operator-facing text naming the rule that decided.
	Reason string
	// Sensitivity is the classification that drove the decision.
	Sensitivity redact.Sensitivity
}

// Policy is the configured egress rule set.
type Policy struct {
	// CloudMaxSensitivity is the highest classification permitted to reach a
	// cloud provider. Data above it is confined to the local SLM.
	//
	// The default is SensitivityInternal: masked topology may egress, personal
	// data and credentials may not. This is deliberately stricter than the
	// mathematically-justified setting. Masked values are placeholders and in
	// principle safe to send, but "in principle" is not the standard a
	// Japanese enterprise's compliance officer applies to My Number, and a
	// detector that misses one value must not also be the only thing standing
	// between that value and a third-party API.
	CloudMaxSensitivity redact.Sensitivity

	// DenyAbove refuses the request entirely above this classification.
	// Defaults to a level nothing reaches, i.e. deny is opt-in.
	DenyAbove redact.Sensitivity

	// AllowCloudFallback permits the gateway to retry on the cloud when the
	// local backend fails. It applies only to payloads the policy already
	// cleared for cloud egress; a local-only payload never falls back,
	// whatever this is set to.
	AllowCloudFallback bool
}

// Default returns the recommended policy: masked infrastructure detail may go
// to the cloud, personal data and credentials stay local, and cloud fallback is
// permitted for payloads that were cloud-eligible to begin with.
func Default() Policy {
	return Policy{
		CloudMaxSensitivity: redact.SensitivityInternal,
		DenyAbove:           denyDisabled,
		AllowCloudFallback:  true,
	}
}

// denyDisabled is above every real sensitivity, so DenyAbove never fires unless
// an operator lowers it.
const denyDisabled = redact.Sensitivity(1 << 20)

// Evaluate returns the verdict for a payload whose highest observed
// classification is max.
func (p Policy) Evaluate(max redact.Sensitivity) Decision {
	if max > p.DenyAbove {
		return Decision{
			Action:      ActionDeny,
			Sensitivity: max,
			Reason: fmt.Sprintf("payload classified %s exceeds the deny threshold %s",
				max, p.DenyAbove),
		}
	}
	if max > p.CloudMaxSensitivity {
		return Decision{
			Action:      ActionLocalOnly,
			Sensitivity: max,
			Reason: fmt.Sprintf("payload classified %s exceeds the cloud egress limit %s; "+
				"confined to the local model with no cloud fallback", max, p.CloudMaxSensitivity),
		}
	}
	return Decision{
		Action:      ActionAllow,
		Sensitivity: max,
		Reason:      fmt.Sprintf("payload classified %s is within the cloud egress limit", max),
	}
}

// CloudFallbackAllowed reports whether a failed local call may be retried
// against the cloud, given this decision. A local-only payload never may — that
// is the entire point of the classification.
func (p Policy) CloudFallbackAllowed(d Decision) bool {
	return p.AllowCloudFallback && d.Action == ActionAllow
}

// Parse builds a Policy from configuration strings, reporting unrecognised
// values as errors so a typo in an egress limit fails at startup rather than
// silently widening what may leave the network.
func Parse(cloudMax, denyAbove string, allowFallback bool) (Policy, error) {
	p := Default()
	p.AllowCloudFallback = allowFallback

	if s := strings.TrimSpace(cloudMax); s != "" {
		v, ok := redact.ParseSensitivity(s)
		if !ok {
			return p, fmt.Errorf("invalid cloud egress limit %q (want low|internal|confidential|restricted)", s)
		}
		p.CloudMaxSensitivity = v
	}
	if s := strings.TrimSpace(denyAbove); s != "" && !strings.EqualFold(s, "none") {
		v, ok := redact.ParseSensitivity(s)
		if !ok {
			return p, fmt.Errorf("invalid deny threshold %q (want low|internal|confidential|restricted|none)", s)
		}
		p.DenyAbove = v
	}
	return p, nil
}

// Describe renders the policy for the startup banner and the stats endpoint, so
// the effective rules are visible without reading the config.
func (p Policy) Describe() string {
	deny := "none"
	if p.DenyAbove != denyDisabled {
		deny = "above " + p.DenyAbove.String()
	}
	return fmt.Sprintf("cloud egress ≤ %s; deny %s; cloud fallback %v",
		p.CloudMaxSensitivity, deny, p.AllowCloudFallback)
}
