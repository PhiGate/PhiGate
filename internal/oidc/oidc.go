// Package oidc verifies OpenID Connect ID tokens so an enterprise can
// authenticate to PhiGate with its own identity provider instead of a static
// key PhiGate issued.
//
// # Why this is hand-written
//
// For the reason internal/metrics speaks the Prometheus exposition format
// directly: a gateway that sits in the path of every LLM request is subject to
// a dependency review, and `make ce-purity` asserts the community edition links
// nothing but tree-sitter. Token verification is signature checking and a
// handful of claim comparisons, all of which the standard library already
// provides. Pulling a JOSE library in to reach them would trade an afternoon's
// reading for a supply-chain surface nobody can finish auditing.
//
// # What it checks, and why each one matters
//
// A verifier that skips any of these is worse than no verifier, because it
// looks like authentication:
//
//   - The signature, against a key fetched from the provider's JWKS endpoint.
//   - The algorithm, against an allow list of asymmetric algorithms. "none" is
//     rejected, and so is any HMAC algorithm: a verifier that accepts HS256
//     while holding RSA public keys can be handed a token the attacker signed
//     with the public key as the shared secret, and the public key is public.
//   - The issuer and audience, exactly. A token minted by the right provider
//     for a different application is not a credential for this one.
//   - Expiry and not-before, with a small clock-skew allowance.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// DefaultSkew is the clock difference tolerated between PhiGate and the
// identity provider. Kept small: the failure it covers is NTP drift, not a
// token that expired minutes ago.
const DefaultSkew = 60 * time.Second

// Config describes one trusted identity provider.
type Config struct {
	// Issuer is the exact `iss` a token must carry.
	Issuer string
	// Audience is the exact value that must appear in `aud`.
	Audience string
	// JWKSURL is where signing keys are published. Empty means derive it from
	// the issuer's discovery document.
	JWKSURL string
	// TenantClaim names the claim carrying the caller's group or role, e.g.
	// "groups" or "roles". Its value is looked up in TenantMap.
	TenantClaim string
	// TenantMap maps a claim value to a PhiGate tenant. A token whose claim
	// matches nothing here is rejected rather than admitted as a default
	// tenant: an unmapped group is a configuration the operator has not made,
	// and guessing at it grants access nobody granted.
	TenantMap map[string]string
	// Skew tolerated on exp/nbf. Zero means DefaultSkew.
	Skew time.Duration
}

// Claims is the subset of a verified token PhiGate acts on.
type Claims struct {
	Subject  string
	Issuer   string
	Audience []string
	Tenant   string
	Expiry   time.Time
	// Raw holds every claim, for an operator writing a tenant rule against one
	// this struct does not name.
	Raw map[string]any
}

// ErrNotAToken reports input that is not a JWS compact serialization at all, so
// a caller can fall through to another credential type rather than failing.
var ErrNotAToken = errors.New("oidc: not a JWT")

// Verifier checks tokens against one provider.
type Verifier struct {
	cfg  Config
	keys *keySet
}

// New returns a Verifier. It performs no network I/O; keys are fetched on first
// use so a provider that is briefly unreachable delays a request rather than
// preventing startup.
func New(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oidc: issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("oidc: audience is required; a token minted for another application is not a credential for this one")
	}
	if cfg.TenantClaim == "" {
		return nil, errors.New("oidc: tenant claim is required")
	}
	if len(cfg.TenantMap) == 0 {
		return nil, errors.New("oidc: tenant map is empty, so no token could ever be admitted")
	}
	if cfg.Skew == 0 {
		cfg.Skew = DefaultSkew
	}
	jwks := cfg.JWKSURL
	if jwks == "" {
		jwks = strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/jwks.json"
	}
	return &Verifier{cfg: cfg, keys: newKeySet(jwks)}, nil
}

// LooksLikeJWT reports whether s has the shape of a compact JWS. It is a cheap
// pre-check so a static API key is never sent through token verification, and
// is not itself a security decision.
func LooksLikeJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts[:2] {
		if p == "" {
			return false
		}
	}
	return true
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Verify checks token and returns its claims.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrNotAToken
	}

	rawHeader, err := decodeSegment(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("oidc: header: %w", err)
	}
	var h header
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return Claims{}, fmt.Errorf("oidc: header: %w", err)
	}
	hash, err := algorithm(h.Alg)
	if err != nil {
		return Claims{}, err
	}

	rawPayload, err := decodeSegment(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("oidc: payload: %w", err)
	}
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("oidc: signature: %w", err)
	}

	key, err := v.keys.lookup(ctx, h.Kid)
	if err != nil {
		return Claims{}, err
	}
	signed := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(h.Alg, hash, key, signed, sig); err != nil {
		return Claims{}, err
	}

	return v.claims(rawPayload)
}

// claims validates the registered claims and resolves the tenant. It runs only
// after the signature has been checked; reading a claim from an unverified
// token and acting on it is the mistake this ordering exists to prevent.
func (v *Verifier) claims(payload []byte) (Claims, error) {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Claims{}, fmt.Errorf("oidc: payload: %w", err)
	}

	iss, _ := raw["iss"].(string)
	if iss != v.cfg.Issuer {
		return Claims{}, fmt.Errorf("oidc: issuer %q is not the configured one", iss)
	}
	aud := audienceOf(raw["aud"])
	if !contains(aud, v.cfg.Audience) {
		return Claims{}, fmt.Errorf("oidc: token audience %v does not include %q", aud, v.cfg.Audience)
	}

	now := time.Now()
	exp, ok := unixClaim(raw["exp"])
	if !ok {
		return Claims{}, errors.New("oidc: token has no exp; a credential that never expires is not one")
	}
	if now.After(exp.Add(v.cfg.Skew)) {
		return Claims{}, fmt.Errorf("oidc: token expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if nbf, ok := unixClaim(raw["nbf"]); ok && now.Add(v.cfg.Skew).Before(nbf) {
		return Claims{}, fmt.Errorf("oidc: token not valid until %s", nbf.UTC().Format(time.RFC3339))
	}

	tenant, err := v.tenantOf(raw)
	if err != nil {
		return Claims{}, err
	}
	sub, _ := raw["sub"].(string)
	return Claims{Subject: sub, Issuer: iss, Audience: aud, Tenant: tenant, Expiry: exp, Raw: raw}, nil
}

// tenantOf resolves the configured claim to a tenant.
func (v *Verifier) tenantOf(raw map[string]any) (string, error) {
	val, ok := raw[v.cfg.TenantClaim]
	if !ok {
		return "", fmt.Errorf("oidc: token carries no %q claim", v.cfg.TenantClaim)
	}
	for _, candidate := range stringsOf(val) {
		if tenant, ok := v.cfg.TenantMap[candidate]; ok {
			return tenant, nil
		}
	}
	// Deliberately not a default tenant. An unmapped group is a decision the
	// operator has not made, and inventing one grants access nobody granted.
	return "", fmt.Errorf("oidc: no value of %q maps to a tenant", v.cfg.TenantClaim)
}

// algorithm returns the hash for alg, rejecting everything that is not an
// asymmetric signature over one of the SHA-2 sizes.
func algorithm(alg string) (crypto.Hash, error) {
	switch alg {
	case "RS256", "PS256", "ES256":
		return crypto.SHA256, nil
	case "RS384", "PS384", "ES384":
		return crypto.SHA384, nil
	case "RS512", "PS512", "ES512":
		return crypto.SHA512, nil
	case "", "none":
		return 0, errors.New(`oidc: token is unsigned ("alg":"none")`)
	case "HS256", "HS384", "HS512":
		// Algorithm confusion: a verifier holding RSA public keys that accepts
		// an HMAC alg can be handed a token signed with the public key as the
		// shared secret. The public key is public.
		return 0, fmt.Errorf("oidc: %s is symmetric and not accepted against a public key set", alg)
	default:
		return 0, fmt.Errorf("oidc: unsupported algorithm %q", alg)
	}
}

func verifySignature(alg string, hash crypto.Hash, key any, signed, sig []byte) error {
	var digest []byte
	switch hash {
	case crypto.SHA256:
		sum := sha256.Sum256(signed)
		digest = sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(signed)
		digest = sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(signed)
		digest = sum[:]
	default:
		return fmt.Errorf("oidc: unsupported hash for %s", alg)
	}

	switch k := key.(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "PS") {
			if err := rsa.VerifyPSS(k, hash, digest, sig, nil); err != nil {
				return fmt.Errorf("oidc: signature does not verify: %w", err)
			}
			return nil
		}
		if !strings.HasPrefix(alg, "RS") {
			return fmt.Errorf("oidc: %s cannot be verified with an RSA key", alg)
		}
		if err := rsa.VerifyPKCS1v15(k, hash, digest, sig); err != nil {
			return fmt.Errorf("oidc: signature does not verify: %w", err)
		}
		return nil
	case *ecdsa.PublicKey:
		if !strings.HasPrefix(alg, "ES") {
			return fmt.Errorf("oidc: %s cannot be verified with an EC key", alg)
		}
		// JWS ECDSA signatures are R||S, each padded to the curve size.
		n := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			return errors.New("oidc: malformed ECDSA signature")
		}
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		if !ecdsa.Verify(k, digest, r, s) {
			return errors.New("oidc: signature does not verify")
		}
		return nil
	default:
		return errors.New("oidc: unsupported key type")
	}
}

func decodeSegment(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func audienceOf(v any) []string { return stringsOf(v) }

func stringsOf(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func unixClaim(v any) (time.Time, bool) {
	switch t := v.(type) {
	case float64:
		return time.Unix(int64(t), 0), true
	case int64:
		return time.Unix(t, 0), true
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(n, 0), true
	default:
		return time.Time{}, false
	}
}
