package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- test provider -----------------------------------------------------

type provider struct {
	key    *rsa.PrivateKey
	kid    string
	server *httptest.Server
	hits   int
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &provider{key: key, kid: "test-key-1"}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.hits++
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": p.kid,
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(p.server.Close)
	return p
}

func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// sign mints a token. Nothing here validates the inputs, which is the point:
// the tests need to produce the tokens a hostile client would.
func (p *provider) sign(t *testing.T, hdr, claims map[string]any) string {
	t.Helper()
	signing := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (p *provider) verifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := New(Config{
		Issuer: "https://idp.example.com", Audience: "phigate",
		JWKSURL: p.server.URL, TenantClaim: "groups",
		TenantMap: map[string]string{"sre-team": "team-sre"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func goodHeader(kid string) map[string]any {
	return map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
}

func goodClaims() map[string]any {
	return map[string]any{
		"iss": "https://idp.example.com", "aud": "phigate", "sub": "svc-aiops",
		"groups": []string{"sre-team"}, "exp": time.Now().Add(time.Hour).Unix(),
	}
}

// --- the happy path ----------------------------------------------------

func TestVerifyAcceptsAWellFormedToken(t *testing.T) {
	p := newProvider(t)
	got, err := p.verifier(t).Verify(context.Background(), p.sign(t, goodHeader(p.kid), goodClaims()))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if got.Tenant != "team-sre" {
		t.Errorf("tenant = %q, want team-sre", got.Tenant)
	}
	if got.Subject != "svc-aiops" {
		t.Errorf("subject = %q, want svc-aiops", got.Subject)
	}
}

// --- the cases that matter ---------------------------------------------

// TestVerifyRejects covers every way a token can be invalid. A verifier that
// admits any of these is worse than none, because it looks like authentication.
func TestVerifyRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		hdr    func(kid string) map[string]any
		claims func() map[string]any
		want   string
	}{
		"unsigned alg none": {
			hdr:  func(kid string) map[string]any { return map[string]any{"alg": "none", "kid": kid} },
			want: "unsigned",
		},
		"missing alg": {
			hdr:  func(kid string) map[string]any { return map[string]any{"kid": kid} },
			want: "unsigned",
		},
		"symmetric alg against a public key set": {
			hdr:  func(kid string) map[string]any { return map[string]any{"alg": "HS256", "kid": kid} },
			want: "symmetric",
		},
		"wrong issuer": {
			claims: func() map[string]any {
				c := goodClaims()
				c["iss"] = "https://attacker.example.com"
				return c
			},
			want: "issuer",
		},
		"audience for another application": {
			claims: func() map[string]any {
				c := goodClaims()
				c["aud"] = "some-other-app"
				return c
			},
			want: "audience",
		},
		"expired": {
			claims: func() map[string]any {
				c := goodClaims()
				c["exp"] = time.Now().Add(-2 * time.Hour).Unix()
				return c
			},
			want: "expired",
		},
		"not yet valid": {
			claims: func() map[string]any {
				c := goodClaims()
				c["nbf"] = time.Now().Add(2 * time.Hour).Unix()
				return c
			},
			want: "not valid until",
		},
		"no expiry at all": {
			claims: func() map[string]any {
				c := goodClaims()
				delete(c, "exp")
				return c
			},
			want: "no exp",
		},
		"group maps to no tenant": {
			claims: func() map[string]any {
				c := goodClaims()
				c["groups"] = []string{"interns"}
				return c
			},
			want: "maps to a tenant",
		},
		"tenant claim absent": {
			claims: func() map[string]any {
				c := goodClaims()
				delete(c, "groups")
				return c
			},
			want: "carries no",
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newProvider(t)
			hdr, claims := goodHeader(p.kid), goodClaims()
			if tc.hdr != nil {
				hdr = tc.hdr(p.kid)
			}
			if tc.claims != nil {
				claims = tc.claims()
			}
			_, err := p.verifier(t).Verify(context.Background(), p.sign(t, hdr, claims))
			if err == nil {
				t.Fatal("token was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestVerifyRejectsATamperedPayload. The signature covers header and payload,
// so editing a claim after signing must invalidate it — including the claim
// that decides which tenant the caller gets.
func TestVerifyRejectsATamperedPayload(t *testing.T) {
	p := newProvider(t)
	token := p.sign(t, goodHeader(p.kid), goodClaims())

	parts := strings.Split(token, ".")
	forged := goodClaims()
	forged["groups"] = []string{"sre-team"}
	forged["sub"] = "somebody-else"
	parts[1] = b64(forged)

	if _, err := p.verifier(t).Verify(context.Background(), strings.Join(parts, ".")); err == nil {
		t.Fatal("a token with an edited payload was accepted")
	}
}

// TestVerifyRejectsAnHMACForgedWithThePublicKey is the algorithm-confusion
// attack in full: the attacker signs with HS256 using the provider's public key
// as the shared secret, which is public. Rejecting the alg is what stops it.
func TestVerifyRejectsAnHMACForgedWithThePublicKey(t *testing.T) {
	p := newProvider(t)
	hdr := map[string]any{"alg": "HS256", "kid": p.kid}
	signing := b64(hdr) + "." + b64(goodClaims())
	mac := hmac.New(sha256.New, p.key.N.Bytes())
	mac.Write([]byte(signing))
	token := signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if _, err := p.verifier(t).Verify(context.Background(), token); err == nil {
		t.Fatal("an HMAC-forged token was accepted")
	}
}

// TestVerifyRejectsATokenFromAnotherKey. A valid signature from a key the
// provider does not publish is not a credential.
func TestVerifyRejectsATokenFromAnotherKey(t *testing.T) {
	p := newProvider(t)
	other := newProvider(t)
	other.kid = p.kid // claim the same key id
	if _, err := p.verifier(t).Verify(context.Background(), other.sign(t, goodHeader(p.kid), goodClaims())); err == nil {
		t.Fatal("a token signed by an unpublished key was accepted")
	}
}

// --- key rotation -------------------------------------------------------

// TestUnknownKeyIDRefreshesOnce. Providers rotate keys, so an unseen kid has to
// be refetchable; it is also the cheapest way to make the gateway hammer the
// provider, so it must refresh at most once per interval.
func TestUnknownKeyIDRefreshesOnce(t *testing.T) {
	p := newProvider(t)
	v := p.verifier(t)

	if _, err := v.Verify(context.Background(), p.sign(t, goodHeader(p.kid), goodClaims())); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	after := p.hits

	for range 5 {
		_, _ = v.Verify(context.Background(), p.sign(t, goodHeader("rotated-key"), goodClaims()))
	}
	if p.hits > after+1 {
		t.Errorf("unknown key ids caused %d fetches; a bad token must not be a way to hammer the provider", p.hits-after)
	}
}

// --- construction -------------------------------------------------------

func TestNewRefusesAConfigurationThatCouldNotAdmitAnyone(t *testing.T) {
	base := Config{
		Issuer: "https://idp.example.com", Audience: "phigate",
		TenantClaim: "groups", TenantMap: map[string]string{"g": "t"},
	}
	for name, mutate := range map[string]func(*Config){
		"no issuer":     func(c *Config) { c.Issuer = "" },
		"no audience":   func(c *Config) { c.Audience = "" },
		"no claim":      func(c *Config) { c.TenantClaim = "" },
		"no tenant map": func(c *Config) { c.TenantMap = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Error("configuration was accepted")
			}
		})
	}
}

func TestLooksLikeJWTDoesNotClaimStaticKeys(t *testing.T) {
	for s, want := range map[string]bool{
		"a.b.c":                    true,
		"sk-live-abcdef":           false,
		"":                         false,
		"only.two":                 false,
		"..":                       false,
		"phigate-key-with.a.dot":   true, // shape only; verification still decides
		"eyJhbGciOiJSUzI1NiJ9.e.s": true,
	} {
		if got := LooksLikeJWT(s); got != want {
			t.Errorf("LooksLikeJWT(%q) = %v, want %v", s, got, want)
		}
	}
}

// TestECDSATokensVerify. Entra ID issues RS256, but providers configured for EC
// exist and a verifier that silently only does RSA would fail them confusingly.
func TestECDSATokensVerify(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "EC", "use": "sig", "crv": "P-256", "kid": "ec-1",
			"x": base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
			"y": base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
		}}})
	}))
	defer srv.Close()

	signing := b64(map[string]any{"alg": "ES256", "kid": "ec-1"}) + "." + b64(goodClaims())
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	token := signing + "." + base64.RawURLEncoding.EncodeToString(sig)

	v, err := New(Config{
		Issuer: "https://idp.example.com", Audience: "phigate", JWKSURL: srv.URL,
		TenantClaim: "groups", TenantMap: map[string]string{"sre-team": "team-sre"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("valid ES256 token rejected: %v", err)
	}
}
