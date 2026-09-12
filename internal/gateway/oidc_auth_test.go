package gateway

import (
	"crypto"
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

	"github.com/phigate/phigate/internal/config"
	"github.com/phigate/phigate/internal/llm"
)

// idp is a throwaway identity provider for the tests below.
type idp struct {
	key *rsa.PrivateKey
	url string
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(srv.Close)
	return &idp{key: key, url: srv.URL}
}

func (i *idp) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	seg := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signing := seg(map[string]any{"alg": "RS256", "kid": "k1"}) + "." + seg(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func oidcConfig(i *idp) config.Config {
	cfg := testConfig()
	cfg.AllowAnonymous = false
	cfg.APIKeys = map[string]string{"static-key": "team-legacy"}
	cfg.OIDC = config.OIDCConfig{
		Issuer: "https://idp.example.com", Audience: "phigate",
		JWKSURL: i.url, TenantClaim: "groups",
		TenantMap: map[string]string{"sre-team": "team-sre"},
	}
	return cfg
}

func postWithAuth(t *testing.T, g *Gateway, credential string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/chat/completions",
		strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`))
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	g.Routes().ServeHTTP(rec, req)
	return rec
}

func validClaims() map[string]any {
	return map[string]any{
		"iss": "https://idp.example.com", "aud": "phigate", "sub": "svc-aiops",
		"groups": []string{"sre-team"}, "exp": time.Now().Add(time.Hour).Unix(),
	}
}

// TestTokenFromTheProviderAuthenticates is the feature: a client presents a
// token its own identity provider minted, and never holds a PhiGate secret.
func TestTokenFromTheProviderAuthenticates(t *testing.T) {
	i := newIDP(t)
	g := newTestGateway(t, oidcConfig(i), &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	if rec := postWithAuth(t, g, i.token(t, validClaims())); rec.Code != 200 {
		t.Fatalf("valid token rejected: %d %s", rec.Code, rec.Body.String())
	}
}

// TestStaticKeysKeepWorkingAlongsideTokens. The two credential types coexist so
// a migration happens one client at a time instead of in one change window.
func TestStaticKeysKeepWorkingAlongsideTokens(t *testing.T) {
	i := newIDP(t)
	g := newTestGateway(t, oidcConfig(i), &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	if rec := postWithAuth(t, g, "static-key"); rec.Code != 200 {
		t.Errorf("static key rejected while OIDC is configured: %d %s", rec.Code, rec.Body.String())
	}
	if rec := postWithAuth(t, g, "wrong-key"); rec.Code != 401 {
		t.Errorf("a wrong static key returned %d, want 401", rec.Code)
	}
}

// TestBadTokensAreRefused walks the same ground as the oidc package's unit
// tests, one layer up, to prove the gateway actually calls the verifier rather
// than admitting anything token-shaped.
func TestBadTokensAreRefused(t *testing.T) {
	i := newIDP(t)
	other := newIDP(t)
	g := newTestGateway(t, oidcConfig(i), &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	for name, token := range map[string]string{
		"signed by another provider": other.token(t, validClaims()),
		"expired": i.token(t, map[string]any{
			"iss": "https://idp.example.com", "aud": "phigate",
			"groups": []string{"sre-team"}, "exp": time.Now().Add(-time.Hour).Unix(),
		}),
		"audience for another app": i.token(t, map[string]any{
			"iss": "https://idp.example.com", "aud": "another-app",
			"groups": []string{"sre-team"}, "exp": time.Now().Add(time.Hour).Unix(),
		}),
		"group maps to no tenant": i.token(t, map[string]any{
			"iss": "https://idp.example.com", "aud": "phigate",
			"groups": []string{"interns"}, "exp": time.Now().Add(time.Hour).Unix(),
		}),
		"not a token at all": "just-a-string",
	} {
		t.Run(name, func(t *testing.T) {
			if rec := postWithAuth(t, g, token); rec.Code != 401 {
				t.Errorf("got %d, want 401\n%s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestRefusedTokensSayWhy. An integration that cannot see why its token was
// rejected costs a day; the holder of the token learns nothing from the reason
// that they did not already have.
func TestRefusedTokensSayWhy(t *testing.T) {
	i := newIDP(t)
	g := newTestGateway(t, oidcConfig(i), &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	rec := postWithAuth(t, g, i.token(t, map[string]any{
		"iss": "https://idp.example.com", "aud": "another-app",
		"groups": []string{"sre-team"}, "exp": time.Now().Add(time.Hour).Unix(),
	}))
	if body := rec.Body.String(); !strings.Contains(body, "audience") {
		t.Errorf("rejection does not say why: %s", body)
	}
	// A wrong static key must stay generic — a specific answer there would be
	// an oracle for guessing one.
	if body := postWithAuth(t, g, "wrong-key").Body.String(); strings.Contains(body, "audience") {
		t.Errorf("a static-key failure leaked a token diagnostic: %s", body)
	}
}

// TestOIDCUnconfiguredChangesNothing. The default path must be byte-identical
// to what it was before tokens existed.
func TestOIDCUnconfiguredChangesNothing(t *testing.T) {
	cfg := testConfig()
	cfg.AllowAnonymous = false
	cfg.APIKeys = map[string]string{"static-key": "team-legacy"}
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	if rec := postWithAuth(t, g, "static-key"); rec.Code != 200 {
		t.Errorf("static key rejected with OIDC off: %d", rec.Code)
	}
	if rec := postWithAuth(t, g, "a.b.c"); rec.Code != 401 {
		t.Errorf("token-shaped credential returned %d with no provider configured, want 401", rec.Code)
	}
}

// TestMisconfiguredOIDCFailsAtStartup. An operator who has told their identity
// team that PhiGate accepts their tokens should find out here, not from the
// first client to try.
func TestMisconfiguredOIDCFailsAtStartup(t *testing.T) {
	for name, mutate := range map[string]func(*config.OIDCConfig){
		"no audience":   func(o *config.OIDCConfig) { o.Audience = "" },
		"no claim":      func(o *config.OIDCConfig) { o.TenantClaim = "" },
		"no tenant map": func(o *config.OIDCConfig) { o.TenantMap = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := oidcConfig(newIDP(t))
			mutate(&cfg.OIDC)
			if _, err := newOIDCVerifier(cfg); err == nil {
				t.Error("a configuration that could admit nobody was accepted")
			}
		})
	}
}

var _ llm.Client = (*fakeClient)(nil)
