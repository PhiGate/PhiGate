package gateway

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phigate/phigate/internal/config"
)

func rbacConfig() config.Config {
	cfg := testConfig()
	cfg.AllowAnonymous = false
	cfg.DebugEnabled = true
	cfg.APIKeys = map[string]string{
		"app-key":    "team-app",
		"ops-key":    "team-ops",
		"admin-key":  "team-admin",
		"unlabelled": "team-old",
	}
	cfg.APIRoles = map[string]config.Role{
		"app-key":   config.RoleCaller,
		"ops-key":   config.RoleOperator,
		"admin-key": config.RoleAdmin,
		// "unlabelled" deliberately absent: it must behave as it did before
		// roles existed.
	}
	return cfg
}

func get(t *testing.T, g *Gateway, path, key string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	g.Routes().ServeHTTP(rec, req)
	return rec.Code
}

func postDebug(t *testing.T, g *Gateway, key string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/debug/compress",
		strings.NewReader(`{"text":"host 10.0.0.1"}`))
	req.Header.Set("Authorization", "Bearer "+key)
	g.Routes().ServeHTTP(rec, req)
	return rec.Code
}

// TestAnApplicationKeyCannotReadTheGatewaysOwnReporting is the hole this
// closes. A key issued so an application could ask questions also read the
// savings ledger, the dashboard, and the plaintext of everything just masked.
func TestAnApplicationKeyCannotReadTheGatewaysOwnReporting(t *testing.T) {
	g := newTestGateway(t, rbacConfig(), &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	for path, want := range map[string]int{
		"/v1/models":        200, // inference surface: allowed
		"/v1/phigate/stats": 403,
		"/v1/phigate/rules": 403,
		"/metrics":          403,
		"/dashboard":        403,
	} {
		if got := get(t, g, path, "app-key"); got != want {
			t.Errorf("caller GET %s = %d, want %d", path, got, want)
		}
	}
	if got := postDebug(t, g, "app-key"); got != 403 {
		t.Errorf("caller reached /debug/compress with %d; that endpoint returns the plaintext of every masked value", got)
	}
}

// TestOperatorReadsReportingButNotPlaintext.
func TestOperatorReadsReportingButNotPlaintext(t *testing.T) {
	g := newTestGateway(t, rbacConfig(), &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	for _, path := range []string{"/v1/phigate/stats", "/v1/phigate/rules", "/metrics", "/dashboard"} {
		if got := get(t, g, path, "ops-key"); got != 200 {
			t.Errorf("operator GET %s = %d, want 200", path, got)
		}
	}
	if got := postDebug(t, g, "ops-key"); got != 403 {
		t.Errorf("operator reached /debug/compress with %d, want 403", got)
	}
}

func TestAdminReachesDebug(t *testing.T) {
	g := newTestGateway(t, rbacConfig(), &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})
	if got := postDebug(t, g, "admin-key"); got != 200 {
		t.Errorf("admin GET /debug/compress = %d, want 200", got)
	}
}

// TestAKeyWithNoRoleBehavesAsItDidBefore. Every credential in a deployment
// upgrading to this version was written before roles existed. Cutting a
// monitoring key off from /metrics on upgrade would be a worse first
// impression than permissions being wider than ideal — with debug the one
// exception, since that is where a generous default actually costs something.
func TestAKeyWithNoRoleBehavesAsItDidBefore(t *testing.T) {
	g := newTestGateway(t, rbacConfig(), &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	for _, path := range []string{"/v1/models", "/v1/phigate/stats", "/metrics", "/dashboard"} {
		if got := get(t, g, path, "unlabelled"); got != 200 {
			t.Errorf("unlabelled key GET %s = %d, want 200 (upgrades must not break)", path, got)
		}
	}
	if got := postDebug(t, g, "unlabelled"); got != 403 {
		t.Errorf("unlabelled key reached /debug/compress with %d; admin must be written down", got)
	}
}

// TestForbiddenIsNotUnauthorized. An application holding a valid key that is
// merely not allowed here must be told so: 403 against 401 is the difference
// between a five-minute fix and an afternoon spent suspecting the credential.
func TestForbiddenIsNotUnauthorized(t *testing.T) {
	g := newTestGateway(t, rbacConfig(), &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	if got := get(t, g, "/v1/phigate/stats", "app-key"); got != 403 {
		t.Errorf("a valid key with the wrong role got %d, want 403", got)
	}
	if got := get(t, g, "/v1/phigate/stats", "no-such-key"); got != 401 {
		t.Errorf("an unknown key got %d, want 401", got)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/phigate/stats", nil)
	req.Header.Set("Authorization", "Bearer app-key")
	g.Routes().ServeHTTP(rec, req)
	if body := rec.Body.String(); !strings.Contains(body, "caller") || !strings.Contains(body, "operator") {
		t.Errorf("the refusal does not say which role was held or needed: %s", body)
	}
}

// TestAnonymousIsAdmin. Running with no credentials at all is a decision the
// operator had to make against a refusal to start; narrowing it protects
// nothing, because there is no credential to escalate from.
func TestAnonymousIsAdmin(t *testing.T) {
	cfg := testConfig()
	cfg.AllowAnonymous = true
	cfg.DebugEnabled = true
	cfg.APIKeys = map[string]string{}
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/debug/compress", strings.NewReader(`{"text":"x"}`))
	g.Routes().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("anonymous dev loop broke: /debug/compress = %d", rec.Code)
	}
}

// TestTokenRoleComesFromTheTenantMap. An IdP group maps to "tenant:role" in
// the same shape PHIGATE_API_KEYS uses.
func TestTokenRoleComesFromTheTenantMap(t *testing.T) {
	i := newIDP(t)
	cfg := oidcConfig(i)
	cfg.DebugEnabled = true
	cfg.OIDC.TenantMap = map[string]string{
		"app-group": "team-app:caller",
		"ops-group": "team-ops:operator",
	}
	g := newTestGateway(t, cfg, &fakeClient{name: "local", reply: "ok"}, &fakeClient{name: "cloud"})

	tok := func(group string) string {
		return i.token(t, map[string]any{
			"iss": "https://idp.example.com", "aud": "phigate",
			"groups": []string{group}, "exp": time.Now().Add(time.Hour).Unix(),
		})
	}
	if got := get(t, g, "/v1/phigate/stats", tok("app-group")); got != 403 {
		t.Errorf("a caller-group token read stats: %d", got)
	}
	if got := get(t, g, "/v1/phigate/stats", tok("ops-group")); got != 200 {
		t.Errorf("an operator-group token was refused stats: %d", got)
	}
}
