package llm

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestSigV4MatchesAnIndependentImplementation is the test that makes writing a
// signer by hand defensible.
//
// The inputs are AWS's published `get-vanilla` case — credentials AKIDEXAMPLE /
// wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY, timestamp 20150830T123600Z, region
// us-east-1, service "service" — and the expected signature was computed by a
// second implementation written separately from the same specification, in
// another language, from hashlib and hmac alone. A signature is either
// byte-identical or it is worthless, so the whole header is asserted rather
// than its shape.
//
// The signature differs from the one AWS publishes for get-vanilla because this
// signer also sends and signs x-amz-content-sha256, which that case does not.
// Signing more headers than the minimum is allowed and is what AWS's own SDKs
// do; what matters is that both implementations agree on the same input.
func TestSigV4MatchesAnIndependentImplementation(t *testing.T) {
	fixed := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	s := &sigV4Signer{
		region:    "us-east-1",
		service:   "service",
		accessKey: "AKIDEXAMPLE",
		secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		now:       func() time.Time { return fixed },
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.amazonaws.com"

	if err := s.sign(req, nil); err != nil {
		t.Fatal(err)
	}

	const want = "AWS4-HMAC-SHA256 " +
		"Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
		"Signature=726c5c4879a6b4ccbbd3b24edbd6b8826d34f87450fbbf4e85546fc7ba9c1642"

	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("signature does not match the independent implementation:\n got %s\nwant %s", got, want)
	}
	if req.Header.Get("X-Amz-Date") != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q", req.Header.Get("X-Amz-Date"))
	}
	// The empty-payload hash is a fixed constant, and getting it wrong is the
	// commonest way a hand-rolled signer fails on a GET.
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if req.Header.Get("X-Amz-Content-Sha256") != emptySHA256 {
		t.Errorf("X-Amz-Content-Sha256 = %q, want the empty-string hash",
			req.Header.Get("X-Amz-Content-Sha256"))
	}
}

// TestSigV4IsDeterministic: the same request signed twice at the same instant
// must produce the same signature, or something not covered by the canonical
// request is leaking into it.
func TestSigV4IsDeterministic(t *testing.T) {
	fixed := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	sign := func() string {
		s := &sigV4Signer{
			region: "ap-northeast-1", service: bedrockService,
			accessKey: "AKID", secretKey: "SECRET",
			now: func() time.Time { return fixed },
		}
		req, _ := http.NewRequest(http.MethodPost,
			"https://bedrock-runtime.ap-northeast-1.amazonaws.com/model/anthropic.claude-opus-5/invoke",
			nil)
		req.Header.Set("Content-Type", "application/json")
		if err := s.sign(req, []byte(`{"a":1}`)); err != nil {
			t.Fatal(err)
		}
		return req.Header.Get("Authorization")
	}
	if a, b := sign(), sign(); a != b {
		t.Errorf("two signatures of the same request differ:\n%s\n%s", a, b)
	}
}

// TestSigV4CoversTheBody. The payload hash is part of the signature; if it were
// not, an intermediary could rewrite the request body and AWS would accept it.
func TestSigV4CoversTheBody(t *testing.T) {
	fixed := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	sign := func(body string) string {
		s := &sigV4Signer{
			region: "us-east-1", service: bedrockService,
			accessKey: "AKID", secretKey: "SECRET",
			now: func() time.Time { return fixed },
		}
		req, _ := http.NewRequest(http.MethodPost, "https://x.amazonaws.com/model/m/invoke", nil)
		if err := s.sign(req, []byte(body)); err != nil {
			t.Fatal(err)
		}
		return req.Header.Get("Authorization")
	}
	if sign(`{"prompt":"a"}`) == sign(`{"prompt":"b"}`) {
		t.Fatal("two different bodies produced the same signature; the payload is unsigned")
	}
}

// TestSigV4ExcludesVolatileHeaders. A header the transport sets after signing —
// Content-Length, User-Agent — would invalidate the signature it was included
// in, and the failure looks like bad credentials rather than a bug here.
func TestSigV4ExcludesVolatileHeaders(t *testing.T) {
	fixed := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	s := &sigV4Signer{
		region: "us-east-1", service: bedrockService,
		accessKey: "AKID", secretKey: "SECRET",
		now: func() time.Time { return fixed },
	}
	req, _ := http.NewRequest(http.MethodPost, "https://x.amazonaws.com/model/m/invoke", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "phigate/test")
	req.Header.Set("Content-Length", "7")
	if err := s.sign(req, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}

	auth := req.Header.Get("Authorization")
	for _, excluded := range []string{"user-agent", "content-length", "authorization"} {
		if strings.Contains(auth, excluded) {
			t.Errorf("SignedHeaders includes %q, which the transport may change after signing: %s",
				excluded, auth)
		}
	}
	if !strings.Contains(auth, "content-type") {
		t.Errorf("SignedHeaders omits content-type, which is part of the request: %s", auth)
	}
}

// TestSigV4SignsTheSessionToken. Temporary credentials — which is what any
// assumed role issues — are rejected unless the token is both sent and signed.
func TestSigV4SignsTheSessionToken(t *testing.T) {
	fixed := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	s := &sigV4Signer{
		region: "us-east-1", service: bedrockService,
		accessKey: "AKID", secretKey: "SECRET", sessionToken: "TOKEN",
		now: func() time.Time { return fixed },
	}
	req, _ := http.NewRequest(http.MethodPost, "https://x.amazonaws.com/model/m/invoke", nil)
	if err := s.sign(req, nil); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Amz-Security-Token") != "TOKEN" {
		t.Error("the session token was not sent")
	}
	if !strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Errorf("the session token is sent but not signed: %s", req.Header.Get("Authorization"))
	}
}

// TestSigV4CanonicalQuerySorts. Parameters are signed in sorted order, so a map
// iteration leaking into the canonical request would make signatures flaky.
func TestSigV4CanonicalQuerySorts(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://x.amazonaws.com/p?b=2&a=1&c=3", nil)
	if got := canonicalQuery(req.URL); got != "a=1&b=2&c=3" {
		t.Errorf("canonicalQuery = %q, want a=1&b=2&c=3", got)
	}
}

// TestCredentialsComeFromTheEnvironment covers the deployment shape that
// matters: a container with credentials injected.
func TestCredentialsComeFromTheEnvironment(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID-env")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SECRET-env")
	t.Setenv("AWS_SESSION_TOKEN", "TOKEN-env")
	t.Setenv("AWS_REGION", "ap-northeast-1")

	s, err := newSigV4Signer(ProviderConfig{Name: "cloud", Provider: ProviderBedrock})
	if err != nil {
		t.Fatal(err)
	}
	if s.accessKey != "AKID-env" || s.secretKey != "SECRET-env" || s.sessionToken != "TOKEN-env" {
		t.Errorf("credentials not read from the environment: %+v", s)
	}
	if s.region != "ap-northeast-1" {
		t.Errorf("region = %q", s.region)
	}
}

// TestInlineCredentialsUseTheAPIKeyField, so a Bedrock backend needs no new
// secret plumbing in the config, the Helm chart or the environment.
func TestInlineCredentialsUseTheAPIKeyField(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")

	s, err := newSigV4Signer(ProviderConfig{
		Name: "cloud", Provider: ProviderBedrock, Region: "us-east-1",
		APIKey: "AKID-inline:SECRET-inline",
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.accessKey != "AKID-inline" || s.secretKey != "SECRET-inline" {
		t.Errorf("inline credentials not parsed: access=%q secret=%q", s.accessKey, s.secretKey)
	}
}
