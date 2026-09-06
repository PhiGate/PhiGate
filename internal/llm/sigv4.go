package llm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4, implemented against the published specification.
//
// # Why this is here rather than aws-sdk-go
//
// The community edition's go.mod lists one third-party dependency, and that is
// the property a customer's security review checks — `make ce-purity` fails the
// build if it stops being true. The AWS SDK's transitive tree would end it, for
// one backend dialect. SigV4 itself is a short, fully specified, deterministic
// function of the request, so it is testable to the byte against the vectors
// AWS publishes, and that is what makes writing it defensible rather than
// reckless.
//
// It fails closed. A wrong signature is a 403 from AWS, not a request that goes
// through unauthenticated.
//
// # What is deliberately not here
//
// The AWS credential *chain* — IMDS, SSO, profile files, AssumeRole — is a much
// larger surface than the signature, and half of one is worse than none. This
// reads static credentials from the configuration or the standard environment
// variables, which covers the deployment shapes that matter for a gateway: a
// container with credentials injected, and an explicitly configured key pair.
// A deployment needing the full chain should put credentials in the environment
// with the tooling it already uses. The configuration reference says so.
type sigV4Signer struct {
	region    string
	service   string
	accessKey string
	secretKey string
	// sessionToken is set for temporary credentials, which is what any
	// assumed role issues.
	sessionToken string

	// now is injectable so the signature is testable against a fixed clock.
	now func() time.Time
}

// bedrockService is the SigV4 service name Bedrock's runtime signs under.
const bedrockService = "bedrock"

// newSigV4Signer resolves credentials for a Bedrock backend.
func newSigV4Signer(cfg ProviderConfig) (*sigV4Signer, error) {
	region := cfg.Region
	if region == "" {
		region = firstNonEmpty(os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION"))
	}
	if region == "" {
		return nil, fmt.Errorf("bedrock backend %q: no region configured "+
			"(set the backend's region, or AWS_REGION)", cfg.Name)
	}

	// The API key field carries "accessKeyID:secretAccessKey" when credentials
	// are configured inline, so a Bedrock backend needs no new secret plumbing
	// in the config, the Helm chart or the environment.
	access, secret := cfg.AccessKeyID, cfg.SecretAccessKey
	if access == "" && secret == "" && strings.Contains(cfg.APIKey, ":") {
		access, secret, _ = strings.Cut(cfg.APIKey, ":")
	}
	if access == "" {
		access = os.Getenv("AWS_ACCESS_KEY_ID")
	}
	if secret == "" {
		secret = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	if access == "" || secret == "" {
		return nil, fmt.Errorf("bedrock backend %q: no credentials found "+
			"(set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or configure them "+
			"on the backend). The AWS credential chain — instance metadata, SSO, "+
			"profile files — is not implemented", cfg.Name)
	}

	token := cfg.SessionToken
	if token == "" {
		token = os.Getenv("AWS_SESSION_TOKEN")
	}

	return &sigV4Signer{
		region:       region,
		service:      bedrockService,
		accessKey:    access,
		secretKey:    secret,
		sessionToken: token,
		now:          time.Now,
	}, nil
}

// sign adds the Authorization and supporting headers to a request.
//
// The body is passed in rather than read from the request because SigV4 hashes
// it, and consuming req.Body here would leave nothing for the transport to
// send.
func (s *sigV4Signer) sign(r *http.Request, body []byte) error {
	now := s.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	payloadHash := hexSHA256(body)

	r.Header.Set("X-Amz-Date", amzDate)
	r.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if s.sessionToken != "" {
		r.Header.Set("X-Amz-Security-Token", s.sessionToken)
	}
	if r.Host != "" {
		r.Header.Set("Host", r.Host)
	} else {
		r.Header.Set("Host", r.URL.Host)
	}

	canonicalHeaders, signedHeaders := canonicalizeHeaders(r)

	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURI(r.URL),
		canonicalQuery(r.URL),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, s.region, s.service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	// The signing key is derived by chaining HMACs over the scope, so a
	// leaked signature reveals nothing about the secret.
	k := hmacSHA256([]byte("AWS4"+s.secretKey), dateStamp)
	k = hmacSHA256(k, s.region)
	k = hmacSHA256(k, s.service)
	k = hmacSHA256(k, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(k, stringToSign))

	r.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKey, scope, signedHeaders, signature))
	return nil
}

// canonicalizeHeaders builds the canonical header block and the signed-header
// list. Names are lowercased and sorted; values have runs of whitespace
// collapsed, which is what the specification requires and the most common
// place a hand-rolled signer goes wrong.
func canonicalizeHeaders(r *http.Request) (canonical, signed string) {
	names := make([]string, 0, len(r.Header)+1)
	values := map[string]string{}

	for name, vs := range r.Header {
		lower := strings.ToLower(name)
		switch lower {
		case "authorization", "content-length", "user-agent":
			// Excluded: set by the transport after signing, or meaningless to
			// sign. A header that changes between signing and sending
			// invalidates the signature.
			continue
		}
		names = append(names, lower)
		trimmed := make([]string, len(vs))
		for i, v := range vs {
			trimmed[i] = strings.Join(strings.Fields(v), " ")
		}
		values[lower] = strings.Join(trimmed, ",")
	}
	if _, ok := values["host"]; !ok {
		names = append(names, "host")
		values["host"] = r.URL.Host
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(values[n])
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(names, ";")
}

// canonicalURI is the path, each segment URI-encoded, with the encoding applied
// once — Bedrock model ids contain dots and colons, and double-encoding them is
// the difference between a signature that verifies and a 403.
func canonicalURI(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

// canonicalQuery sorts parameters by name and re-encodes them.
func canonicalQuery(u *url.URL) string {
	q := u.Query()
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
