package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// refreshInterval bounds how often an unknown key id may trigger a fetch.
//
// Providers rotate signing keys, so an unrecognised kid is expected and has to
// be refetchable. It is also what an attacker would send to make the gateway
// hammer the provider, so a miss refreshes at most this often and otherwise
// fails closed against the keys already held.
const refreshInterval = time.Minute

// maxJWKSBytes caps a JWKS response. The document is a few keys; anything
// larger is a misconfigured URL or a hostile one.
const maxJWKSBytes = 1 << 20

// keySet holds the provider's public keys and refetches them when a token
// arrives signed by one it has not seen.
type keySet struct {
	url    string
	client *http.Client

	mu          sync.RWMutex
	keys        map[string]any
	lastAttempt time.Time
}

func newKeySet(url string) *keySet {
	return &keySet{
		url:    url,
		keys:   map[string]any{},
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// lookup returns the key for kid, fetching the document if it is unknown.
func (k *keySet) lookup(ctx context.Context, kid string) (any, error) {
	k.mu.RLock()
	key, ok := k.keys[kid]
	k.mu.RUnlock()
	if ok {
		return key, nil
	}

	if err := k.refresh(ctx); err != nil {
		return nil, err
	}

	k.mu.RLock()
	defer k.mu.RUnlock()
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	// A single unnamed key is the common shape for a provider with one signing
	// key, and a token from it may carry no kid at all.
	if kid == "" && len(k.keys) == 1 {
		for _, only := range k.keys {
			return only, nil
		}
	}
	return nil, fmt.Errorf("oidc: no signing key %q in %s", kid, k.url)
}

func (k *keySet) refresh(ctx context.Context) error {
	k.mu.Lock()
	if time.Since(k.lastAttempt) < refreshInterval {
		k.mu.Unlock()
		return errors.New("oidc: signing key is unknown and the key set was refreshed recently")
	}
	k.lastAttempt = time.Now()
	url := k.url
	client := k.client
	k.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("oidc: jwks: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: jwks returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return fmt.Errorf("oidc: read jwks: %w", err)
	}

	parsed, err := parseJWKS(body)
	if err != nil {
		return err
	}
	if len(parsed) == 0 {
		return errors.New("oidc: jwks contains no usable key")
	}
	k.mu.Lock()
	k.keys = parsed
	k.mu.Unlock()
	return nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseJWKS converts a JWKS document into public keys, skipping entries it does
// not understand rather than failing the whole set: a provider publishing one
// encryption key alongside its signing keys must not lock everyone out.
func parseJWKS(body []byte) (map[string]any, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oidc: parse jwks: %w", err)
	}
	out := map[string]any{}
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			key, err := rsaKey(k)
			if err != nil {
				continue
			}
			out[k.Kid] = key
		case "EC":
			key, err := ecKey(k)
			if err != nil {
				continue
			}
			out[k.Kid] = key
		}
	}
	return out, nil
}

func rsaKey(k jwk) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	if len(n) == 0 || len(e) == 0 {
		return nil, errors.New("oidc: empty RSA parameter")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}, nil
}

func ecKey(k jwk) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("oidc: unsupported curve %q", k.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}
