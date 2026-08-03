package llm

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Provider names an upstream API dialect.
//
// "OpenAI-compatible" is not one protocol in practice. Azure OpenAI — the
// deployment most Japanese enterprises actually have, because it is the one
// their existing Microsoft agreement and their data-residency requirements
// permit — authenticates with an api-key header, addresses models as
// deployments in the path, and requires an api-version query parameter. A
// gateway that only speaks public-OpenAI cannot be dropped into those
// environments at all, which is why this exists.
type Provider string

const (
	// ProviderOpenAI is the public OpenAI API and the many services that
	// clone it, including Ollama, vLLM, Together and Groq.
	ProviderOpenAI Provider = "openai"
	// ProviderAzure is Azure OpenAI Service.
	ProviderAzure Provider = "azure"
)

// ParseProvider maps a config string to a Provider.
func ParseProvider(s string) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "openai", "openai-compatible", "ollama", "vllm", "compatible":
		return ProviderOpenAI, nil
	case "azure", "azure-openai", "azureopenai":
		return ProviderAzure, nil
	}
	return "", fmt.Errorf("unknown provider %q (want openai|azure)", s)
}

// ProviderConfig describes one upstream backend.
type ProviderConfig struct {
	// Name labels the backend in logs and audit records ("local"/"cloud").
	Name string
	// Provider selects the API dialect.
	Provider Provider
	// BaseURL is the endpoint root. For OpenAI it includes the /v1 suffix;
	// for Azure it is the resource root, e.g. https://x.openai.azure.com.
	BaseURL string
	// APIKey authenticates to the provider.
	APIKey string
	// APIVersion is required by Azure, e.g. "2024-10-21".
	APIVersion string
	// Deployment overrides the Azure deployment name when it differs from the
	// model name, which it usually does.
	Deployment string
	// Timeout bounds a single upstream call.
	Timeout time.Duration
	// Retries is the number of additional attempts for retryable failures.
	Retries int
	// BreakerThreshold is the number of consecutive failures that opens the
	// circuit breaker. Zero disables the breaker.
	BreakerThreshold int
	// BreakerCooldown is how long the circuit stays open.
	BreakerCooldown time.Duration
}

// endpoint returns the chat completions URL for a model.
func (p ProviderConfig) endpoint(model string) string {
	base := strings.TrimRight(p.BaseURL, "/")
	switch p.Provider {
	case ProviderAzure:
		deployment := p.Deployment
		if deployment == "" {
			deployment = model
		}
		version := p.APIVersion
		if version == "" {
			version = DefaultAzureAPIVersion
		}
		return fmt.Sprintf("%s/openai/deployments/%s/chat/completions?api-version=%s",
			base, deployment, version)
	default:
		return base + "/chat/completions"
	}
}

// DefaultAzureAPIVersion is used when none is configured.
const DefaultAzureAPIVersion = "2024-10-21"

// authorize applies provider-appropriate authentication to a request.
func (p ProviderConfig) authorize(r *http.Request) {
	if p.APIKey == "" {
		return
	}
	switch p.Provider {
	case ProviderAzure:
		r.Header.Set("api-key", p.APIKey)
	default:
		r.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
}
