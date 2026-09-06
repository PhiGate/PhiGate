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
	// ProviderAnthropic is Anthropic's first-party Messages API.
	//
	// It is not OpenAI-compatible — a different endpoint, a different auth
	// header, and a different request and response shape — so it is a dialect
	// this package translates to rather than a base URL it points at.
	ProviderAnthropic Provider = "anthropic"
	// ProviderBedrock is Claude on Amazon Bedrock: the same Messages wire
	// format, addressed by URL, authenticated with AWS SigV4.
	//
	// It matters for the same reason Azure does. A Japanese enterprise with an
	// existing AWS agreement and a data-residency requirement often cannot buy
	// the first-party API at all, and a gateway it cannot be dropped in front
	// of is not in the running.
	ProviderBedrock Provider = "bedrock"
)

// ParseProvider maps a config string to a Provider.
func ParseProvider(s string) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "openai", "openai-compatible", "ollama", "vllm", "compatible":
		return ProviderOpenAI, nil
	case "azure", "azure-openai", "azureopenai":
		return ProviderAzure, nil
	case "anthropic", "claude":
		return ProviderAnthropic, nil
	case "bedrock", "aws-bedrock", "awsbedrock":
		return ProviderBedrock, nil
	}
	return "", fmt.Errorf("unknown provider %q (want openai|azure|anthropic|bedrock)", s)
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
	// Model is the backend's default model. It is used only where a request
	// cannot supply one — the readiness probe, which has to name a model on a
	// provider with no listing endpoint.
	Model string
	// APIKey authenticates to the provider.
	APIKey string
	// APIVersion is required by Azure, e.g. "2024-10-21".
	APIVersion string
	// Deployment overrides the Azure deployment name when it differs from the
	// model name, which it usually does. On Bedrock it overrides the model id
	// in the invocation path, which is where an inference profile ARN goes.
	Deployment string

	// --- Bedrock ---

	// Region is the AWS region to sign for and address.
	Region string
	// AccessKeyID, SecretAccessKey and SessionToken are static AWS
	// credentials. Empty falls back to the standard environment variables.
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
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

// embeddingsEndpoint returns the embeddings URL for a model.
//
// Azure addresses a deployment rather than a model, and an embeddings
// deployment is a different one from a chat deployment, so the configured
// Deployment is deliberately not reused here — the model name from the request
// is what names it.
func (p ProviderConfig) embeddingsEndpoint(model string) string {
	base := strings.TrimRight(p.BaseURL, "/")
	switch p.Provider {
	case ProviderAzure:
		version := p.APIVersion
		if version == "" {
			version = DefaultAzureAPIVersion
		}
		return fmt.Sprintf("%s/openai/deployments/%s/embeddings?api-version=%s",
			base, model, version)
	default:
		return base + "/embeddings"
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
