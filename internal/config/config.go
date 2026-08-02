// Package config loads PhiGate's runtime configuration from the environment.
// All knobs have sensible local-first defaults so the gateway boots without any
// configuration against a local Ollama instance.
package config

import "os"

// Config holds the settings for the gateway and its two LLM backends.
type Config struct {
	Addr string

	// Local SLM (Ollama / llama.cpp, OpenAI-compatible endpoint).
	LocalBaseURL string
	LocalModel   string
	LocalAPIKey  string

	// Cloud LLM (OpenAI-compatible upstream).
	CloudBaseURL string
	CloudModel   string
	CloudAPIKey  string

	// SystemPreamble is prepended to every upstream request so the model knows
	// that tokens like <V1> / #REF1 are anonymized placeholders.
	SystemPreamble string
}

// DefaultSystemPreamble explains PhiGate's anonymization convention to the
// upstream model so it preserves placeholders verbatim in its answer.
const DefaultSystemPreamble = "You are an IT operations and SRE assistant. " +
	"The user's logs and code have been anonymized by a gateway: tokens such as " +
	"<V1>, <V2>, #REF1 and placeholders like <id>, <str>, <int> stand in for real " +
	"values that were removed for security. Reason about the structure and refer to " +
	"these tokens verbatim in your answer; they will be restored before the operator " +
	"sees your response. Do not invent the hidden values."

// FromEnv builds a Config from environment variables, applying defaults.
func FromEnv() Config {
	return Config{
		Addr: envOr("PHIGATE_ADDR", ":8080"),

		LocalBaseURL: envOr("PHIGATE_LOCAL_BASE_URL", "http://localhost:11434/v1"),
		LocalModel:   envOr("PHIGATE_LOCAL_MODEL", "phi4-mini"),
		LocalAPIKey:  os.Getenv("PHIGATE_LOCAL_API_KEY"),

		CloudBaseURL: envOr("PHIGATE_CLOUD_BASE_URL", "https://api.openai.com/v1"),
		CloudModel:   envOr("PHIGATE_CLOUD_MODEL", "gpt-4o"),
		CloudAPIKey:  firstNonEmpty(os.Getenv("PHIGATE_CLOUD_API_KEY"), os.Getenv("OPENAI_API_KEY")),

		SystemPreamble: envOr("PHIGATE_SYSTEM_PREAMBLE", DefaultSystemPreamble),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
