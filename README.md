# PhiGate

**The Next-Gen SLM Gateway for Enterprise Token Optimization & Local Security.**

PhiGate is an OpenAI-compatible reverse proxy that sits between your AIOps tooling and
cloud LLMs. Instead of forwarding raw logs and code to the cloud, it **compresses,
anonymizes, and intelligently routes** traffic — cutting token spend while keeping
sensitive enterprise data (IPs, credentials, code, stack traces) inside your network.

> Status: **Steps 1–3 complete** — Compression & Anonymization, Intelligent Routing, and
> the Dynamic Security Sandbox (egress guardrail, including streaming) are all implemented.

## Architecture (3-stage pipeline)

1. **Compression & Anonymization Layer** *(implemented)* — `internal/compressor`
2. **Intelligent Routing Layer** *(implemented)* — `internal/router` + `internal/llm`
3. **Dynamic Security Sandbox** *(implemented)* — `internal/sandbox`

### Request path

```
POST /v1/chat/completions
   → compress + anonymize each message   (internal/compressor)
   → route local vs cloud                (internal/router, deterministic)
   → dispatch to backend                 (internal/llm, OpenAI-compatible)
        • local  = Phi-4-mini via Ollama  → cloud cost 0
        • cloud  = OpenAI-compatible LLM
        • local failure → automatic cloud fallback
   → hydrate the answer back to real values for the operator
   → egress guardrail inspects output    (internal/sandbox)
        • non-stream: full answer vetted, blocked answer redacted
        • stream (SSE): inspected line-by-line, destructive command
          withheld mid-stream before it reaches the client
```

The upstream model only ever sees `<V*>` / `#REF*` / AST placeholders. Response headers
`X-PhiGate-Route`, `X-PhiGate-Backend`, `X-PhiGate-Reason`, `X-PhiGate-Compression`, and
`X-PhiGate-Blocked` expose the routing decision, token savings, and any guardrail action.

### Egress guardrail (`internal/sandbox`)

A deterministic, rule-based deny list (`rm -rf`, `dd of=/dev/…`, `mkfs`, fork bombs,
`DROP TABLE`, pipe-to-shell, `shutdown`, `kubectl delete --all`, …). For streaming
responses the guard buffers whole lines so a command split across SSE chunks
(`rm -r` + `f /`) is still inspected as one unit and blocked before egress. Every block is
attributable to a named rule for audit.

### Routing policy (`internal/router`)

Deterministic and explainable: code/config structure or large/multi-template payloads →
**cloud**; recognized single-component infra errors or small payloads → **local**.

### Compression pipeline (`Masker → Drain → RefDict → ASTPrune`)

| Stage      | File              | What it does                                                        | Reversible? |
|------------|-------------------|---------------------------------------------------------------------|-------------|
| `Masker`   | `masker.go`       | Regex-masks IPs, UUIDs, timestamps, tokens, emails → `<V1>`, `<V2>` | Yes         |
| `Drain`    | `drain.go`        | Clusters near-identical log lines into one template (`<*>`, `(xN)`) | No (lossy)  |
| `RefDict`  | `refdict.go`      | Folds repeated long package paths → `#REF1`                         | Yes         |
| `ASTPrune` | `astprune.go`     | tree-sitter strips values from Go/Python code, keeps structure      | No (lossy)  |

Every reversible substitution is recorded in a session-bound, in-memory **Dictionary**
(`dictionary.go`) so responses can be **hydrated** back to original values for the operator.
Lossy stages (Drain, ASTPrune) trade exact reconstruction for token savings — by design.

## Requirements

- Go **1.23+**
- A C compiler (`gcc`/`clang`) — tree-sitter bindings require **`CGO_ENABLED=1`**
- For real routing: a local [Ollama](https://ollama.com) running `phi4-mini`, and/or a
  cloud API key. With neither, the gateway still boots and compresses; upstream calls fail.

## Configuration (env)

| Variable                  | Default                      | Purpose                          |
|---------------------------|------------------------------|----------------------------------|
| `PHIGATE_ADDR`            | `:8080`                      | listen address                   |
| `PHIGATE_LOCAL_BASE_URL`  | `http://localhost:11434/v1`  | local SLM (Ollama) endpoint      |
| `PHIGATE_LOCAL_MODEL`     | `phi4-mini`                  | local model tag                  |
| `PHIGATE_CLOUD_BASE_URL`  | `https://api.openai.com/v1`  | cloud LLM endpoint               |
| `PHIGATE_CLOUD_MODEL`     | `gpt-4o`                     | cloud model                      |
| `PHIGATE_CLOUD_API_KEY`   | (`OPENAI_API_KEY` fallback)  | cloud API key                    |
| `PHIGATE_SYSTEM_PREAMBLE` | built-in                     | tells the model about placeholders |

## Build, test, run

```bash
make build      # CGO_ENABLED=1 go build -o bin/phigate ./cmd/phigate
make test       # go test ./...
make run        # starts the gateway on :8080
```

## Endpoints

- `POST /v1/chat/completions` — OpenAI-compatible. Repoint your client's `base_url` here.
- `POST /debug/compress` — POST raw text, inspect `{compressed, hydrated, dictionary}`.
- `GET  /healthz`

### Try it

```bash
# Anonymization round trip
printf 'ERROR client 192.168.1.10 token Bearer abc123 retry 192.168.1.10' \
  | curl -s --data-binary @- localhost:8080/debug/compress

# AST pruning of a code snippet
printf 'func login(u string) bool { pw := "s3cret"; return u == "root" }' \
  | curl -s --data-binary @- localhost:8080/debug/compress

# Streaming (SSE) — the egress guardrail blocks destructive commands mid-stream
curl -N localhost:8080/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"disk full on 10.0.0.5"}]}'
```

## Layout

```
cmd/phigate/        server entrypoint
internal/
  compressor/       Compression & Anonymization Layer (core IP) + tests
  router/           Intelligent Routing Layer — local vs cloud classifier
  llm/              OpenAI-compatible client (local Ollama + cloud)
  config/           env-driven configuration
  gateway/          OpenAI-compatible HTTP surface, compress→route→dispatch→hydrate→guard
  sandbox/          Dynamic Security Sandbox — rule engine + streaming scanner
  types/            OpenAI-compatible wire structs
```
