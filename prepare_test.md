# Preparing a Real End-to-End Test for PhiGate

This guide walks through wiring PhiGate to a **real local SLM (Phi-4-mini via Ollama)** and a
**real cloud LLM (OpenAI API)**, then driving an end-to-end smoke test that exercises routing,
anonymization, and the streaming egress guardrail.

> Defaults are local-first: `config.FromEnv()` already points the local backend at Ollama and
> the cloud backend at OpenAI, so the **only strictly required** setting is your cloud API key.

---

## 1. Local SLM — Phi-4-mini via Ollama

```bash
# Install Ollama (Linux / WSL2)
curl -fsSL https://ollama.com/install.sh | sh

# WSL2 usually has no systemd, so start the server yourself in a spare terminal:
ollama serve            # leave running; listens on :11434

# Pull the model (~2.5 GB Q4; runs on CPU, just slower than on a GPU)
ollama pull phi4-mini

# Sanity-check Ollama's OpenAI-compatible endpoint (this is what PhiGate calls)
curl http://localhost:11434/v1/chat/completions \
  -d '{"model":"phi4-mini","messages":[{"role":"user","content":"say hi"}]}'
```

**Gotchas**

- **Model name must match exactly.** `PHIGATE_LOCAL_MODEL` has to equal what `ollama list`
  prints (it may be `phi4-mini:latest`). Run `ollama list` and copy that string.
- **WSL2 networking.** Install Ollama *inside* WSL so `localhost:11434` works. If you instead
  run Ollama on the Windows host, point the local base URL at the host IP:
  ```bash
  PHIGATE_LOCAL_BASE_URL=http://$(grep nameserver /etc/resolv.conf | awk '{print $2}'):11434/v1
  ```
- **CPU-only is fine** for phi4-mini (3.8B), but expect a few seconds per response. A GPU makes
  it snappy. Slow local latency is expected, not a bug.

---

## 2. Cloud — OpenAI API

Create an API key at <https://platform.openai.com>. Use `gpt-4o-mini` to keep test cost near
zero (the whole smoke test bills well under a cent); swap to `gpt-4o` for quality.

---

## 3. Configuration

Copy `.env.example` to `.env` and fill in your key. All values have sensible defaults except
`PHIGATE_CLOUD_API_KEY`.

```bash
# .env
PHIGATE_ADDR=:8080

# Client credentials — REQUIRED. Format "key:tenant,key:tenant".
# PhiGate refuses to start without this unless PHIGATE_ALLOW_ANONYMOUS=true:
# an unauthenticated gateway in front of a billed API key is an open relay.
PHIGATE_API_KEYS=local-test-key:dev

# Local SLM (Ollama, OpenAI-compatible)
PHIGATE_LOCAL_BASE_URL=http://localhost:11434/v1
PHIGATE_LOCAL_MODEL=phi4-mini          # match `ollama list`
PHIGATE_LOCAL_API_KEY=                 # Ollama ignores this

# Cloud LLM (OpenAI-compatible)
PHIGATE_CLOUD_BASE_URL=https://api.openai.com/v1
PHIGATE_CLOUD_MODEL=gpt-4o-mini
PHIGATE_CLOUD_API_KEY=sk-replace-me    # REQUIRED

# Your internal hostname suffixes, so topology is masked too.
PHIGATE_INTERNAL_DOMAINS=internal,corp,local

# ⚠️ Leave PHIGATE_DEBUG unset. /debug/compress returns the plaintext of every
# masked value, which is useful for this walkthrough but never in production.
# PHIGATE_DEBUG=true
```

---

## 4. Run PhiGate

```bash
cd /path/to/phigate
cp .env.example .env
$EDITOR .env                           # set PHIGATE_API_KEYS and PHIGATE_CLOUD_API_KEY

# Ensure the Go toolchain is on PATH, e.g. if you installed it outside the
# system prefix:
# export PATH="$HOME/sdk/go/bin:$PATH"
set -a; source .env; set +a            # load .env into the environment
make run                               # CGO_ENABLED=1, listens on :8080
```

On startup the gateway logs both backends so you can confirm config took effect:

```
local backend  : openai http://localhost:11434/v1 (model phi4-mini)
cloud backend  : openai https://api.openai.com/v1 (model gpt-4o-mini)
egress policy  : cloud egress <= internal; deny none; cloud fallback true
auth           : 1 API key(s) configured
```

---

## 5. Drive the smoke test (second terminal)

```bash
scripts/smoke_test.sh http://localhost:8080 local-test-key
```

It exercises each guarantee in turn and prints the telltale headers and body:

| # | Prompt | Expect | Proves |
|---|--------|--------|--------|
| 1 | no credentials | **401** | the gateway is not an open relay |
| 2 | `/debug/compress` | **404** | the plaintext endpoint is off by default |
| 3 | "connection refused on 10.0.0.5" | route **local** | Phi-4-mini answered; cloud cost 0 |
| 4 | a Go code snippet | route **cloud** | escalation to the larger model |
| 5 | 個人番号 1234 5678 9018 | policy **local_only** | My Number never leaves the network |
| 6 | a DSN with a password | sensitivity **restricted** | credentials are classified, not just masked |
| 7 | two alerts differing only in IP | second is a **cache hit** | template caching costs zero upstream tokens |
| 8 | `stream:true` asking for `rm -rf /` | ⛔ notice | the guardrail withholds it mid-stream |

---

## 6. How to read the results

- **Routing** — check the `X-PhiGate-Route` / `X-PhiGate-Backend` response headers and the
  gateway log lines (`route=local backend=local ...`).
- **Cost savings** — `X-PhiGate-Tokens-Saved` and `X-PhiGate-Compression` are per request;
  `GET /v1/phigate/stats` and `GET /dashboard` show the running totals in tokens and money.
  A locally-served request or a cache hit saves 100% of the cloud prompt, not just the
  compressed difference.
- **Egress policy** — `X-PhiGate-Policy` and `X-PhiGate-Sensitivity` show the classification
  and what it permitted. `local_only` means that payload could not have reached the cloud even
  if the local model had failed.
- **Guardrail** — the stream should contain the ⛔ notice with
  `finish_reason: content_filter`, and **never** the literal `rm -rf /`. Note that advice
  merely *mentioning* rebooting or shutting down is delivered normally: the guard reads
  commands, not prose.
- **Anonymization with real OpenAI** — you cannot observe OpenAI's inbound payload. To *watch*
  the masked payload leave the gateway, point `PHIGATE_CLOUD_BASE_URL` at a local echo server
  and read what it received. `PHIGATE_DEBUG=true` plus `/debug/compress` shows the same thing
  offline. The leak-corpus test (`go test ./internal/redact/ -run Leak`) asserts it
  continuously.
- **Your own data** — `bin/phigate-eval leak -dir /var/log/yourapp` reports what would be
  detected in your real logs, by classification and rule. Run it before trusting any of the
  above.

---

## 7. Optional: fully local, zero-cost variant

To exercise both routes without any OpenAI key, point the "cloud" backend at a second local
Ollama model:

```bash
PHIGATE_CLOUD_BASE_URL=http://localhost:11434/v1
PHIGATE_CLOUD_MODEL=llama3.1           # or any model you've `ollama pull`ed
PHIGATE_CLOUD_API_KEY=                 # not needed for Ollama
```

Now "local" routes hit phi4-mini and "cloud" routes hit the larger local model — same routing
logic and guardrail, no external calls, no cost.
