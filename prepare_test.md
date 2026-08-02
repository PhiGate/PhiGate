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

# Local SLM (Ollama, OpenAI-compatible)
PHIGATE_LOCAL_BASE_URL=http://localhost:11434/v1
PHIGATE_LOCAL_MODEL=phi4-mini          # match `ollama list`
PHIGATE_LOCAL_API_KEY=                 # Ollama ignores this

# Cloud LLM (OpenAI-compatible)
PHIGATE_CLOUD_BASE_URL=https://api.openai.com/v1
PHIGATE_CLOUD_MODEL=gpt-4o-mini
PHIGATE_CLOUD_API_KEY=sk-replace-me    # REQUIRED
```

---

## 4. Run PhiGate

```bash
cd /mnt/c/Users/info/work/phigate
cp .env.example .env
nano .env                              # set PHIGATE_CLOUD_API_KEY

# Go must be on PATH (installed at ~/sdk/go/bin in this environment).
export PATH="$HOME/sdk/go/bin:$PATH"
set -a; source .env; set +a            # load .env into the environment
make run                               # CGO_ENABLED=1, listens on :8080
```

On startup the gateway logs both backends so you can confirm config took effect:

```
local backend : http://localhost:11434/v1 (model phi4-mini)
cloud backend : https://api.openai.com/v1 (model gpt-4o-mini)
```

---

## 5. Drive the smoke test (second terminal)

```bash
scripts/smoke_test.sh http://localhost:8080
```

It exercises four behaviors and prints the telltale headers/body:

| # | Prompt                                  | Expect `X-PhiGate-Route` | Proves                               |
|---|-----------------------------------------|--------------------------|--------------------------------------|
| 1 | "connection refused on 10.0.0.5"        | **local**                | Phi-4-mini answered, cloud cost = 0  |
| 2 | a Go code snippet                       | **cloud**                | escalation to the cloud model        |
| 3 | `/debug/compress` with IP+email+token   | —                        | values masked to `<V*>` before egress|
| 4 | `stream:true`, asks for `rm -rf /var/data` | —                     | guardrail redacts mid-stream         |

---

## 6. How to read the results

- **Routing** — check the `X-PhiGate-Route` / `X-PhiGate-Backend` response headers and the
  gateway log lines (`route=local backend=local ...`).
- **Cost savings** — `X-PhiGate-Compression: NN% saved` shows tokens trimmed before the cloud
  call.
- **Guardrail** — in test #4 the stream should contain the ⛔ redaction line with
  `finish_reason: content_filter`, and **never** the literal `rm -rf`.
- **Anonymization with real OpenAI** — you can't observe OpenAI's inbound payload, but test #3
  (`/debug/compress`) shows exactly what *would* be sent, and the unit tests already assert the
  upstream request carries no raw IP. To *watch* the masked payload leave the gateway,
  temporarily point `PHIGATE_CLOUD_BASE_URL` at a local echo upstream.

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
