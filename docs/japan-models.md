# Japanese government-selected models (源内 / Gennai)

[日本語 README](../README.ja.md) · [English README](../README.md)

On 2026-03-06 the Digital Agency (デジタル庁) selected seven domestic LLMs for trial
use in **源内 (Gennai)**, the government-wide generative AI platform being rolled out
from May 2026 to roughly 180,000 staff across every ministry and agency.

This page is a connection guide: which PhiGate settings point the gateway at each
model. It is a lookup table, not a support matrix — see
[What "supported" means here](#what-supported-means-here) before you trust a row.

---

## PhiGate has no per-model code

There is nothing model-specific in this repository. `phi4-mini` is a default string in
[`internal/config/config.go`](../internal/config/config.go) and nothing else — no GGUF,
no llama.cpp binding, no downloader, no chat template, no stop tokens. Both backends
are plain HTTP against a chat-completions endpoint, and `ParseProvider` already treats
`ollama`, `vllm` and `compatible` as aliases for the OpenAI dialect.

Changing which model PhiGate talks to is configuration:

```bash
PHIGATE_LOCAL_MODEL=your-model
PHIGATE_LOCAL_BASE_URL=http://your-host:11434/v1
```

Four wire dialects are implemented — `openai`, `azure`, `anthropic`, `bedrock` — and
between them they cover every access mode in the table below. Nothing here requires a
code change to PhiGate.

## The product names are not model identifiers

The single most useful thing to know before wiring any of this up: **the names the
Digital Agency procured are vendor product names, and most of them do not correspond
to a public model identifier you can pull.**

"Sarashina2 mini" has no Hugging Face repository of that name. "PLaMo 2.0 Prime" is not
among the models the public PLaMo API currently serves. Four of the seven are
proprietary and are delivered as a hosted API or an on-premises appliance, with no
downloadable weights at all.

So the table has a *Nearest public artifact* column, and it is deliberately separate
from the Gennai name. They are not always the same weights.

## What "supported" means here

PhiGate's core contract is that the upstream model echoes anonymization placeholders —
`<V1>`, `<V2>`, `#REF1`, `<id>` — back **verbatim**, so they can be restored before the
operator sees the answer. The system preamble in
[`internal/config/config.go`](../internal/config/config.go) asks for exactly that.

If a model paraphrases those tokens, renumbers them, or helpfully expands them, the
restoration step produces a wrong answer and **says nothing**. There is no error. This
is the failure mode to care about, and it is model-dependent.

None of the seven has been measured against that contract. The *Status* column
therefore distinguishes two things that are easy to conflate:

| Status | Means |
|---|---|
| `connection documented` | The settings below are derived from vendor documentation. Nobody has run traffic through it. |
| `end-to-end verified` | Someone ran `scripts/smoke_test.sh` against it and confirmed placeholders survived. |

Every row is currently `connection documented`. Treat that honestly when quoting this
page to anyone.

---

## The seven

| Gennai name | Vendor | Nearest public artifact | Access | PhiGate slot · provider | Status |
|---|---|---|---|---|---|
| PLaMo 2.0 Prime | Preferred Networks | `plamo-2.2-prime`, `plamo-3.0-prime` | Hosted API, OpenAI-compatible | `cloud` · `openai` | connection documented |
| tsuzumi 2 | NTT | Microsoft Foundry catalog (`azureml-nttdatacorp`) | Managed compute; also single-GPU / on-prem | `cloud` or `local` · `azure` or `openai` | connection documented |
| Llama-3.1-ELYZA-JP-70B | KDDI · ELYZA | 70B: none. 8B: `elyza/Llama-3-ELYZA-JP-8B` | 70B is demo/API only — **weights are not downloadable**. The 8B is open. | 70B → `cloud`; 8B → `local` · `openai` | connection documented |
| Sarashina2 mini | SoftBank · SB Intuitions | `sbintuitions/sarashina2.2-3b-instruct-v0.1` and siblings | Open weights on Hugging Face, MIT for the main LMs | `local` · `openai` | connection documented |
| cotomi v3 | NEC | none | Proprietary, NEC-delivered | unverified | needs vendor docs |
| Takane 32B | Fujitsu | none | Proprietary (Kozuchi); on-prem operation is advertised | unverified | needs vendor docs |
| CC Gov-LLM | Customer Cloud | none | Proprietary, government-specific | unverified | needs vendor docs |

The three `unverified` rows are not oversights. Their wire protocol is not publicly
documented, and guessing it here would produce a configuration that fails at the first
request. Ask the vendor two questions — *does it expose an OpenAI-compatible
`/v1/chat/completions`?* and *how is the key passed?* — and if the answer to the first
is yes, they are a `provider=openai` backend like any other.

---

## Connection recipes

### PLaMo — Preferred Networks

The one Gennai model that works today with no caveats: the PLaMo API is explicitly
OpenAI-compatible (the vendor documents using `openai-python` and `langchain-openai`
against it) and authenticates with a bearer token, which is exactly what PhiGate's
OpenAI client sends.

```bash
PHIGATE_CLOUD_PROVIDER=openai
PHIGATE_CLOUD_BASE_URL=https://api.platform.preferredai.jp/v1
PHIGATE_CLOUD_MODEL=plamo-3.0-prime
PHIGATE_CLOUD_API_KEY=<your PLaMo key>
```

**Note the model name.** The Digital Agency selected "PLaMo 2.0 Prime", but the public
API currently serves `plamo-3.0-prime`, `plamo-3.0-prime-beta` and `plamo-2.2-prime`.
Check what your contract entitles you to rather than copying the Gennai name.

`plamo-3.0-prime` advertises a 262,144-token context and a 20,000-token output cap.
PhiGate does not model context windows, so a request that exceeds the window fails
upstream rather than being truncated by the gateway.

### tsuzumi 2 — NTT

Listed in the Microsoft Foundry model catalog under the `azureml-nttdatacorp` registry,
and NTT advertises single-GPU and on-premises operation.

Which dialect you need depends on how it is deployed, so confirm this before choosing:

- **Deployed through Azure OpenAI**, with a deployment name and an `api-version` query
  parameter — use `provider=azure`. PhiGate builds
  `{base}/openai/deployments/{name}/chat/completions?api-version=...`:

  ```bash
  PHIGATE_CLOUD_PROVIDER=azure
  PHIGATE_CLOUD_BASE_URL=https://<resource>.openai.azure.com
  PHIGATE_CLOUD_DEPLOYMENT=<deployment name>
  PHIGATE_CLOUD_API_VERSION=2024-10-21
  PHIGATE_CLOUD_API_KEY=<key>
  ```

- **Deployed as a serverless endpoint or self-hosted on your own GPU**, exposing a
  plain `/v1/chat/completions` — use `provider=openai` and point `BASE_URL` at it.

Self-hosted on your own hardware, tsuzumi belongs in the `local` slot, which keeps it
inside the egress policy boundary and makes it eligible for the routed-local path.

### ELYZA — KDDI · ELYZA

The 70B model the Digital Agency selected is **not downloadable**; it is reachable
through ELYZA's demo and commercial API. Point the `cloud` slot at whatever endpoint
your contract provides, after confirming the dialect.

The 8B sibling *is* openly published and is a realistic `local` backend today:

```bash
PHIGATE_LOCAL_PROVIDER=openai
PHIGATE_LOCAL_BASE_URL=http://localhost:11434/v1
PHIGATE_LOCAL_MODEL=<your ollama tag>
```

Ollama can pull GGUF directly from Hugging Face
(`ollama pull hf.co/<repo>:<quant>`); check the repository for the exact quantization
tags it publishes, then make `PHIGATE_LOCAL_MODEL` match `ollama list` **exactly** —
Ollama often appends `:latest`, and a mismatched name fails at the first request.

### Sarashina — SoftBank · SB Intuitions

SB Intuitions publishes the Sarashina language models openly on Hugging Face under MIT
(the TTS variant is a non-commercial licence — check the specific repository you use,
not the family). There is no repository named "Sarashina2 mini"; the published
instruct-tuned models run from 0.5B to 3B, with larger 7B/70B base models available.

At 3B this is a plausible replacement for `phi4-mini` in the `local` slot for a
Japanese deployment, where it has two jobs the default is weak at: answering
locally-routed queries in Japanese, and adjudicating Japanese personal names for the
Enterprise Edition name recognizer.

GGUF conversions are community-published rather than official — verify the provenance
of whichever conversion you pull before running it against production traffic.

---

## Where PhiGate sits relative to Gennai

Gennai being a government platform does not remove the reason PhiGate exists. A
ministry still has logs, stack traces and ticket text that should not leave its own
boundary in raw form, and "the endpoint is domestic" is a statement about jurisdiction,
not about what gets written into a vendor's request logs.

The natural arrangement is unchanged: a small open-weight Japanese model in the `local`
slot handling short and sensitive traffic, a Gennai-selected model in the `cloud` slot
for everything that genuinely needs it, and the compression, anonymization and egress
policy in between. The redaction engine, the Drain templating and the classifier are
deterministic Go and behave identically whichever model sits on either side.

## Validating a model yourself

Until a row says `end-to-end verified`, this is how to move it there.

1. Point a backend at the model using the recipe above.
2. Run `scripts/smoke_test.sh`. A 200 proves the dialect and credentials are right.
3. Send a payload dense in values that will be masked — IPs, hostnames, tokens — and
   read the **raw upstream answer** with `PHIGATE_DEBUG=true`, not the restored one.
   Confirm the model repeated `<V1>`, `#REF1` and friends exactly, rather than
   paraphrasing or renumbering them.
4. For a local model, also check throughput. `PHIGATE_LOCAL_TIMEOUT` defaults to a
   value tuned for phi4-mini at roughly 3.9 tokens/second on CPU; a larger model on the
   same hardware will need it raised.

If you do this for one of the seven, the result is worth contributing back — a measured
row helps everyone else reading this page.

---

## Sources

- [ITmedia — デジタル庁、国産7モデルを検証](https://www.itmedia.co.jp/aiplus/articles/2603/06/news097.html)
- [PLaMo API reference](https://docs.plamo.preferredai.jp/en/api) · [PFN — PLaMo Prime](https://www.preferred.jp/en/news/pr20241202)
- [Microsoft Foundry model catalog — tsuzumi 2](https://ai.azure.com/explore/models/tsuzumi2/version/2/registry/azureml-nttdatacorp-p/) · [NTT R&D — tsuzumi](https://www.rd.ntt/e/research/LLM_tsuzumi.html)
- [ELYZA — Llama-3-ELYZA-JP collection](https://huggingface.co/collections/elyza/llama-3-elyza-jp-667a311d51c8952e07778ecc)
- [SB Intuitions — Sarashina2.2 collection](https://huggingface.co/collections/sbintuitions/sarashina22)
