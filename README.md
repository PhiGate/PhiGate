# PhiGate

**The Next-Gen SLM Gateway for Enterprise Token Optimization & Local Security.**

[日本語 README](README.ja.md) · [Threat model](THREAT-MODEL.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

PhiGate is an OpenAI-compatible reverse proxy between your AIOps tooling and cloud
LLMs. Instead of forwarding raw logs and code to a third party, it **compresses,
anonymizes, classifies, routes and vets** every request — cutting token spend
while keeping sensitive data inside your network.

Repoint your client's `base_url` at PhiGate. Nothing else changes.

---

## What it actually guarantees

Both of PhiGate's selling points are empirical, so both have tests that fail when
they stop being true. Run them yourself:

| Claim | Enforced by | Verify with |
|---|---|---|
| No credential or personal datum leaves unmasked | [`internal/redact`](internal/redact/) | `go test ./internal/redact/ -run Leak` |
| …including inside tool calls, which carry no message content at all | [`internal/gateway`](internal/gateway/) | `go test ./internal/gateway/ -run ToolCall` |
| A value is never *partially* masked | single-pass overlap resolution | same test — partial leaks fail it |
| Data above your sensitivity limit never reaches the cloud, even on failure | [`internal/policy`](internal/policy/) | `go test ./internal/policy/` |
| Catastrophic commands never reach the operator | [`internal/sandbox`](internal/sandbox/) | `go test ./internal/sandbox/` |
| The guard does **not** block ordinary prose | same | `-run TestGuardDoesNotBlockProse` |
| A streamed answer is guarded exactly as a non-streamed one | [`internal/sandbox`](internal/sandbox/) | `go test ./internal/sandbox/ -run TestStreamingAgrees` |
| The cache never serves one session's values to another | [`internal/cache`](internal/cache/) | `go test ./internal/gateway/ -run Cache` |
| …and never answers one question with another's answer | shape keying is exact matching | `go test ./internal/gateway/ -run Shape` |
| Audit records contain no raw values | [`internal/audit`](internal/audit/) | the `Event` type has no field that can hold one |

Then measure it on **your** data:

```bash
./bin/phigate-eval leak  -dir /var/log/yourapp    # what gets detected, by class and rule
./bin/phigate-eval bench -dir /var/log/yourapp    # token reduction per pipeline stage
./bin/phigate-eval eval  -cases eval/cases.json   # answer quality: raw vs through PhiGate
```

The last one is the important one. It sends each case twice — once raw to the
cloud model, once through PhiGate — and has a judge model score both. A savings
number without a quality number beside it is the figure every buyer already
distrusts.

---

## Measured results

Numbers below are from the **public [LogHub](https://github.com/logpai/loghub)
corpora** — 15,994 lines of real system logs collected by researchers with no
stake in PhiGate's figures. Reproduce them in two commands:

```bash
scripts/fetch-benchmark-corpus.sh
./bin/phigate-eval bench -dir eval/corpus
```

| Dataset | Raw tokens | After pipeline | Reduction |
|---|---:|---:|---:|
| Apache | 72,346 | 335 | 99.5% |
| OpenSSH | 87,540 | 538 | 99.4% |
| Spark | 77,682 | 802 | 99.0% |
| Zookeeper | 115,973 | 1,138 | 99.0% |
| Linux | 88,563 | 950 | 98.9% |
| BGL | 160,587 | 3,749 | 97.7% |
| HDFS | 103,869 | 4,015 | 96.1% |
| Thunderbird | 143,187 | 10,573 | 92.6% |
| **All eight** | **849,747** | **22,100** | **97.4%** |

**Read these with their caveats.** These are 2,000-line samples of highly
repetitive machine logs — Drain's best case, and the traffic PhiGate is built
for. A mixed workload with more prose and less repetition will land lower. The
figure measures compression only; requests the router keeps local, and template
cache hits, avoid 100% of cloud prompt cost rather than 97%.

**Where the saving actually comes from — and doesn't.** Masking contributes
between **−10.5% and +7.5%** depending on dataset. It sometimes makes prompts
*larger*, because a distinct value replaced by a distinct `<V1234>` placeholder
costs about what the value did. Essentially all reduction is Drain's. The masking
stage is a privacy control whose contribution to cost is indirect: normalising
values is what allows a thousand log lines to collapse into one template.

We publish that because a compression stage that pays for itself only indirectly
is exactly the detail a vendor is tempted to leave out.

### Detection coverage on the same corpus

```bash
./bin/phigate-eval leak -dir eval/corpus
```

59,343 sensitive spans across the eight datasets: 391 credential-class
(entropy-detected session tokens), 3 personal, 20,171 network, 3,694 path,
35,084 identifier. Running this against **your own** logs before adopting
PhiGate is the point of the tool.

### Answer quality

Measured 2026-09-12 against question (a) below — the pipeline alone. Both arms
answer with `claude-sonnet-5`, the judge is `claude-sonnet-5`, five runs per
case, and the gateway ran with `PHIGATE_CACHE_ENABLED=false` so both arms
generate afresh rather than one of them replaying a cached answer.

| Case | Raw | PhiGate | Delta |
|---|---|---|---|
| nginx-upstream-timeout | 8.60 ±0.80 | 9.00 ±0.00 | +0.40 |
| oomkilled-pod | 9.40 ±0.49 | 9.40 ±0.49 | +0.00 |
| multi-component-cascade | 9.00 ±0.00 | 9.00 ±0.00 | +0.00 |
| high-placeholder-density | 9.00 ±0.00 | 9.00 ±0.00 | +0.00 |
| code-connection-leak | 9.40 ±0.49 | 10.00 ±0.00 | +0.60 |
| japanese-incident-ticket | 8.80 ±0.40 | 9.00 ±0.00 | +0.20 |
| disk-full-remediation | 8.60 ±0.80 | 7.20 ±2.14 | −1.40 |
| tls-cert-expiry | 7.20 ±1.72 | 8.40 ±0.49 | +1.20 |
| **All eight** | **8.75** | **8.88** | **+0.12** |

**+0.12 does not mean PhiGate improves answers.** The largest per-case spread is
±2.14 on the same scale, so a mean delta of a tenth of a point is judge noise
and the honest reading is that there is no measurable quality difference between
answering the raw prompt and answering the compressed, anonymised one. That is
the claim this table supports, and it is the one worth making.

**`disk-full-remediation` is the row with a history.** An earlier run of this
same benchmark scored it **1.60 against a raw 9.00**, because the egress guard
withheld the *whole* response over one `find ... -delete` in a four-step
remediation — the `du` hunt, the `lsof` check for deleted-but-open files and the
log-rotation advice went with it. That was a real defect, it was found by this
benchmark rather than by argument, and it is fixed: a block now cuts out the
span the rule matched and delivers the rest. The row above is the same case
re-measured against the fixed build. The −7.40 that exposed the defect is kept
in the [changelog](CHANGELOG.md) rather than erased, because a number a vendor
improves quietly is one a reader should distrust.

**A correction, on the record.** An earlier run scored `tls-cert-expiry` at
−1.00 and this README explained it: `internal_hostname` masks `api.internal.corp`
to `<V1>`, and that hostname is the clue that the chain comes from a private CA.
The masking is real and worth knowing about. The quality cost attributed to it
was not — the same case scores **+1.20** here, and both figures sit inside a
±1.72 spread. It was a story built on one sample, which is exactly what the
second caveat below warns against. The mechanism stands; the price tag does not.

Prompt-token saving on the same run: **64.2%**, unchanged from the earlier run —
compression and routing are deterministic, so only the judged columns move. Almost all of it is routing
rather than compression — the five locally-routed cases avoid the cloud call
entirely, while the three that do reach the cloud compress by 0.6–11%. The
97.4% in the compression table above is the same pipeline on bulk logs, which
is the shape Drain has most to work with; eight short incident questions are
the shape it has least. Quote whichever matches the traffic you send, and say
which one you quoted. Note also that this run pinned the local backend to a
paid API to hold the model constant, so a locally-routed case avoided the cloud
call without being free; in a deployment where local inference is your own
hardware, it is.

Reproduce it, or price it first:

```bash
./bin/phigate-eval eval -cases eval/cases.json -dry-run -repeat 5
```

**There are two questions here, and one number cannot answer both.** The
harness runs either, and which one you want changes how you configure the
gateway before running it.

**(a) Does the pipeline itself degrade answers?** Both arms have to use the same
model, or the result includes a model change rather than measuring compression.
Point the local backend at the cloud one, so routing cannot decide which model
answers and the only variable left is compress → anonymise → hydrate:

```bash
PHIGATE_LOCAL_BASE_URL=https://api.openai.com/v1 \
PHIGATE_LOCAL_MODEL=gpt-4o \
PHIGATE_LOCAL_API_KEY=$OPENAI_API_KEY \
  ./bin/phigate-eval eval -cases eval/cases.json -repeat 5 \
    -gateway http://localhost:8080/v1 -gateway-key <key> \
    -baseline https://api.openai.com/v1 -baseline-key $OPENAI_API_KEY
```

**(b) What quality does a real deployment get?** The same command without those
overrides, so the router does what it normally does and some cases are answered
by the local SLM. That is the number a buyer cares about, and it measures the
pipeline *and* the routing together. Reporting it as an answer to (a) would be
wrong, which is why the two are separated here.

`-baseline-provider` selects the dialect of the raw arm — `openai`, `azure`,
`anthropic` or `bedrock` — so the comparison is against whatever you actually
use today.

**These numbers carry three caveats**, and none of them is incidental:

- Unlike the compression table above, they do **not** come from a third-party
  corpus. `eval/cases.json` holds eight cases written by this project, chosen to
  include the payloads PhiGate finds hardest — high placeholder density,
  AST-pruned code, Japanese text. That is a sanity check, not an independent
  benchmark.
- A judge model is not deterministic, so a single score per case is a sample.
  `-repeat` runs each case several times and reports the spread; a delta smaller
  than the spread is noise, not a finding.
- The judge shares a model family with the answers, which biases it. The same
  judge scores both arms, so the bias largely cancels in the *delta*, which is
  the figure that matters. The absolute scores are not comparable to any other
  benchmark's; the delta is the only column worth quoting.

**This table is a measurement, not a guarantee**, and the difference is the one
the guarantee table above is built on. The leak corpus and the policy tests run
in CI and fail the build when a claim stops holding. Answer quality cannot: it
costs real money per run and needs credentials no CI job should hold. So the
figure is dated, the command that produced it is written down, and it will drift
silently until someone re-runs it. Treat it as you would a benchmark in a paper —
evidence that a specific build behaved a specific way on a specific day.

Savings are read from the first run of each case, on a cold cache. Later repeats
are exact cache hits that save the whole baseline, and taking one of those would
make the headline improve the more times you ran it.

The number that should convince your organisation is the one measured on your
own ticket history. Extend the file and run it.

---

## Request path

```
POST /v1/chat/completions
  → authenticate, resolve the tenant       per-tenant policy and rule set
  → check the tenant's token budget        internal/gateway    ← 429 when spent
  → screen for prompt injection            internal/sandbox  (ingress)
  → compress + anonymize                   internal/compressor + internal/redact
      message content, tool-call arguments, and tool descriptions
  → classify what was found                secret / pii / network / identifier / …
  → EGRESS POLICY decides where it may go  internal/policy     ← binding
  → template cache lookup                  internal/cache      ← keyed on shape
  → route local vs cloud                   internal/router     ← advisory
  → dispatch (retry + circuit breaker)     internal/llm
      OpenAI | Azure OpenAI | Anthropic | Amazon Bedrock
  → hydrate back to real values            + enumeration guard
  → inspect the answer                     internal/sandbox    (egress)
      prose *and* tool-call arguments
  → account for it                         internal/tokens     tokens + money
  → audit                                  internal/audit      structured JSON
```

**Policy outranks routing.** The router asks which backend is cheapest; the
policy asks which backends this payload is *permitted* to reach. When the two
disagree, the policy wins — including when the local backend fails. A payload
confined to local does not fall back to the cloud. It fails.

---

## The three ideas worth knowing

### 1. The template cache is the real cost lever — and it is keyed on *shape*

AIOps traffic is extraordinarily repetitive: the same disk-full alert thousands
of times a day, differing only in the IP, timestamp and request id. A normal
cache never hits, because those values make every prompt unique.

PhiGate has already replaced exactly those values with placeholders before the
cache is consulted. But placeholders alone are not enough, and measuring it is
what showed why. The session dictionary numbers a value the first time it is
*ever* seen — which is what makes hydration work, since `<V7>` has to mean one
particular host for a whole conversation — so the same log line arriving an hour
apart compresses to `<V7> failed` and `<V931> failed`. Keyed on that text, they
were different keys, and the cache missed on two payloads that are the same
payload.

Measure it yourself, on the same corpus the table above uses:

```bash
./bin/phigate-eval cache -dir eval/corpus
```

| Keyed on | Hit rate over 16,000 lines |
|---|---:|
| the compressed text | **4.5%** |
| the compressed **shape** (placeholders renumbered per payload) | **50.5%** |

So the key is built on the shape. This is still *exact* matching — two payloads
share a key only if they are identical once their placeholders are renumbered —
so the cache still cannot answer one question with another's answer. Entries are
stored in canonical form and translated back into the requesting payload's own
numbering before hydration.

The remaining 44.9% are payloads whose shape occurs exactly once in the corpus.
That is the entire headroom a semantic tier could ever compete for, and it could
only convert them by matching a payload to a *different* one — which is where a
wrong answer comes from, and which the exact-match cache cannot do at all.

The cache stores answers **before** hydration and keys them on a hash, so it
holds no customer data at all and is safe to share across tenants — each session
hydrates the shared answer with its own dictionary.

### 2. Classification is a control, not a label

Every detected value carries a classification, and the highest one in a payload
decides where that payload may go:

| Class | Examples | Default |
|---|---|---|
| `restricted` | API keys, private keys, JWTs, passwords | **local only** |
| `confidential` | My Number, cards, phone, email, address | **local only** |
| `internal` | IPs, MACs, internal hostnames, paths | cloud OK (masked) |
| `low` | UUIDs, hashes, timestamps | cloud OK (masked) |

Set `PHIGATE_CLOUD_MAX_SENSITIVITY=low` for the strictest posture, or
`PHIGATE_DENY_ABOVE_SENSITIVITY=confidential` to refuse such requests outright.

### 3. The guard reads commands, not prose

The egress guard extracts what could plausibly be *executed* — fenced code,
inline code, unambiguous command lines — lexes it into argv, and matches on
program and flags:

```
"if that fails, reboot the node"     → allowed  (prose)
"graceful shutdown via SIGTERM"      → allowed  (prose)
sudo reboot                          → warn     (legitimate remediation)
rm -rf ./build                       → warn     (scoped)
rm --force --recursive /             → BLOCK    (a regex deny list misses this)
```

Severity tiers exist because blocking every destructive-looking operation is how
a guardrail gets switched off — and a guardrail that is off protects nothing.

**A block withholds the command, not the answer around it.** The offending span
is cut out and replaced with a notice naming the rule; the investigation steps,
the explanation and any other code blocks are delivered untouched. What is
returned is clean by construction rather than by inspection — the redaction unit
is never smaller than the span the rule matched, and re-inspecting the result is
never blocked, which is a property test run over the same fuzz corpus as the
stream scanner. Tool calls are the exception and are dropped whole: an argument
list is not prose, there is nothing in it worth keeping, and an agent handed the
call would execute it.

This matters more than it sounds. Measured on `eval/cases.json`, replacing the
whole response cost 7.4 points out of 10 on a full-`/var` remediation — the `du`
hunt, the `lsof` check and the log-rotation advice went out with the one command
that earned the block, on the most common emergency in the job.

**Streamed answers stop at the block instead.** Everything vetted before that
point has already been sent and is safe to read; the tail is not sent. The
scanner holds a unit, inspects it, and seals once a rule fires, because there is
no safe way to resume a state machine whose invariant is that nothing after a
block is emitted. The notice says so and says to re-request without streaming to
get the full answer with the span cut out. Both transports agree on *whether* a
rule fired and on which one — that is
[`parity_test.go`](internal/sandbox/parity_test.go) — and neither emits the
command.

---

## Quick start

**Evaluate the whole thing in one command — no cloud API key, nothing leaves the
machine:**

```bash
docker compose up
```

That brings up PhiGate, a local Phi-4-mini on [Ollama](https://ollama.com) (pulled
for you) and Prometheus. The egress limit is set to `low`, so anything carrying a
hostname, an IP or a path is pinned to the local model by
[`internal/policy`](internal/policy/) rather than by intention. Then:

```bash
curl localhost:8080/v1/chat/completions \
  -H 'Authorization: Bearer demo-key' -H 'Content-Type: application/json' \
  -d '{"model":"phi4-mini","messages":[
        {"role":"user","content":"nginx upstream timeout to 10.24.8.19, help"}]}'
```

`docker compose logs phigate` shows the audit record for that request — which
rules fired, where it was routed, and why. The dashboard is at
[localhost:8080/dashboard](http://localhost:8080/dashboard), metrics at
[localhost:9090](http://localhost:9090).

To reproduce the published benchmark, or to measure your own logs:

```bash
scripts/fetch-benchmark-corpus.sh              # eval/corpus is fetched, not vendored
docker compose run --rm bench                  # the table above
docker compose run --rm -v /var/log:/data:ro bench -dir /data   # your data
```

Add a cloud model when you want to compare against one:
`PHIGATE_CLOUD_API_KEY=sk-... PHIGATE_CLOUD_MAX_SENSITIVITY=internal docker compose up`.

### Or run the gateway alone

```bash
docker run -p 8080:8080 \
  -e PHIGATE_API_KEYS="my-client-key:team-sre" \
  -e PHIGATE_CLOUD_API_KEY="sk-..." \
  -e PHIGATE_INTERNAL_DOMAINS="internal,corp" \
  ghcr.io/phigate/phigate:latest
```

Or from source (needs Go 1.26+ and a C compiler — tree-sitter uses cgo):

```bash
make build && make run
```

Then point any OpenAI client at it:

```python
client = OpenAI(base_url="http://localhost:8080/v1", api_key="my-client-key")
```

```bash
curl localhost:8080/v1/chat/completions \
  -H 'Authorization: Bearer my-client-key' -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o","messages":[
        {"role":"user","content":"nginx upstream timeout to 10.24.8.19, help"}]}'
```

The response carries what PhiGate did, in headers and in a `phigate` block:

```
X-PhiGate-Route: local            X-PhiGate-Policy: allow
X-PhiGate-Sensitivity: internal   X-PhiGate-Tokens-Saved: 61
X-PhiGate-Compression: 78% saved
```

### Embeddings, for RAG

In a retrieval deployment the text sent for embedding **is** the corpus — the
tickets, the contracts, the notes. It is the most sensitive traffic a gateway
will ever see, and guarding the questions while the documents go straight to the
provider is guarding the wrong half.

```bash
curl localhost:8080/v1/embeddings -H 'Authorization: Bearer my-client-key' \
  -H 'Content-Type: application/json' -H 'X-PhiGate-Session: corpus-1' \
  -d '{"model":"text-embedding-3-small","input":["従業員 1234 5678 9018 の記録"]}'
```

Inputs are masked and classified like any other payload, and the egress policy
binds: a corpus it confines to local is embedded locally or not at all.

One property decides whether a deployment works. The vectors describe the
**masked** text, so the index holds embeddings of masked text — and a query
embedded through the same gateway with the same session dictionary is masked the
same way, so retrieval matches. Index through PhiGate and query around it and it
will not. That is the design, not a defect in it.

**Kubernetes:** `helm install phigate deploy/helm/phigate --set secrets.apiKeys="key:team"`

---

## Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/chat/completions` | ✅ | OpenAI-compatible, streaming and blocking |
| `POST /v1/embeddings` | ✅ | inputs masked before they leave; the egress policy binds |
| `GET /v1/models` | ✅ | model listing (clients call this on startup) |
| `GET /v1/phigate/stats` | ✅ | tokens and money saved, cache, backends |
| `GET /v1/phigate/rules` | ✅ | effective controls, for auditors |
| `GET /metrics` | ✅ | Prometheus exposition |
| `GET /dashboard` | ✅ | single-page ops view, embedded, no CDN |
| `GET /healthz` | — | liveness |
| `GET /readyz` | — | readiness; probes both backends |
| `POST /debug/compress` | ✅ | **off by default** — returns plaintext |

---

## Configuration

Everything below can also come from a JSON file named by `PHIGATE_CONFIG`.
Precedence is **defaults → file → environment**: the file is the declared state
you version-control and an auditor reads, and the environment is where a
container's secrets live and where you reach during an incident, so an emergency
`PHIGATE_CLOUD_MAX_SENSITIVITY=low` is never overruled by a checked-in file.
An unknown key in the file is a startup error — a misspelled key accepted and
ignored is a control that silently does nothing.

**Per-tenant controls.** The tenant label in `PHIGATE_API_KEYS="key:tenant"` can
carry its own egress policy, rate limit and rule packs, so one gateway serves a
finance team and an SRE team under different rules instead of two deployments:

```json
{
  "api_keys": { "sre-key": "team-sre", "fin-key": "team-finance" },
  "policy":   { "cloud_max_sensitivity": "internal" },
  "tenants": {
    "team-finance": {
      "policy": { "cloud_max_sensitivity": "low" },
      "rate_limit_per_min": 60,
      "redact_packs": ["core", "jp", "secrets"]
    }
  }
}
```

A tenant may **narrow** what the operator configured, never widen it: a tenant
policy above the global ceiling is a startup error, as is a tenant block whose
label no API key maps to. `GET /v1/phigate/rules` answers for the calling
tenant, so an auditor sees the rules their own traffic is subject to.

**Reload without restarting.** `kill -HUP` re-reads the file. No listener is
closed, no connection is dropped, and a streaming completion in flight finishes
under the configuration it started with. API keys, policy thresholds, rate
limits, rule packs, guard severities and tenant blocks all take effect on the
next request; a rule change purges the template cache, because every key in it
was derived under rules that no longer apply. The address, the metrics path and
whether the dashboard and debug endpoints exist are read once at startup and
still need a restart. A reload that fails validation is a **no-op that says so**
— the whole configuration is built before any of it is published, so a malformed
edit leaves the running gateway exactly as it was.

Only `PHIGATE_API_KEYS` and `PHIGATE_CLOUD_API_KEY` are required. PhiGate
**refuses to start** without client credentials unless you set
`PHIGATE_ALLOW_ANONYMOUS=true`, because an unauthenticated gateway in front of a
billed API key is an open relay.

<details>
<summary><b>Backends</b> — OpenAI-compatible or Azure OpenAI</summary>

| Variable | Default | Purpose |
|---|---|---|
| `PHIGATE_LOCAL_PROVIDER` | `openai` | `openai` \| `azure` \| `anthropic` \| `bedrock` |
| `PHIGATE_LOCAL_BASE_URL` | `http://localhost:11434/v1` | Ollama / vLLM / llama.cpp |
| `PHIGATE_LOCAL_MODEL` | `phi4-mini` | must match `ollama list` exactly |
| `PHIGATE_CLOUD_PROVIDER` | `openai` | `azure`, `anthropic` or `bedrock` |
| `PHIGATE_CLOUD_BASE_URL` | `https://api.openai.com/v1` | Azure: the resource root |
| `PHIGATE_CLOUD_MODEL` | `gpt-4o` | |
| `PHIGATE_CLOUD_API_KEY` | (`OPENAI_API_KEY`) | |
| `PHIGATE_CLOUD_API_VERSION` | `2024-10-21` | Azure only |
| `PHIGATE_CLOUD_DEPLOYMENT` | (model name) | Azure deployment name; on Bedrock, an inference profile ARN |
| `PHIGATE_CLOUD_REGION` | (`AWS_REGION`) | Bedrock only |
| `PHIGATE_CLOUD_ACCESS_KEY_ID` | (`AWS_ACCESS_KEY_ID`) | Bedrock only |
| `PHIGATE_CLOUD_SECRET_ACCESS_KEY` | (`AWS_SECRET_ACCESS_KEY`) | Bedrock only |
| `PHIGATE_CLOUD_SESSION_TOKEN` | (`AWS_SESSION_TOKEN`) | Bedrock only, for temporary credentials |

**Claude, first-party or on Bedrock.** Neither speaks OpenAI's wire format, so
they are dialects PhiGate translates to rather than base URLs it points at —
system prompts move to a top-level field, `max_tokens` becomes required, and
content is a list of typed blocks. Tool calls are translated in both directions,
so they are masked and guarded exactly as on any other backend.

```json
{ "cloud": { "provider": "anthropic", "model": "claude-opus-5",
             "base_url": "https://api.anthropic.com", "api_key": "sk-ant-..." } }
```

```json
{ "cloud": { "provider": "bedrock", "model": "anthropic.claude-opus-5",
             "base_url": "https://bedrock-runtime.ap-northeast-1.amazonaws.com",
             "region": "ap-northeast-1" } }
```

Bedrock requests are SigV4-signed. Credentials come from the backend config or
the standard `AWS_*` environment variables; **the full AWS credential chain —
instance metadata, SSO, profile files, AssumeRole — is not implemented**, and a
Bedrock backend with no region or no credentials fails at startup rather than on
the first request. Bedrock **streaming is not supported**: its event stream is a
binary framing rather than SSE, and the backend says so plainly instead of
pretending. Use a non-streaming request, or the first-party API.

**Changing the model needs no code.** There is nothing model-specific in this
repository — `phi4-mini` is a default string, not an integration. For the seven
domestic models Japan's Digital Agency selected for the 源内 (Gennai) government
platform — PLaMo, tsuzumi 2, ELYZA, Sarashina and three proprietary others — see
[docs/japan-models.md](docs/japan-models.md), which documents how to connect each
one and is explicit that connecting is not the same as having validated it.

</details>

<details>
<summary><b>Access control</b></summary>

| Variable | Default | Purpose |
|---|---|---|
| `PHIGATE_API_KEYS` | — | `key1:tenant-a,key2:tenant-b` |
| `PHIGATE_ALLOW_ANONYMOUS` | `false` | run with no auth (not for production) |
| `PHIGATE_RATE_LIMIT_PER_MIN` | `0` | per-tenant limit; 0 = unlimited |
| `PHIGATE_TRUSTED_PROXY_HEADER` | — | e.g. `X-Forwarded-For`; set only if a proxy you control sets it |

</details>

<details>
<summary><b>Redaction</b></summary>

| Variable | Default | Purpose |
|---|---|---|
| `PHIGATE_REDACT_PACKS` | all | `core`, `jp`, `secrets` |
| `PHIGATE_INTERNAL_DOMAINS` | `internal,corp,local,lan,intra` | hostname suffixes to mask |
| `PHIGATE_REDACT_RULE_DIR` | — | directory of your own `*.json` rule packs |
| `PHIGATE_REDACT_DISABLE` | — | rule names to switch off |
| `PHIGATE_REDACT_DISABLE_ENTROPY` | `false` | turn off unknown-secret detection |

Run `phigate -rules` to print every rule and its classification.

</details>

<details>
<summary><b>Egress policy, guardrails, cache, accounting, observability</b></summary>

| Variable | Default | Purpose |
|---|---|---|
| `PHIGATE_CLOUD_MAX_SENSITIVITY` | `internal` | highest class allowed to reach the cloud |
| `PHIGATE_DENY_ABOVE_SENSITIVITY` | none | refuse such requests entirely |
| `PHIGATE_ALLOW_CLOUD_FALLBACK` | `true` | only ever applies to cloud-eligible payloads |
| `PHIGATE_GUARD_SEVERITY` | — | `host_power_state=block,sql_truncate=warn` |
| `PHIGATE_INGRESS_SCAN` | `true` | prompt-injection screening |
| `PHIGATE_CACHE_ENABLED` / `_TTL` / `_MAX` | `true` / `15m` / `5000` | template cache |
| `PHIGATE_SESSION_TTL` / `_MAX` | `30m` / `10000` | multi-turn dictionary continuity |
| `PHIGATE_PRICE_BOOK` | — | your negotiated rates, in your currency. The built-in table is list prices for OpenAI, Anthropic and Gemini; Bedrock and Vertex are partner-operated with separate rates and are deliberately **unpriced** rather than aliased onto first-party ones — a request on an unpriced model is counted in `unpriced_requests` on `/v1/phigate/stats`, which is visible in a way that a confidently wrong figure is not |
| `PHIGATE_LOCAL_COST_PER_MTOK` | `0` | amortise local hardware if finance wants it |
| `PHIGATE_AUDIT_LOG` | stderr | JSON audit destination |
| `PHIGATE_DEBUG` | `false` | ⚠️ `/debug/compress` returns plaintext |

**Multi-turn:** send `X-PhiGate-Session: <conversation-id>` so the same value
maps to the same placeholder across turns.

</details>

---

## Compression pipeline

| Stage | What it does | Reversible? |
|---|---|---|
| `Masker` | detects and masks sensitive values via [`internal/redact`](internal/redact/) → `<V1>` | ✅ |
| `Drain` | clusters near-identical log lines into one template | ❌ lossy |
| `RefDict` | folds repeated long package paths → `#REF1` | ✅ |
| `ASTPrune` | tree-sitter strips values from Go/Python, keeps structure | ❌ lossy |

Reversible substitutions live in a session-bound, in-memory dictionary that is
never written to disk. Lossy stages trade exact reconstruction for token savings,
by design.

### Detection coverage

- **`core`** — emails, IPv4/IPv6, MAC, URLs, UUIDs, timestamps, hashes, paths
- **`secrets`** — PEM private keys, AWS/GCP/Azure keys, GitHub, Slack, Stripe,
  npm, JWTs, Bearer/Basic, DSN passwords, generic `key=value` credentials, plus
  an entropy detector for formats no pattern anticipated
- **`jp`** — 個人番号 (My Number) and 法人番号 with their official check digits,
  credit cards with Luhn, JP phone/postal/address, passport

Check-digit validation is what lets a broad pattern like "twelve digits" be used
for My Number without flooding the dictionary with false positives.

---

## Requirements

- Go **1.26+** and a C compiler (`gcc`/`clang`) — tree-sitter needs
  `CGO_ENABLED=1`. The [Dockerfile](Dockerfile) removes this requirement entirely.
- Optionally a local [Ollama](https://ollama.com) running `phi4-mini`, and/or a
  cloud API key. With neither, the gateway still boots, compresses and audits.

```bash
make build   # bin/phigate and bin/phigate-eval
make test
make docker
```

---

## Project layout

```
cmd/phigate/          server entrypoint, graceful shutdown
cmd/phigate-eval/     bench / cache / eval / leak measurement harness
internal/
  redact/             detection engine, rule packs, leak corpus  ← the privacy guarantee
  compressor/         Masker → Drain → RefDict → ASTPrune + dictionary
  policy/             egress policy: classification decides destination
  router/             local-vs-cloud cost heuristic (advisory)
  cache/              template cache — pre-hydration, keyed on payload shape
  sandbox/            egress guard (shell lexer, severity tiers) + ingress guard
  llm/                OpenAI, Azure, Anthropic and Bedrock clients (SigV4),
                      retry, circuit breaker
  tokens/             token estimator, price book, savings ledger
  session/            TTL'd multi-turn dictionary store
  audit/              structured JSON audit records
  metrics/            Prometheus exposition, dependency-free
  gateway/            HTTP surface, auth, rate limiting, dashboard
  config/             file + env configuration, per-tenant, reload on SIGHUP
deploy/helm/phigate/  production Helm chart
eval/cases.json       golden quality cases
ee/                   Enterprise Edition — separate Go module, separate licence
```

## Editions

PhiGate is open-core. **Everything described in this README is the Community
Edition, and it is free to run in production, forever, under Apache-2.0.** That
includes every privacy control: the redaction packs, the Japanese PII rules, the
egress policy, the sandbox, the audit log.

The `ee/` directory is the Enterprise Edition, under a source-available licence.
It is a **separate Go module**, which is what keeps the Community Edition's
dependency list at one third-party module — the property a security review
checks. Nothing in `ee/` can affect a CE build; `make ce-purity` fails if that
ever changes.

|  | Community Edition | Enterprise Edition |
|---|---|---|
| Licence | Apache-2.0 | [BSL 1.1](ee/LICENSE) → Apache-2.0 after 4 years |
| Production use | free | commercial licence required |
| Non-production use | free | free |
| Dependencies | tree-sitter only | its own, isolated in `ee/go.mod` |

EE is scale and operations, not privacy. Three of its four seams are
implemented: a tamper-evident audit chain (`ee/audit/worm`), a durable
per-tenant token ledger (`ee/tokens/durable`), and Japanese name detection that
composes with — never replaces — CE's regex engine (`ee/redact/slm`). A semantic
cache tier is deliberately not built; the measurement that decided that is in
[ee/README.md](ee/README.md).

The privacy guarantees stay in CE. Every control in the table at the top of this
file is Community Edition, and EE's name detector can only ever find *more* than
CE's engine — CE's own leak corpus is run through it, against an adversarial
recognizer, as a test. See [ee/README.md](ee/README.md), and
[ee/LICENSING-FAQ.md](ee/LICENSING-FAQ.md) for what "production" means, with
worked examples. Evaluating EE against real production data is free on request.

## License

Copyright 2026 Tenkan Inc. (天干株式会社). See [NOTICE](NOTICE).

- Community Edition — everything outside `ee/`: [Apache License 2.0](LICENSE).
- Enterprise Edition — `ee/`: [Business Source License 1.1](ee/LICENSE),
  converting to Apache-2.0 four years after each version's release.
