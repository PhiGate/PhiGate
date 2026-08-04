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
| A value is never *partially* masked | single-pass overlap resolution | same test — partial leaks fail it |
| Data above your sensitivity limit never reaches the cloud, even on failure | [`internal/policy`](internal/policy/) | `go test ./internal/policy/` |
| Catastrophic commands never reach the operator | [`internal/sandbox`](internal/sandbox/) | `go test ./internal/sandbox/` |
| The guard does **not** block ordinary prose | same | `-run TestGuardDoesNotBlockProse` |
| The cache never serves one session's values to another | [`internal/cache`](internal/cache/) | `go test ./internal/gateway/ -run Cache` |
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

Not published yet — and deliberately not estimated. Measuring whether compression
degrades answers requires sending each case to a real model twice, which needs
API credentials and costs money, so it can only be run by someone with both:

```bash
./bin/phigate-eval eval -cases eval/cases.json \
  -gateway http://localhost:8080/v1 -gateway-key <key> \
  -baseline https://api.openai.com/v1 -baseline-key $OPENAI_API_KEY
```

It answers each case twice — once raw to the cloud model, once through PhiGate —
and has a judge model score both against a rubric. A savings figure without a
quality figure beside it is the number every buyer already distrusts, so treat
the table above as incomplete until this one sits next to it.

---

## Request path

```
POST /v1/chat/completions
  → authenticate (API key, per-tenant)
  → screen for prompt injection            internal/sandbox  (ingress)
  → compress + anonymize                   internal/compressor + internal/redact
  → classify what was found                secret / pii / network / identifier / …
  → EGRESS POLICY decides where it may go  internal/policy     ← binding
  → template cache lookup                  internal/cache      ← zero-token hit
  → route local vs cloud                   internal/router     ← advisory
  → dispatch (retry + circuit breaker)     internal/llm        OpenAI | Azure OpenAI
  → hydrate back to real values            + enumeration guard
  → inspect the answer                     internal/sandbox    (egress)
  → account for it                         internal/tokens     tokens + money
  → audit                                  internal/audit      structured JSON
```

**Policy outranks routing.** The router asks which backend is cheapest; the
policy asks which backends this payload is *permitted* to reach. When the two
disagree, the policy wins — including when the local backend fails. A payload
confined to local does not fall back to the cloud. It fails.

---

## The three ideas worth knowing

### 1. The template cache is the real cost lever

AIOps traffic is extraordinarily repetitive: the same disk-full alert thousands
of times a day, differing only in the IP, timestamp and request id. A normal
cache never hits, because those values make every prompt unique.

PhiGate has already replaced exactly those values with placeholders before the
cache is consulted. Ten thousand distinct log lines collapse to one template, so
occurrences 2 through 10,000 cost **zero upstream tokens**. Compression makes the
cache work; the cache is what makes compression pay for itself.

The cache stores answers **before** hydration and keys them on a hash of the
compressed prompt, so it holds no customer data at all and is safe to share
across tenants — each session hydrates the shared answer with its own dictionary.

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

---

## Quick start

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

**Kubernetes:** `helm install phigate deploy/helm/phigate --set secrets.apiKeys="key:team"`

---

## Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/chat/completions` | ✅ | OpenAI-compatible, streaming and blocking |
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

Only `PHIGATE_API_KEYS` and `PHIGATE_CLOUD_API_KEY` are required. PhiGate
**refuses to start** without client credentials unless you set
`PHIGATE_ALLOW_ANONYMOUS=true`, because an unauthenticated gateway in front of a
billed API key is an open relay.

<details>
<summary><b>Backends</b> — OpenAI-compatible or Azure OpenAI</summary>

| Variable | Default | Purpose |
|---|---|---|
| `PHIGATE_LOCAL_PROVIDER` | `openai` | `openai` \| `azure` |
| `PHIGATE_LOCAL_BASE_URL` | `http://localhost:11434/v1` | Ollama / vLLM / llama.cpp |
| `PHIGATE_LOCAL_MODEL` | `phi4-mini` | must match `ollama list` exactly |
| `PHIGATE_CLOUD_PROVIDER` | `openai` | `azure` for Azure OpenAI |
| `PHIGATE_CLOUD_BASE_URL` | `https://api.openai.com/v1` | Azure: the resource root |
| `PHIGATE_CLOUD_MODEL` | `gpt-4o` | |
| `PHIGATE_CLOUD_API_KEY` | (`OPENAI_API_KEY`) | |
| `PHIGATE_CLOUD_API_VERSION` | `2024-10-21` | Azure only |
| `PHIGATE_CLOUD_DEPLOYMENT` | (model name) | Azure deployment name |

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
| `PHIGATE_PRICE_BOOK` | — | your negotiated rates, in your currency |
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
cmd/phigate-eval/     bench / eval / leak measurement harness
internal/
  redact/             detection engine, rule packs, leak corpus  ← the privacy guarantee
  compressor/         Masker → Drain → RefDict → ASTPrune + dictionary
  policy/             egress policy: classification decides destination
  router/             local-vs-cloud cost heuristic (advisory)
  cache/              template cache — pre-hydration, hash-keyed
  sandbox/            egress guard (shell lexer, severity tiers) + ingress guard
  llm/                OpenAI + Azure clients, retry, circuit breaker
  tokens/             token estimator, price book, savings ledger
  session/            TTL'd multi-turn dictionary store
  audit/              structured JSON audit records
  metrics/            Prometheus exposition, dependency-free
  gateway/            HTTP surface, auth, rate limiting, dashboard
  config/             env configuration, fails loudly on bad values
deploy/helm/phigate/  production Helm chart
eval/cases.json       golden quality cases
```

## License

[Apache License 2.0](LICENSE).
