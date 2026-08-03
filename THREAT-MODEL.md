# PhiGate Threat Model

This document states what PhiGate protects against, what it does not, and why.

It exists because "100% data privacy" is not a claim any software can honestly
make, and a vendor who makes it anyway is telling you they have not thought
about it. Conservative buyers — the enterprises PhiGate is built for — trust a
precise boundary far more than a confident slogan. Everything below is meant to
be read by someone deciding whether to put this in front of their production
data.

## What PhiGate is

An OpenAI-compatible reverse proxy between internal AIOps tooling and LLM
providers. It compresses and anonymises payloads, classifies what it found,
enforces an egress policy over that classification, routes between a local SLM
and a cloud model, and inspects the answer before it reaches an operator.

## Assets

| Asset | Why it matters |
|---|---|
| Credentials in logs and configs | Leaking one is an incident |
| Personal data (My Number, cards, contacts) | Regulated under APPI / the My Number Act |
| Internal topology (hostnames, IPs, paths) | Reconnaissance value to an attacker |
| Source code and business logic | Trade secret |
| The gateway's own upstream API keys | Direct financial loss |
| The audit trail | The evidence that controls were enforced |

## Trust boundaries

```
  operator / AIOps tooling
        │  (trusted network, authenticated by API key)
        ▼
  ┌───────────── PhiGate ─────────────┐
  │  redact → classify → policy →     │   ← the boundary this document is about
  │  cache → route → guard → hydrate  │
  └───────────────────────────────────┘
        │                     │
        ▼                     ▼
  local SLM              cloud provider
  (trusted,              (UNTRUSTED —
   in-network)            third party, off-network)
```

Log *content* is **not** trusted, even though it arrives from inside the
network. Logs contain user agents, URLs, form fields and error strings chosen by
outsiders. Anyone who can write to a log line can write instructions into it.

## Threats addressed

### T1 — Sensitive data reaching a third-party provider

**Control.** `internal/redact` detects credentials, personal data and topology
before anything is dispatched, in a single pass with priority-based overlap
resolution so a value is always claimed by its most specific rule and masked in
full. A partial mask is treated as a failure, because it looks safe.

**Residual risk.** Pattern coverage is open-ended. The entropy detector catches
unknown key-like tokens, but a low-entropy bespoke secret (`ACCT-000123-AB`) in
an unrecognised format will pass. **Mitigate** by adding a rule pack for your own
identifier formats.

### T2 — A cost heuristic overriding a compliance requirement

**Control.** The router proposes; `internal/policy` disposes. Classification runs
before routing, and a payload above `PHIGATE_CLOUD_MAX_SENSITIVITY` is confined
to the local model. Crucially, that confinement survives failure: a local-only
payload does **not** fall back to the cloud when the local backend is down. It
fails.

**Residual risk.** If the local model is unavailable, those requests fail
outright. That is the intended trade — availability yields to confidentiality —
but capacity-plan the local backend accordingly.

### T3 — Destructive commands reaching an operator or an automation runner

**Control.** `internal/sandbox` extracts executable text (code fences, inline
code, unambiguous command lines), lexes it into argv, and matches on program and
flags. Severity tiers separate the catastrophic from the merely destructive.

**Residual risk — significant, and stated plainly.** This is *defence in depth
against a model giving bad advice*, not a sandbox against a hostile one. It can
be evaded by obfuscation: base64-encoded commands, variable indirection
(`X=rm; $X -rf /`), scripts fetched at runtime, or destructive operations
expressed inside Python or Go rather than shell. **Do not** rely on it as the
only control before automated execution. Put a human or a signed-runbook
allowlist between PhiGate and anything that runs commands.

### T4 — Prompt injection through log content

**Control.** `internal/sandbox.IngressGuard` screens inbound payloads for
instruction-override, role-reassignment and placeholder-enumeration patterns,
and annotates the answer. The egress guard is the backstop for what the model
does as a result.

**Residual risk.** Detection is pattern-based and advisory. Novel phrasings pass.
This is an unsolved problem industry-wide; PhiGate reduces exposure rather than
eliminating it.

### T5 — Hydration as an exfiltration channel

This one is specific to PhiGate's design and worth spelling out. Hydration
deliberately re-inserts real values into text the gateway did not author. A model
induced to emit `<V1> <V2> <V3> …` would make PhiGate paste back every secret it
was never shown.

**Control.** `HydrateReport` counts distinct substitutions. An answer resolving
more than `MaxFraction` of a dictionary of at least `MinDictionary` entries is
withheld. The system preamble also instructs the model not to enumerate
placeholders.

**Residual risk.** An attacker who extracts a *small* number of values stays
under the threshold. The threshold catches recitation, not targeted extraction.

### T6 — Cross-session leakage through the cache

**Control.** The cache stores answers **before** hydration and keys them on a
hash of the compressed prompt. Session A's `<V1>` and session B's `<V1>` are
different values; each hydrates the shared masked answer with its own dictionary.
No customer value is ever stored in the cache — not even masked text, since the
key is a hash.

**Residual risk.** A cached answer is shared across tenants by design. If your
compressed templates themselves encode something tenant-specific, set
`PHIGATE_CACHE_ENABLED=false`.

### T7 — The gateway as an open relay

**Control.** API-key authentication with constant-time comparison, optional
per-tenant rate limiting, and a startup failure when no keys are configured
unless anonymous access is explicitly chosen.

### T8 — Disclosure through operational surfaces

**Control.** `/debug/compress` returns plaintext and is off by default. Upstream
errors are logged for audit but never returned to callers. Audit records carry
rule names, category counts and content hashes — the `Event` type has no field
capable of holding a raw value.

## Threats explicitly NOT addressed

| Not addressed | Why |
|---|---|
| **A malicious cloud provider** | PhiGate reduces what a provider sees; it does not make the provider trustworthy. Use the local-only policy for data you would not send at all. |
| **A compromised PhiGate host** | The process holds plaintext in memory by necessity. Host compromise is total compromise. |
| **A hostile local model** | The local SLM is inside the trust boundary. |
| **Inference from masked structure** | `<V1> connection refused <V2>` still discloses that a connection failed between two hosts. Masking removes values, not the fact of the event. |
| **Traffic analysis** | Request timing and volume are not concealed. |
| **A model memorising placeholders** | Providers may retain prompts per their own terms. PhiGate ensures those prompts contain no raw values; it cannot control retention. |
| **Denial of service** | Rate limiting is per-tenant and in-process. Put a real WAF or gateway in front for internet exposure. |
| **Lossy-stage reconstruction** | Drain and AST pruning discard information by design. Hydration restores masked values, not pruned ones. |

## Assumptions

1. PhiGate runs inside the enterprise network and is reached over TLS terminated
   by infrastructure the enterprise controls.
2. Clients holding API keys are trusted operators or trusted tooling.
3. The local SLM runs on infrastructure the enterprise controls.
4. The audit log is shipped somewhere append-only that PhiGate cannot rewrite.
5. Operators review `--rules` output and tune rule packs for their own data.

## Verifying the claims

Every guarantee above has a test that fails when it stops being true:

```bash
make test                                   # everything
go test ./internal/redact/   -run Leak      # T1: no secret survives redaction
go test ./internal/policy/                  # T2: local-only never falls back
go test ./internal/sandbox/                 # T3: bypasses closed, prose not blocked
go test ./internal/gateway/  -run Cache     # T6: no cross-session leakage
./bin/phigate-eval leak -dir /path/to/logs  # coverage on your own data
```

Run the last one against your own corpus before you trust the first six.
