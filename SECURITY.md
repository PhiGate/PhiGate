# Security Policy

PhiGate sits in the path of every LLM request an enterprise makes and holds
credentials for upstream providers. A vulnerability here is a vulnerability in
the customer's data-protection boundary, so we treat reports accordingly.

## Reporting a vulnerability

**Do not open a public issue.**

Email **security@tenkan.co.jp** with:

- what you found and where (file, endpoint, or rule),
- a minimal reproduction — a payload that leaks, a command that bypasses the
  guard, or a request that escapes the egress policy,
- the impact you believe it has.

Japanese and English are both fine. 日本語でのご報告も歓迎します。

We aim to acknowledge within **3 business days** and to ship a fix or a
mitigation within **30 days** for anything rated high or critical. We will credit
you in the release notes unless you prefer otherwise.

## What we consider a vulnerability

These are the guarantees PhiGate makes. A reproducible break of any of them is a
security bug, not a feature request:

| Guarantee | Break looks like |
|---|---|
| No credential or personal datum reaches an upstream provider unmasked | A payload whose secret survives `internal/redact` |
| A value masked in part is never sent | A partially-masked secret in the upstream request |
| Data above the configured sensitivity never reaches a cloud backend | Any path that egresses a `local_only` payload, including retries, fallbacks and error handlers |
| A `block`-severity command never reaches the client | A destructive command that passes the egress guard |
| Hydration cannot be turned into an exfiltration channel | An answer that makes PhiGate paste back the dictionary |
| The audit log contains no raw sensitive values | Any customer value appearing in an audit record |
| The gateway is not an open relay | Reaching an authenticated endpoint without a valid key |

The regression suites for these live in
[`internal/redact/leak_test.go`](internal/redact/leak_test.go),
[`internal/sandbox/sandbox_test.go`](internal/sandbox/sandbox_test.go), and
[`internal/gateway/handler_test.go`](internal/gateway/handler_test.go). A good
report is often a new failing case for one of them.

## What we do not consider a vulnerability

- **A rule that fails to match some secret format.** Pattern coverage is
  open-ended and the entropy detector is a backstop, not a proof. New patterns
  are very welcome as ordinary pull requests — see
  [`internal/redact/packs/`](internal/redact/packs/).
- **A guard rule that misses an exotic obfuscation** (base64-encoded commands,
  variable indirection). The egress guard is defence in depth for a model that
  gives bad advice, not a sandbox against a hostile model. See
  [THREAT-MODEL.md](THREAT-MODEL.md).
- **Anything requiring `PHIGATE_DEBUG=true`.** That flag is documented as
  disclosing plaintext and is off by default.
- Findings against a deployment that set `PHIGATE_ALLOW_ANONYMOUS=true` and
  exposed the port publicly.

## Deployment guidance

PhiGate is a data-protection boundary, so how it is run is part of its security:

- **Set `PHIGATE_API_KEYS`.** Startup fails without it unless you explicitly opt
  into anonymous access, because an unauthenticated gateway in front of a billed
  API key is an open relay.
- **Leave `PHIGATE_DEBUG` unset.** `/debug/compress` returns the plaintext of
  every masked value.
- **Keep the audit log.** Write it somewhere append-only; it is your evidence
  that the controls were in force.
- **Terminate TLS in front of PhiGate** and set `PHIGATE_TRUSTED_PROXY_HEADER`
  only if a proxy you control sets it. Reading `X-Forwarded-For` unconditionally
  lets any client forge the address in your audit trail.
- **Set `PHIGATE_INTERNAL_DOMAINS`** to your real internal suffixes. Hostname
  masking is opt-in because the suffixes are site-specific.
- **Review `--rules` output** before going live, so you know what is detected.

## Supported versions

Until 1.0, security fixes land on `main` and in the latest tagged release.
