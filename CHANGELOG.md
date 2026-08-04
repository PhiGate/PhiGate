# Changelog

All notable changes to PhiGate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because PhiGate is a data-protection boundary, entries that change **what may
leave the network**, **what is detected**, or **what is blocked** are called out
explicitly — those are the changes an operator has to re-approve, not merely
read.

## [Unreleased]

## [0.1.0] — 2026-08-04

First public release. The three-stage pipeline (compression, routing, egress
sandbox) was already in place; this release makes the two claims PhiGate is sold
on — no data egress, real cost reduction — defensible in code and testable by
anyone who clones the repository.

### Added

#### Security controls

- **Redaction engine** (`internal/redact`) — single-pass detection with
  priority-based overlap resolution, replacing sequential regex substitution.
  Rules are data, loaded from JSON packs, so an enterprise can add its own
  identifier formats without rebuilding.
  - `core` pack: emails, IPv4/IPv6, MAC, URLs, UUIDs, timestamps, hashes, paths.
  - `secrets` pack: PEM private keys, AWS/GCP/Azure keys, GitHub, Slack, Stripe,
    npm, JWTs, Bearer/Basic, DSN passwords, generic `key=value` credentials.
  - `jp` pack: 個人番号 (My Number) and 法人番号 validated by their official
    check digits, credit cards by Luhn, JP phone/postal/address, passport.
  - Shannon-entropy detector as a backstop for credential formats no pattern
    anticipates.
- **Egress policy** (`internal/policy`) — classification decides destination.
  Data above `PHIGATE_CLOUD_MAX_SENSITIVITY` is confined to the local model and
  **fails rather than falling back** when that model is unavailable.
- **Ingress guard** — screens inbound payloads for prompt-injection patterns,
  including attempts to make the model enumerate placeholders.
- **Dictionary-enumeration guard** — withholds an answer that resolves most of a
  session's dictionary, closing hydration as an exfiltration channel.
- **API-key authentication** with constant-time comparison and per-tenant
  labelling. The gateway refuses to start without credentials unless anonymous
  access is chosen explicitly.
- **Per-tenant rate limiting**, request IDs, panic recovery, and server timeouts.

#### Cost

- **Template cache** (`internal/cache`) — keyed on a hash of the *compressed*
  prompt, so repeated alerts differing only in masked values cost zero upstream
  tokens. Stores pre-hydration text only, which is what makes it safe to share
  across sessions and tenants.
- **Token and cost ledger** (`internal/tokens`) — real token accounting with a
  CJK-aware estimator, an overridable price book (your rates, your currency), and
  separate reporting of provider-measured versus estimated figures.

#### Operations

- **Structured JSON audit log** (`internal/audit`) whose event type has no field
  capable of holding a raw value — only rule names, category counts and hashes.
- **Prometheus metrics** and a `/v1/phigate/stats` endpoint.
- **Embedded single-binary dashboard** at `/dashboard`, with no external assets,
  so it renders on air-gapped networks.
- **`/readyz`** probing both backends, distinct from liveness.
- **Graceful shutdown** that drains in-flight streaming completions.
- **Session store** (`internal/session`) giving a conversation one dictionary, so
  a value maps to the same placeholder across turns.
- **Azure OpenAI support**, plus upstream retry with backoff and a circuit
  breaker per backend.
- **`phigate-eval`** — `leak`, `bench` and `eval` subcommands for measuring
  detection coverage, token reduction, and answer quality on your own data.
- **`phigate -rules`** prints every active detection rule and its classification.

#### Project

- Apache-2.0 licence, `SECURITY.md`, `CONTRIBUTING.md`, `THREAT-MODEL.md`,
  Japanese README, CI across Linux/macOS/Windows, a distroless container image,
  and a production Helm chart.

### Fixed

- **Partial masking corrupted credentials.** Sequential regex application let a
  low-priority path rule consume the middle of an AWS secret key, emitting a
  half-masked value that looked safe. Single-pass overlap resolution means a
  value is always claimed by its most specific rule and masked in full.
- **The Drain stage never clustered real logs.** Its bucket key used the first
  token, which the masker had just replaced with a *unique* placeholder per
  timestamp — so on any log whose lines begin with a timestamp, the stage was a
  no-op. On repetitive traffic its contribution went from 0% to ~92%.
- **`/debug/compress` returned plaintext, unauthenticated, by default.** It now
  requires both authentication and an explicit `PHIGATE_DEBUG=true`.
- **The egress guard blocked ordinary prose.** "If that fails, reboot the node"
  and "graceful shutdown is configured via SIGTERM" were treated as destructive
  commands. The guard now extracts only executable text and matches on lexed
  argv, with severity tiers so destructive-but-legitimate operations warn rather
  than block.
- **The egress guard missed obvious bypasses.** `rm -f -r /`,
  `rm --force --recursive /` and `find / -delete` all passed the regex deny list.
- **Requests were silently degraded.** Unmodelled fields — `tools`,
  `response_format`, `top_p`, `stop`, `seed`, `n` — were dropped while the call
  still succeeded. They are now preserved verbatim.
- **Savings were reported in runes, not tokens**, and ignored the larger saving
  from avoiding a cloud call entirely.
- **Upstream errors were returned to callers**, disclosing backend URLs and
  provider messages to anyone able to trigger a failure.
- **The container health check could not detect a wedged server.** It now issues
  a real request to `/healthz` via `phigate -healthcheck`.
- **`observability.auditLog` produced an unstartable pod** in the Helm chart —
  a read-only root filesystem with no volume at the log path.

### Security

- **Go 1.26 is required.** Older toolchains ship a standard library with 25
  vulnerabilities that `govulncheck` flags against this code, several reachable
  in normal operation: an unauthenticated TLS 1.3 KeyUpdate denial of service on
  the listener, `net/http` cookie-parsing memory exhaustion, an HTTP/2 transport
  infinite loop on upstream calls, and `html/template` XSS reachable from the
  dashboard. This is a floor rather than a minimum language version precisely so
  a released binary cannot be built against a vulnerable stdlib.
- Test fixtures store synthetic credentials as fragments joined at load time, so
  no credential-shaped literal exists in the repository. `TestNoLiteralCredentialsInCorpus`
  enforces this for future contributors.

[Unreleased]: https://github.com/phigate/phigate/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/phigate/phigate/releases/tag/v0.1.0
