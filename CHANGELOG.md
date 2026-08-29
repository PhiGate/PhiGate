# Changelog

All notable changes to PhiGate are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because PhiGate is a data-protection boundary, entries that change **what may
leave the network**, **what is detected**, or **what is blocked** are called out
explicitly — those are the changes an operator has to re-approve, not merely
read.

## [Unreleased]

## [0.3.0] — 2026-08-30

Two defects in the streaming egress path, and the evaluation on-ramp that was
missing. **This release changes what the gateway blocks on streamed responses**
— see the first entry below, which is the one to re-approve rather than merely
read.

### Security

- **A streamed answer is now guarded exactly as a non-streamed one.** This
  changes **what is blocked**, and is the entry on this page an operator has to
  re-approve rather than merely read.

  The streaming scanner inspected model output one line at a time, and
  `extractExecutable` rebuilds its code-fence state on every call. A line handed
  to it individually was therefore inspected with no knowledge that it sat
  inside a fence, and fell through to the outside-a-fence path. The blocking
  path inspects the whole hydrated answer, where a fence body arrives as one
  code segment.

  The two paths could consequently reach different verdicts on the same answer,
  and which one applied depended on whether the client sent `"stream": true` — a
  performance preference, not a security decision, and not visible in an audit
  log afterwards. Confirmed reachable for any rule matching across lines within
  a fence, including `fork_bomb` and `dd_to_device`.

  The scanner now carries fence state across writes and inspects a fenced block
  as one segment. That the two paths agree is asserted in
  `internal/sandbox/parity_test.go` and is part of `make guarantees`; the
  agreement is checked byte-by-byte, at every split boundary, and under fuzzing.

- **A response can no longer hold the scanner's buffer open without bound.** A
  code fence the model never closes — truncated, or injected into emitting an
  endless block — previously grew the held text indefinitely, as did a line with
  no newline in it. `PHIGATE_STREAM_MAX_BUFFER` (1 MiB) now bounds it. Reaching
  the bound releases nothing unvetted: the held text is inspected as a code
  segment and released early rather than dumped, and a stream still growing after
  that is sealed.

### Changed

- **Prose streams as it arrives.** The scanner released nothing until it saw a
  newline, so an answer written as a single paragraph — the ordinary shape of a
  short AIOps answer — was buffered end to end, and an endpoint that is
  nominally streaming behaved like a blocking one.

  Text is now released as soon as no continuation of the stream could change the
  guard's verdict on it: prose immediately, a line that could be read as a
  command at its newline, a fenced block when the fence closes. Ambiguity holds
  — an unbalanced quote, an open `$(`, a line continuation or a token that could
  still grow into a command name all keep the text held, so obfuscation costs an
  attacker latency and buys them nothing.

  `PHIGATE_STREAM_MODE=strict` restores whole-answer buffering for deployments
  that prefer it. Both modes give the same verdict; they differ only in latency.

### Added

- **`docker-compose.yml` — a one-command evaluation stack.** PhiGate, a local
  Phi-4-mini on Ollama (pulled by an init service, so the first request cannot
  fail with a model-not-found), and Prometheus. **No cloud API key is required
  and no cloud LLM is contacted**: the stack sets
  `PHIGATE_CLOUD_MAX_SENSITIVITY=low` and disables cloud fallback, so anything
  carrying a hostname, an IP or a path is confined to the local model by
  `internal/policy` rather than by configuration convention.

  This closes the gap between what the README asks a reader to do — run it on
  your own logs and check the numbers — and what that actually cost them: a Go
  toolchain, a C compiler for tree-sitter, an Ollama install, a model pull and a
  Prometheus wiring, none of which say anything about whether the product works.
  The compose file uses the published `ghcr.io` image, so neither the toolchain
  nor the compiler is in the path of a first evaluation.

  An opt-in `bench` profile runs `phigate-eval bench` against the public LogHub
  corpus or a bind-mounted directory of your own logs.

- **`deploy/prometheus.yml`** for that stack. It carries the demo bearer
  credential because `/metrics` sits behind the same authentication as the rest
  of the API — per-rule block counts and token totals describe traffic through a
  data-protection boundary, and are not something to serve unauthenticated.

### Fixed

- **The Helm chart deployed the wrong version of PhiGate.** `Chart.yaml` was
  still at `0.1.0` and `values.yaml` defaults `image.tag` to `.Chart.AppVersion`,
  so `helm install` from the 0.2.0 tag installed the **0.1.0** image — without
  the open-core split's fixes, and without anything in this release. The chart
  version and `appVersion` now track the release, and both are part of the
  release checklist rather than a step to remember.

  Anyone running the chart from 0.1.0 or 0.2.0 should check what is actually
  deployed: `kubectl get deploy -o jsonpath='{..image}'`. Pinning
  `image.tag` explicitly in your values file also avoids this class of mistake.

## [0.2.0] — 2026-08-23

Structural only. **No change to what the gateway detects, blocks, or lets leave
the network.** The request path, the rule packs, the egress policy and the
sandbox are untouched; the full guarantee suite passes with the `ee/` directory
physically removed from the tree.

### Added

- **Open-core structure.** PhiGate is now split into a Community Edition
  (everything outside `ee/`, Apache-2.0, free in production forever — including
  every privacy control) and an Enterprise Edition (`ee/`, BSL 1.1, free for
  non-production use, commercial licence for production).

  EE is a **separate Go module**, not a build tag. One module would mean one
  `go.mod`, and enterprise dependencies — an OpenTelemetry SDK, an embedded
  key/value store, a Redis client — would appear in the file a customer's
  security review reads. A nested module means `go install
  github.com/phigate/phigate/cmd/phigate` never resolves `ee/go.mod` at all.

  Nothing is implemented in EE yet. `phigate-ee` builds, resolves the seams and
  then refuses to serve, because shipping CE under an EE name would misrepresent
  what is running.

- **Four substitution seams**, each with a compile-time assertion that the
  community implementation satisfies it: `cache.Store`, `tokens.LedgerStore`,
  `redact.Detector`, and `audit.Sink`. EE substitutes implementations through
  `Gateway.SetCache`, `SetLedger` and `SetAudit` rather than forking the request
  path, so a bug fixed in CE is fixed in EE and CE's leak corpus still means
  something for both.

  Any `cache.Store` implementation inherits the obligation documented on the
  interface: it holds **pre-hydration** text only. A tier that stores hydrated
  answers would serve one session's real values to another.

- **`make ce-purity`**, run in CI and as a release gate. It asserts that no
  community package imports `ee/`, and that the shipped binaries link
  tree-sitter, its grammars and `go-pointer` and nothing else. The check reads
  `go list -deps` over `./cmd/...` rather than `go list -m all`: the module
  graph includes the test-only dependencies *of* dependencies — tree-sitter
  pulls testify — which are never compiled in, so the graph overstates what
  ships.

- **`make ee`**, building the enterprise module. It also settles the assumption
  the layout rests on, that a nested module may import the parent module's
  `internal/` packages.

- **DCO sign-off** required on contributions (`git commit -s`). A CLA would only
  be necessary to relicense the Community Edition away from Apache-2.0, which is
  not intended; Apache-2.0 already permits CE contributions to be used in EE
  with attribution preserved.

- **Copyright declared.** `NOTICE` names Tenkan Inc. (天干株式会社) as copyright
  holder, states which licence governs which directory, and lists the four
  third-party modules actually linked into the shipped binaries. The repository
  previously declared no owner at all — the Apache appendix was an unfilled
  template and there was no `NOTICE`.

- **`ee/LICENSING-FAQ.md`** defines "production", the word on which the entire
  free/paid boundary turns and which BSL itself leaves undefined. It covers the
  two cases that mislead people — internal-only use is still production, and
  "staging" is decided by data and dependency rather than by the environment's
  name — and commits to issuing free time-boxed evaluation licences for
  real-data trials, extended when a security review runs long.

### Fixed

- **The audit sink no longer relies on nil-receiver methods.** `Gateway.audit`
  was left nil until `SetAudit` ran and worked only because `*audit.Logger`'s
  methods guard against a nil receiver — a path every test exercised, since no
  test calls `SetAudit`. It now defaults to `audit.Nop{}`. Same observable
  behaviour, no longer resting on the guard.

### Supply-chain tooling, previously drafted as 0.1.1

An earlier draft of this file documented the two entries below as `[0.1.1] —
2026-08-04` and stated they had been "released as a tag". **That tag was never
created.** No `v0.1.1` tag, GitHub release, or container image exists, and
nothing was shipped between 0.1.0 and this release.

They are folded in here rather than tagged retroactively. The 0.1.1 entry itself
recorded that the binary and image were byte-for-byte equivalent to 0.1.0, so a
retroactive release would have added a version to every user's upgrade decision
without changing anything they run.

- **Dependabot configuration** for Go modules, the `golang` build image, and
  workflow actions. Watching the build image matters more than it looks: the
  released artifact is the container, so a standard-library security release
  reaches users through the base image rather than through `go.mod`. Dependabot
  does not bump Go toolchains, so that entry plus the `govulncheck` CI job are
  what cover the gap that produced the 25 stdlib advisories fixed in 0.1.0.
- **Push-protection guidance** (`.github/SECRET_SCANNING.md`), linked from
  GitHub's secret-scanning block message. It puts rotation before history
  rewriting — removing a secret from git does not un-leak it — and documents the
  fragment technique for test fixtures, which this repository needs more than
  most: a corpus that proves credentials are detected is necessarily full of
  things that look like credentials, and a scanner cannot tell the difference.

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

[Unreleased]: https://github.com/phigate/phigate/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/phigate/phigate/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/phigate/phigate/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/phigate/phigate/releases/tag/v0.1.0
