# Contributing to PhiGate

Thanks for helping. 日本語での issue / PR も歓迎します。

## The one rule

**Every claim gets a test that fails when the claim stops being true.**

PhiGate sells two properties — that sensitive data does not leave the network,
and that it cuts token spend. Both are empirical, and both were once asserted in
a README without anything checking them. If your change touches either, it needs
a test that would catch the regression:

| If you change… | Add a case to… |
|---|---|
| Detection rules or priorities | `internal/redact/testdata/leak_corpus.json` |
| The egress guard | `internal/sandbox/sandbox_test.go` — **both** a blocked case and a prose case that must not block |
| The egress policy | `internal/policy/policy_test.go` |
| Caching or hydration | `internal/gateway/handler_test.go` — prove no cross-session leakage |
| Token accounting | `internal/tokens/tokens_test.go` |

## Setup

```bash
git clone https://github.com/phigate/phigate && cd phigate
make build     # needs Go 1.26+ and a C compiler (tree-sitter uses cgo)
make test
```

`CGO_ENABLED=1` is mandatory. If the build fails on missing headers, install
`build-essential` (Debian/Ubuntu) or Xcode command line tools (macOS).

## Before opening a PR

```bash
make fmt vet test
```

Keep the dependency list short. PhiGate has exactly one non-stdlib dependency
family (tree-sitter) on purpose: it is a security gateway, and a JP enterprise
security review has to be able to read the whole supply chain. Prometheus
exposition, the token estimator, the shell lexer and the LRU caches are all
hand-written for this reason. A PR adding a dependency should say why the
stdlib will not do.

## Adding a detection rule

Rules are data, in [`internal/redact/packs/`](internal/redact/packs/):

```json
{
  "name": "acme_employee_id",
  "category": "pii",
  "priority": 84,
  "validator": "luhn",
  "pattern": "\\bACME-\\d{6}-[A-Z]{2}\\b",
  "description": "Acme Corp internal employee identifier"
}
```

- **`category`** drives the egress policy. Getting it wrong is a security bug:
  a My Number classified `identifier` instead of `pii` would be allowed to
  egress. Pick from `secret`, `pii`, `network`, `identifier`, `temporal`, `path`.
- **`priority`** resolves overlaps; higher wins. Credentials sit at 90-100,
  personal data at 78-88, topology at 60-70, generic identifiers below 50.
- **Patterns are RE2.** No lookahead, no backreferences.
- **Prefer a broad pattern plus a validator** over a narrow pattern. That is how
  `jp_mynumber` can match any twelve digits without flooding the dictionary.
- **Ship risky rules `"disabled": true`** with a note on when to enable them.

Then add a leak-corpus case with the value that must not survive, and — just as
important — a `must_survive` string proving the rule does not eat ordinary text.

## Adding an egress guard rule

Guard rules live in [`internal/sandbox/rules.go`](internal/sandbox/rules.go) and
match on lexed argv, not on raw text.

Assign severity by one question: **is this ever a correct answer?**

- `SeverityBlock` — never correct. `rm -rf /`, `mkfs` on a device, a fork bomb.
- `SeverityWarn` — destructive but routinely right. Restarting a service,
  rebooting a node, deleting a scoped directory.

Over-blocking is not the safe default. The original rule set blocked the
sentence "if that fails, reboot the node", and a guard that blocks correct advice
gets switched off — at which point it protects nothing. Every guard PR must
include a prose case that must **not** block.

## Style

Follow the surrounding code. Comments should explain *why*, especially where a
decision looks odd — several choices here (storing pre-hydration text in the
cache, failing rather than falling back, scoping the guard to code) look like
extra work until you know what goes wrong without them.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
