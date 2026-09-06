# PhiGate Enterprise Edition

**This directory is not open source.** It is licensed under the
[Business Source License 1.1](./LICENSE); everything outside `ee/` is the
Community Edition and stays under Apache-2.0.

| | Community Edition | Enterprise Edition |
|---|---|---|
| Location | everything outside `ee/` | this directory |
| Licence | Apache-2.0 | BSL 1.1 → Apache-2.0 after 4 years |
| Production use | **free, always** | requires a commercial licence |
| Non-production use | free | free — read it, build it, evaluate it |
| Source | public | public |

The short version: **you can read all of it, and you can run the Community
Edition in production for free forever.** A licence is needed only to run the
enterprise features in production.

What "production" means is defined with worked examples in
[LICENSING-FAQ.md](./LICENSING-FAQ.md). If you want to evaluate EE against real
production data — the only way to judge it honestly — a free time-boxed
evaluation licence is granted on request: info@tenkan.co.jp.

## Why the split exists at all

The Community Edition's `go.mod` lists one third-party dependency, tree-sitter.
That is not an aesthetic preference — it is the property a customer's security
review actually checks, and PhiGate is sold to organisations whose review is
adversarial by design.

Enterprise features need dependencies that CE cannot afford to carry: an
OpenTelemetry SDK, an embedded key/value store, a Redis client, a vector index.
Putting them behind a build tag would have failed, because one module means one
`go.mod` and those dependencies would appear in the file the reviewer reads.

So `ee/` is a **separate Go module**. `go install
github.com/phigate/phigate/cmd/phigate` does not resolve `ee/go.mod` at all,
whatever this directory grows into. The dependency claim is structural rather
than a matter of discipline, and `make ce-purity` fails the build if it ever
stops being true.

## Architectural rule

EE contains no request-path logic. The pipeline, redaction engine, egress
policy and sandbox all live in CE; EE only substitutes implementations of the
seams CE declares:

| Seam | CE implementation | EE substitutes | Wired through |
|---|---|---|---|
| `cache.Store` | bounded in-memory LRU | embedded HNSW semantic tier, distributed tier | `SetCache`, plus the optional `cache.ProbeStore` |
| `tokens.LedgerStore` | in-memory totals | durable and cross-node quota accounting | `SetLedger`, plus the optional `tokens.TenantLedger` |
| `redact.Detector` | regex rule packs | dictionary/SLM-backed precision detection | `NewWith` — see below |
| `audit.Sink` | JSON lines to a file | append-only storage, retention proofs, SIEM | `SetAudit` |

Two of those seams needed more from CE than an interface, and CE now provides
it. A hash is one-way, so a semantic tier cannot work from a cache key alone:
`cache.Probe` carries the compressed text beside the key, and a store that
implements `ProbeStore` is handed the whole probe. And a quota is per-tenant or
it is not a quota, so `tokens.Record` carries the tenant label and
`tokens.TenantLedger` is the optional half a durable store implements. CE
implements neither optional interface — deliberately, and with a test asserting
it, because CE's exact-match cache holds no prompt text at all and its ledger's
totals are process-wide. Claiming otherwise would make a budget check silently
answer for the whole deployment.

The detector is the seam that cannot be substituted after construction: the
compression pipeline captures it, and swapping a `Masker` while requests are in
flight is a data race. EE therefore builds its gateway through `NewWith` rather
than `New`, and CE exports `BuildRedactEngine` and `BackendConfig` so it can
assemble the same engine and clients `New` would have.

Whatever detector EE installs **wraps** the community engine rather than
replacing it. A detector that could find less than CE's would quietly weaken
the leak guarantee CE's own corpus is written against, so composition is the
rule and the EE detector's tests assert the superset property directly.

Keeping the fork at the seams rather than in the handler is what stops the two
editions drifting. A bug fixed in CE is fixed in EE, and a leak test that passes
in CE means something for EE too.

Any `cache.Store` implementation inherits one non-negotiable obligation from
CE's package documentation: it stores answers **before hydration**. A tier that
persists or shares hydrated text serves one session's real values to another.

## Status

| Seam | Status |
|---|---|
| `audit.Sink` — tamper-evident chain | **implemented**, `ee/audit/worm` |
| `tokens.LedgerStore` — durable per-tenant quota | **implemented**, `ee/tokens/durable` |
| `cache.Store` — semantic tier | not yet |
| `redact.Detector` — dictionary/SLM-backed | not yet |

`phigate-ee` serves once it has at least one enterprise implementation to offer,
and refuses without one: it requires `PHIGATE_EE_AUDIT_DIR`, because a binary
that fell back to CE's file logger would be the community edition under an
enterprise name, which is a lie told to whoever runs it.

### The audit chain

Every record carries the hash of the record before it. Altering a record,
removing one, or inserting one breaks the linkage, and verification reports the
segment, line and sequence number where. This does not *prevent* tampering —
nothing running on the same machine as the file can — it makes tampering
evident, which is the question an ISMS, FISC or APPI audit actually asks and the
one a plain log file cannot answer.

```sh
PHIGATE_EE_AUDIT_DIR=/var/lib/phigate/audit \
PHIGATE_EE_AUDIT_RETENTION=2160h \
  phigate-ee

phigate-ee audit verify -dir /var/lib/phigate/audit
```

Verification is a subcommand rather than an endpoint, because an auditor
checking a log should not have to trust, or even reach, the process that wrote
it. It exits non-zero on a break.

Three properties worth knowing before it is put in front of a customer:

- **It never blocks the request path.** `audit.Sink`'s contract says a
  destination that stalls must drop or buffer, never wait, so writes go through
  a bounded queue. When that queue fills, records are dropped — and a *gap
  record* goes into the chain saying how many. A silent jump in sequence numbers
  is indistinguishable from a deletion, which would defeat the point.
- **A restart continues the chain**, rather than starting a second one that
  would look exactly like the log having been replaced.
- **Retention refuses as well as deletes.** `Prune` removes only expired
  segments and declines anything younger, because "records are kept for N years
  and cannot be removed sooner" is what a retention requirement actually says. A
  zero retention — the default — deletes nothing at all.

### The durable ledger

`internal/tokens` says of the community ledger that it is "honest for a PoC and
wrong for a production quota: a rolling update or a crash resets every tenant's
consumption to zero, so a monthly hard limit stops being a limit." That is this
package's entire reason to exist. A customer deploying weekly has twelve times
the monthly allowance they were sold.

```sh
PHIGATE_EE_LEDGER_PATH=/var/lib/phigate/ledger.db phigate-ee
```

The budget itself is configured in CE, per tenant, and enforced by CE — the
enterprise edition contains no request-path logic, so what it substitutes is the
store the decision is made against:

```json
{ "budget_period": "monthly", "budget_timezone": "Asia/Tokyo",
  "tenants": { "team-finance": { "token_budget": 5000000 } } }
```

Two properties to know before quoting it to a customer:

- **A budget always overshoots by one request.** A request's token cost is not
  known until it has finished, so the check is against what a tenant has already
  spent. A streaming answer can overshoot by more. The bound is that the first
  request after the allowance runs out is refused, not that the allowance is
  never exceeded.
- **A crash loses at most one flush interval of accounting.** bbolt fsyncs on
  commit and a transaction per request would put a disk flush in the request
  path, so spend is batched. Under-counting slightly after a crash is the right
  direction to be wrong in; the alternative on offer is not "exact", it is
  "zero".

Periods reset in `budget_timezone`, which defaults to `Asia/Tokyo` rather than
UTC because a budget period is a billing period and a Japanese customer's month
ends at midnight JST — a boundary computed in UTC puts nine hours of every
month-end in the wrong month.

Run the Community Edition instead if you do not need these: `cmd/phigate`. CE
enforces the same budgets against its in-memory ledger, which is honest for as
long as the process lives and resets on a rolling update.

## Building

```sh
make ee          # builds to ../bin/
make ce-purity   # proves CE stayed clean and imports nothing from here
```
