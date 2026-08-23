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

| Seam | CE implementation | EE substitutes |
|---|---|---|
| `cache.Store` | bounded in-memory LRU | embedded HNSW semantic tier, distributed tier |
| `tokens.LedgerStore` | in-memory totals | durable and cross-node quota accounting |
| `redact.Detector` | regex rule packs | dictionary/SLM-backed precision detection |
| `audit.Sink` | JSON lines to a file | append-only storage, retention proofs, SIEM |

Keeping the fork at the seams rather than in the handler is what stops the two
editions drifting. A bug fixed in CE is fixed in EE, and a leak test that passes
in CE means something for EE too.

Any `cache.Store` implementation inherits one non-negotiable obligation from
CE's package documentation: it stores answers **before hydration**. A tier that
persists or shares hydrated text serves one session's real values to another.

## Status

Nothing is implemented yet. `phigate-ee` builds, resolves the seams, and then
**refuses to serve** — shipping CE under an EE name would be a lie told to
whoever runs it. The binary exists now because it is the compile-time proof that
a nested module can import the parent module's `internal/` packages, which is
the assumption the entire layout rests on.

Run the Community Edition: `cmd/phigate`.

## Building

```sh
make ee          # builds to ../bin/
make ce-purity   # proves CE stayed clean and imports nothing from here
```
