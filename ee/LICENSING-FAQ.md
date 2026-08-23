# PhiGate Enterprise Edition — Licensing FAQ

This document is the Licensor's published interpretation of the
[Business Source License 1.1](./LICENSE) as it applies to the PhiGate
Enterprise Edition. **It does not modify the licence** — BSL forbids that, and
the Terms in `ee/LICENSE` govern if anything here conflicts with them. Its
purpose is to answer, in advance and in public, the question the licence leaves
open: what counts as production.

Licensor: Tenkan Inc. (天干株式会社) · info@tenkan.co.jp

---

## The short version

**The Community Edition is free in production, forever, with no licence from
us.** That includes every privacy control PhiGate is sold on: the redaction
engine, the Japanese PII rules, the egress policy, the sandbox, the audit log.
If you never touch `ee/`, nothing on this page applies to you.

The Enterprise Edition (`ee/`) is free to read, build, test and evaluate. A
commercial licence is needed only to run it **in production**.

If you want to evaluate EE against real production data — which is the only way
to judge it honestly — **ask us for a free time-boxed evaluation licence.** See
[Evaluating with real data](#evaluating-with-real-data).

---

## What "production" means

Use of the Enterprise Edition is **production use** if it meets **any** of the
following:

1. **Real data.** It processes, transmits, caches or stores data originating
   from your real users, employees, customers, systems or infrastructure — as
   opposed to synthetic, sample, or irreversibly anonymised data.
2. **Real work.** It serves or supports a workload that people rely on to do
   their jobs, whether they are inside or outside your organisation.
3. **A commitment depends on it.** Any service level, availability target,
   regulatory obligation or contractual promise is met, in whole or in part, by
   its operation.
4. **Ongoing operation.** It runs continuously, or on a schedule, as a standing
   part of how your organisation operates — rather than for the bounded duration
   of a specific test or evaluation.

Use is **non-production**, and free under the licence, when none of those apply.
Non-production use expressly includes:

- Evaluating whether to buy a commercial licence.
- Development and testing against synthetic, sample or scrubbed data.
- Automated test suites and CI.
- Benchmarking, load testing, performance and security testing.
- Security review, source auditing, and compliance assessment of PhiGate itself.
- Demonstrations, training, teaching and conference talks.
- Academic research.
- Personal and hobby use.

### Two clarifications that catch people out

**Internal-only use is still production.** Whether a system is public-facing has
no bearing on this. A gateway used only by your own SRE team, on your own
internal network, processing your own logs, is production use. It meets criteria
1, 2 and 4.

**"Staging" is not automatically non-production.** What matters is the data and
the dependency, not the environment's name. A staging deployment fed synthetic
data, used to validate a release, is non-production. A staging deployment
mirroring live traffic with real logs is production use.

---

## Worked examples

| Scenario | Verdict |
|---|---|
| Running the **Community Edition** in production, at any scale, forever | **Free.** Apache-2.0. Nothing here applies. |
| Reading, forking or auditing the `ee/` source | **Free.** Non-production. |
| Building `phigate-ee` and running its test suite in CI | **Free.** Non-production. |
| Benchmarking EE's semantic cache against synthetic logs | **Free.** Non-production. |
| A developer running EE on a laptop against scrubbed sample logs | **Free.** Non-production. |
| Security team auditing EE before an approval decision | **Free.** Non-production. |
| A 3-day PoC piping **real** production logs through EE | **Ask us.** Production data — free evaluation licence available. |
| EE handling your SRE team's real alerts, internal network only | **Licence required.** Internal is still production. |
| EE in staging, mirroring live traffic | **Licence required.** Real data, ongoing. |
| EE running nightly against yesterday's real logs | **Licence required.** Real data, scheduled, ongoing. |
| Offering PhiGate to your customers as a hosted service | **Licence required.** |
| A consultancy running EE inside a client's production environment | **Licence required.** The client's use is production use. |

---

## Evaluating with real data

PhiGate's value is measurable only against real traffic. Its cost claim depends
on how repetitive *your* logs are; its privacy claim depends on what *your* data
actually contains. Synthetic data cannot answer either question, so a licence
that made real-data evaluation impossible would be self-defeating.

**We grant a free evaluation licence covering production use, for a defined
period, on request.** Email info@tenkan.co.jp with your organisation, the
intended deployment, and how long you need. The default term is 60 days and we
will extend it if your review process needs longer — a Japanese enterprise
security review routinely takes more than 60 days, and that is a reason to
extend, not a reason to buy early.

We do not require a purchase commitment, a sales call, or contact details beyond
what is needed to issue the licence.

---

## Other common questions

**Do I need a licence to contribute to `ee/`?**
No. Contributions are welcome under the DCO (`git commit -s`); see
[CONTRIBUTING.md](../CONTRIBUTING.md). You keep your copyright.

**What happens after the Change Date?**
Each released version of the Enterprise Edition converts to Apache-2.0 four
years after that version is first publicly distributed. Conversion is per
version, and it is automatic — it does not require anything from us, and we
cannot revoke it.

**Can you change the licence later and take this away?**
Not retroactively. Any version published under BSL 1.1 stays under BSL 1.1 and
converts on schedule. A licence change could only affect future versions.

**Does the Enterprise Edition make the Community Edition less safe?**
No, and the repository is arranged so you do not have to take our word for it.
CE contains every privacy control, and `make ce-purity` fails the build if any
CE package imports from `ee/`. The published container image excludes `ee/`
entirely. You can delete the directory and CE still builds and passes its full
guarantee suite — that is a checked release gate, not a claim.

**We are a Japanese corporation and our legal team needs the licence in
Japanese.**
Ask. The English text in `ee/LICENSE` governs, but we will provide a Japanese
reference translation for review purposes.

**Something here is ambiguous for our situation.**
Ask before assuming either answer: info@tenkan.co.jp. We would rather answer a
question than discover a disagreement later, and answers that turn out to be
generally useful get added to this page.
