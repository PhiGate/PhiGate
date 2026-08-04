# Your push was blocked by secret scanning

GitHub found something in your commits that matches a credential pattern. Work
through this in order — the first question is the only one that really matters.

---

## 1. Is it a real credential?

**If yes — rotate it first, before touching the git history.**

The secret is already on your disk, in your shell history, and possibly in a
build log or a CI cache. Removing it from git does not un-leak it; only
revoking it does. Rotate at the provider, confirm the old value is dead, and
*then* clean the history.

**Do not use the "allow this secret" link GitHub offers.** That unblocks the
push and leaves a live credential in a public repository forever.

Once rotated:

```bash
# If the secret is in the most recent commit and it has not been pushed:
git rm --cached <file>          # or edit the file to remove the value
git commit --amend --no-edit

# If it is in an older commit, rewrite the range:
git rebase --onto <good-commit> <bad-commit>^ <branch>
```

Then tell **security@tenkan.co.jp** what leaked and when, even if you rotated
it. That is a disclosure decision, not an engineering one.

---

## 2. Is it a test fixture?

This is the common case in PhiGate, because the project's whole purpose is
detecting credentials — so the test suite is full of things that look exactly
like credentials.

**A scanner cannot tell your fixture from a real secret, and neither can a
future reader.** So the rule here is:

> No credential-shaped literal exists anywhere in this repository.

Fixtures are stored as **fragments joined at load time**. See
[`internal/redact/testdata/leak_corpus.json`](../internal/redact/testdata/leak_corpus.json):

```json
"synthetic_secrets": {
  "slack_token": ["xox", "b-2444556677-", "8899001122-", "AbCdEfGhIjKlMnOpQrSt"]
}
```

and reference it from a case as `${slack_token}`. The test assembles the exact
same bytes, so detection is tested at full strength — but no file on disk ever
contains the assembled string.

`TestNoLiteralCredentialsInCorpus` enforces this, and it will fail before
GitHub does:

```bash
go test ./internal/redact/ -run TestNoLiteralCredentials
```

If you add a fixture for a credential format that test does not yet know about,
add its pattern there too, so the next contributor gets the same early warning.

---

## 3. Is it a false positive?

Genuinely random data — a UUID, a hash, a base64 blob — occasionally matches a
provider pattern. If you are certain it is not a credential and cannot be
mistaken for one:

1. Say so in the pull request, with what the value actually is.
2. Ask a maintainer to review before anything is bypassed.

Bypassing is a maintainer decision, not an author one. It is recorded in the
repository's security log either way.

---

## Why this is stricter here than elsewhere

PhiGate is a data-protection boundary. Its credibility rests on a test corpus
that proves no credential survives redaction — and that corpus is worthless if
contributors have to disable a security control to commit it, or if it quietly
teaches people that bypassing push protection is routine.

Keeping the repository free of credential-shaped literals costs one extra step
when adding a fixture. Getting it wrong costs a real secret in public history.

Questions: **security@tenkan.co.jp** · [SECURITY.md](../SECURITY.md) · [CONTRIBUTING.md](../CONTRIBUTING.md)
