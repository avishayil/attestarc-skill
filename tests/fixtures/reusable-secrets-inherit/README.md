# Fixture: reusable-secrets-inherit

**Status: vulnerable.**

A caller workflow whose job `uses:` an **external** reusable workflow at a
**mutable** ref and passes `secrets: inherit`:

```yaml
uses: some-org/ci/.github/workflows/deploy.yml@main
secrets: inherit
```

Two correlated weaknesses in one call:

1. **Mutable external reference** (`@main`, not a pinned commit SHA). Whoever
   controls `some-org/ci` can change what runs at `main` at any time, without a
   reviewed change in this repository.
2. **`secrets: inherit`** hands the callee the caller's *entire* secret scope,
   not an explicit, minimal subset.

Trust transition: **dependency → build**. The capability reached is
`READ_SECRET` (all inherited secrets) by a party outside this repository, gated
only on that external party (or anyone who compromises it) moving `main`.

Expected: a **high** (or critical, if the inherited secrets are
production-capable) finding. The two observations should be *correlated* — the
mutable ref is what makes `secrets: inherit` dangerous — not reported as two
disconnected warnings. Reachability is `conditional` on the external repo being
changed/compromised; the trust-policy detail of what those secrets grant may be
an `evidence_gap`.
