# Threat model: source integrity

Whether the code that ships is the code that was reviewed. Pair this with
`references/github.md` for how to observe branch protection, rulesets, and
CODEOWNERS on GitHub. The organizing question:

> **Can one compromised trusted identity unilaterally introduce production
> source?**

If the answer is yes, then a single phished or malicious `developer` (or a
`compromised maintainer`) reaches `MODIFY_SOURCE` on shippable code with no
second party in the way. That is the boundary to close.

## Two-party review beats signatures

Signed commits prove *who* authored a commit; they prove nothing about whether
the change is *safe*. A malicious trusted developer can sign malicious code. So
weight controls in this order:

1. **Required review of the final revision** by someone independent of the
   author/uploader — the strongest control, denies unilateral `MODIFY_SOURCE`.
2. **Re-review after modification** — approvals dismissed when new commits land,
   so an approved PR cannot be swapped for different code before merge.
3. **Sensitive-path ownership** — CODEOWNERS that actually gate changes to
   `.github/workflows/`, deploy/IaC, release config, and auth code.
4. **Signed commits / protected history** — useful, but below the above.

A repo that requires signatures but allows a single identity to self-merge to a
release ref has not closed the boundary.

## All consumable refs, not just the default branch

"What ships" is broader than `main`. Enumerate every **consumable ref** an
attacker could target to reach released or deployed code:

```
main            release/*            v*  (release tags)            production/*
```

For each, ask the reachability questions: who can push or merge to it, who can
move/delete it, and is review actually required there? A pristine `main` with an
unprotected `release/*` branch or movable `v*` tags still leaves a `direct` path
to `MUTATE_RELEASE`. Tag protection (cannot move/delete release tags) matters
because downstream consumers trust the tag.

## Bypass is where protection leaks

Protection is only as strong as who can skip it. Look for:

- **Bypass actors** — admins, specific apps/bots, or "roles that can bypass" on a
  ruleset; a broad bypass list quietly reintroduces `BYPASS_REVIEW`.
- **Enforcement status** — a ruleset in "evaluate"/report mode is not enforced.
- **Review-dismissal restrictions** — who may dismiss reviews, and whether stale
  approvals are auto-dismissed.
- **Force-push / deletion** allowances on protected refs.

Record these as `remote-config` evidence; when the API is unavailable, mark the
affected transition `needs_review` with the setting named as an `evidence_gap`.

## SLSA Source as an internal ladder

Use this to reason about *how strong* source integrity is — never to lead the
user experience with a level number. Levels follow the **SLSA v1.2 Source track**:

- **L1** — the source is version-controlled in an identified system.
- **L2** — history is protected and retained (no silent force-push/rewrite), and
  changes are authenticated to an author/identity.
- **L3** — continuity/authenticity of the revision history is assured by
  continuous technical controls that resist tampering.
- **L4** — two-party review of the final revision, including re-review after any
  modification.

The jump from "protected branch" to L4 is exactly the two-party, review-the-final
-revision property above. Frame findings by the concrete unilateral-change risk,
not the level.
