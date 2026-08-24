# Evolution (the Evolver principal)

The **Evolver** is how AttestArc improves *itself* — its knowledge, references,
helpers, and (rarely) its kernel. It is a **dev-time, PR-gated workflow**, not a
runtime capability. The running assessor never edits AttestArc; it may only emit
`LearningCandidate` proposals (`schemas/learning-candidate.schema.json`). Nothing
here ships in the skill payload (`evolution/` is excluded from `SKILL_PAYLOAD`).

The governing rule (`THREAT_MODEL.md`):

> AI may *discover*, *propose*, and *propose changes to itself*. A deterministic
> policy — not the model — decides what becomes trusted, gated by review and
> evals. The running assessor can never grant itself more trust.

## Guarantees

- **No runtime self-modification.** A candidate is a proposal on disk. It becomes
  real only through a human-reviewed PR that passes the full eval corpus.
- **The eval corpus is root of trust.** A candidate MAY *add* paired
  find / refuse evals. It MUST NOT weaken, loosen, or delete a trusted eval in the
  same trust step (that is two-party review, always — see
  `core/promotion-policy.md`).
- **No secrets, no private content.** A candidate carries a *generalized*,
  scrubbed observation, never a secret value or private repository content.
  Learning defaults to local-only.
- **Direction matters.** A `security_regression_direction: negative` candidate
  (one that would make a previously-flagged pattern look safe) always requires
  human review — that is exactly the shape of a poisoning attempt.

## Workflow (dev-time, per candidate)

1. **Capture** — a gap surfaces during an assessment, from user feedback, or from
   an eval failure. Record it as a `LearningCandidate` under `evolution/candidates/`
   (use `prompts/classify-candidate.md`). Scrub secrets and private content.
2. **Classify** — set `type` and `change_target` (knowledge / reference / helper /
   methodology) and `security_regression_direction`. The target decides the review
   tier (methodology and root-of-trust files are two-party).
3. **Draft the change on a branch** — the concrete edit: a knowledge pack entry
   (routed through the Updater and its promotion policy), a reference paragraph, a
   helper behavior + unit test, or a kernel clause.
4. **Generate paired evals** — add a find case *and* its refuse-false-positive
   counterpart (use `prompts/generate-paired-evals.md`); add `needs-review` and
   `historical` variants where the reasoning is version- or date-sensitive.
   Additive only.
5. **Run the corpus** — the existing evals plus the new ones must pass. For
   knowledge changes, `may-promote` must not return a tier stricter than the
   review you are actually doing.
6. **Open a PR** — with rationale + provenance. Human review and CI gate the
   merge. Optionally run a generator/critic model-diversity check (a different
   model reviews the candidate for over-fitting or a hidden regression).

## Files

- `candidates/` — `LearningCandidate` JSON files (draft proposals; gitignored
  except `.gitkeep`, since real candidates may reference in-flight work).
- `prompts/classify-candidate.md` — turn a raw observation into a schema-valid
  candidate.
- `prompts/generate-paired-evals.md` — turn a candidate into an additive
  find/refuse (+needs-review/historical) eval set.
