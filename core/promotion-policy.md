# Promotion policy (root of trust)

How a knowledge claim moves from **candidate** (untrusted) to **verified**
(trusted for reasoning). This file is itself a **root-of-trust artifact**:
changing it changes what AttestArc will believe, so edits require two-party
review (§ *Root-of-trust files* below and `THREAT_MODEL.md` §6).

The governing rule (from `THREAT_MODEL.md`):

> AI may *discover*, *propose*, and *propose changes to itself*. A
> **deterministic** policy — not the model — decides what becomes trusted. The
> running assessor can never grant itself more trust.

The model may call `propose`; it may **never** call `promote`. Promotion is a
deterministic decision made by policy over facts, gated by review and evals.

## Candidate vs verified — the model never declares trusted fields

The model produces a **candidate** (`schemas/knowledge-candidate.schema.json`),
never a verified entry. A candidate deliberately **omits** the trusted `status`
and `confidence` fields and never declares a source's `publisher`/`type`/
`authority`: those are **assigned by promotion**, not by the model. A candidate
that carries `status` or `confidence` is a structural error rejected by
`validate_candidate`. Only `promote_to_verified` — deterministic policy, gated by
an auto-promote tier — emits a trusted `VerifiedKnowledgeEntry`
(`schemas/knowledge.schema.json`): it sets `status: active`, derives `confidence`
from source authority (`corroborated` when two or more independent authoritative
origins agree, else `authoritative`), and copies each source's provenance from the
**self-verified quarantine receipt**, never the model's declarations.

## Inputs the policy reads (never model opinion)

- **Source authority** — an integer assigned by the source registry
  (`knowledge/sources.yaml`) and **derived** by reclassifying each source URL
  (HTTPS-only, origin + path-prefix scoped, dot-segments normalized before prefix
  matching), never chosen or asserted by the model. A candidate whose declared
  authority/publisher/type disagrees with the derived values is rejected. Tiers:
  vendor docs 100, vendor changelog 95, vendor repo 90, standard 90, security org
  80, research 60, issue 40, community 20, arbitrary web 0.
- **Claim structure** — did slot extraction produce a well-formed candidate
  (schema-valid, `applies_to` bound, temporal fields present)?
- **Provenance binding** — every promotion-eligible source (allowlisted origin)
  must carry a **resolvable, self-verifying** quarantine `receipt_id`: the stored
  `.raw` bytes are re-hashed and must match the receipt's `content_hash`, and the
  receipt's `final_url` re-classifies to the same authority. An inline
  `content_hash` alone is **not** sufficient; a fabricated receipt whose bytes do
  not rehash does not resolve. Receipts also record `requested_url`/`final_url`/
  `redirect_chain`; a redirect that crosses origin (scheme+host) off the final
  origin is marked not-allowed and cannot back a promotion.
- **Conflict** — does the claim contradict an existing *authoritative* entry in the
  **immutable baseline**? The baseline is **mandatory and pinned**: it is the last
  verified released snapshot, resolved from the installed **verified** snapshot
  (`resolve_verified_baseline`, which fails closed if none is trusted) or an
  explicit `--baseline <root>`. The working tree that carries the proposal is
  **never** an implicit baseline — judging a candidate against the tree that already
  contains it would erase every conflict/modify signal.
- **Semantic diff** — against that same baseline, is the candidate `added` (new
  id) or `modified` (same id, changed `claim`/`claim_key`/`applies_to`/`effect`)?
  The set of changed paths and removed/modified evals is **derived from git**
  (`git diff --name-status <baseline-commit> HEAD`), not from caller-supplied flags,
  so a caller cannot omit the path that carries a poisoning edit. (Caller flags are
  honored only behind an explicitly-untrusted `--trust-caller-diff`, for tests.)
  Any modify of an existing **active** entry — or a supersession of one — is a
  change to established security semantics and routes to review **even when
  `supersedes` was not written** (an additive edit cannot dodge the trigger).
- **Security-regression direction** — **derived deterministically**, never taken
  from the candidate. A new `mitigation` claim, or a modification that moves an
  active `risk-increasing` claim toward `mitigation`/`neutral`, is **negative**
  (lowers scrutiny — the exact shape of a poisoning attempt); any other
  modification of an active semantic is **uncertain**. Both negative and uncertain
  route to review (fail toward scrutiny). A new `risk-increasing` claim is
  **positive**.
- **Eval result** — the policy consumes an **eval-result artifact**
  (`schemas/eval-result.schema.json`) that is trusted ONLY when it is **digest-bound**
  to the exact inputs it was produced over: `candidate_sha256` (the canonical digest
  of the entry being promoted), `baseline_manifest_sha256` (the immutable baseline it
  was judged against), and `eval_corpus_sha256` (the trusted eval corpus).
  `_load_eval_result_verified` recomputes all three and **rejects** the result on any
  mismatch, so a bare `{"passed": true}` — or a passing result recycled from a
  different candidate/baseline/corpus — can never satisfy the gate. `passed` is honored
  only with an empty `failures` list. Absent, unbound, or `passed: false` **fails
  closed** (blocks auto-promote). This is **not** an eval-runner: the behavioral evals
  stay manually judged; what the artifact binds is that a given judgement belongs to a
  given change.
- **Provenance / attestation (distribution trust)** — for published packs, a valid
  Sigstore build-provenance attestation whose identity matches the external trust
  anchor (`knowledge/trust-anchor.json`), verified via `gh attestation verify` in
  `scripts/knowledge_verify.py`. This is **distribution trust**, separate from
  content eligibility: a *missing* signature (`None`) means "not attested yet" and
  never reads as valid, but does not by itself block content promotion (the
  attestation is applied at release and verified at runtime); only a genuine
  **failed** attestation over a published pack blocks.

`may_promote` is fed the `validate_candidate` **result object** and refuses to run
on a candidate that has not passed validation (returns `never-auto`, fail closed).
`evaluate_candidate` is the single, unskippable orchestrator: validate → conflict →
semantic diff → direction → may-promote.

## Promotion tiers

**Auto-promote** — all of: candidate passed validation + authoritative source
(derived authority ≥ 90) bound to a self-verifying quarantine receipt + no conflict
with an authoritative entry + does not modify or supersede an active claim + a
non-negative, non-uncertain derived direction + a **bound** passing eval-result
artifact (see above) + (for published packs) no failed attestation.

**Require review (single-maintainer PR)** — any of: the change supersedes,
conflicts with, or otherwise **modifies an existing active/authoritative claim** (a
conflict is adjudicated → `disputed` until resolved); the direction is
**security-negative or uncertain** (previously-vulnerable → "safe", or a change we
cannot prove is safe); the eval-result artifact is missing/failing; a published
pack's attestation failed.

**Two-party review** — any change to a root-of-trust file:
`core/agent-safety.md`, `core/promotion-policy.md`, `scripts/knowledge_verify.py`,
`scripts/knowledge.py`, `scripts/knowledge_compile.py`, `knowledge/sources.yaml`,
`knowledge/trust-anchor.json`, `schemas/knowledge*.schema.json`,
`schemas/learning-candidate.schema.json`, `schemas/eval-result.schema.json`,
anything under `knowledge/promotions/` (the promotion decisions and the bootstrap
approval), the release workflow (`.github/workflows/release-knowledge.yml`), **or any
weakening or deletion of a trusted eval.**

## Promotion is enforced at release, not merely at proposal

`may_promote` decides a tier when a candidate is *proposed*, but a tier a maintainer
saw in a PR is not, by itself, what ships. The floor is **recomputed at release** so
that `promote_to_verified` is the **only** path to a shipped active entry — not merely
*a* path a hand-edited pack could sidestep.

Each promotion is recorded as a committed, reviewed artifact under
`knowledge/promotions/`:
- `<entry-id>.decision.json` — binds the promoted entry's canonical digest
  (`entry_sha256`), the baseline it was judged against (`baseline_manifest_sha256`),
  the tier, the bound eval-result, and (for a review tier) the recorded
  `review.approved_by`.
- `bootstrap.approval.json` — the digest-pinned two-party approval of the
  hand-authored entries that rode in on the signed skill release (which predate the
  pipeline and carry no quarantine receipts); recorded once, one canonical digest per
  entry id.

`knowledge_compile.py verify-promotions` runs in the release workflow **before the
manifest is built** and fails the release unless **every active entry** in the packs
is accounted for by exactly one of: a matching bootstrap-approval digest; an
`auto-promote` decision whose digest + baseline match and which **still recomputes**
to `auto-promote` from the pinned baseline + git-derived diff + rebound eval-result;
or a review-tier decision with a recorded approver. An entry that was edited after its
decision (digest mismatch), whose auto-promote decision no longer recomputes, or that
nothing accounts for, is a hard failure. This gate does not re-run quarantine/fetch —
provenance is a promotion-time property recorded in the decision; it recomputes only
what is reproducible from shipped material.

**Never auto-promote** — blog post, issue comment, researcher claim, forum post,
or model inference. These are recorded as **candidate** only. Candidate knowledge
MAY shape which investigation questions AttestArc asks; it MUST NOT drive a
security conclusion.

## The eval corpus is root of trust

A candidate MAY *add* paired find / refuse-false-positive evals. A candidate MUST
NOT weaken, loosen, or delete a trusted eval **in the same trust step** — doing so
would let a poisoning change also remove the test that catches it. Eval deletions
are two-party review, always.

## Direction matters more than confidence

A high-authority source proposing a *security-negative* — or merely *uncertain* —
change still gets human review, because that is precisely where a
compromised-source or tampered-changelog attack lands. Authority gates
auto-promotion of scrutiny-*increasing* changes; it never fast-tracks
scrutiny-*decreasing* ones. The direction is **derived** from the candidate's
`effect` and its semantic diff against the immutable baseline, never read from a
field the model controls.
