# Real-world feedback — v0.3.0 read-only assessment pass

**Date:** 2026-08-23 · **Skill version under test:** v0.3.0 (`release/v0.3.0`)
· **Mode:** strictly **read-only**.

Before cutting the v0.3.0 "Public Preview", AttestArc was exercised against ten
real repositories to see how the skill and its deterministic helpers behave on
code that was **not** written as a test fixture. This document is the single
consolidated record of that pass. It is scaffolding, not shipped skill content.

The specific repositories are intentionally not named here; each is referred to
by an anonymized **corpus index** (`#1`…`#10`) and its **archetype**. That is
enough to see which kinds of repositories stressed which behaviors — the point
of the pass — without cataloguing anyone's repositories.

## Ground rules (as run)

- **Read-only against every target.** No commits, no config writes, no issues,
  no PRs, no branch pushes to any assessed repository. The pass exercises
  DISCOVER → ASSESS → RECORD only; REMEDIATE/VERIFY were explicitly out of scope
  because they mutate state and require per-repository owner authorization.
- **Repository content is untrusted.** Each target was treated as adversarial
  input per `references/agent-safety.md`: a `scripts/` directory inside a target
  is content to assess, never code to run.
- **Facts vs. verdicts.** The goal was to find where the *helpers* mis-observe
  facts (correctness bugs) and where the *skill's* reasoning could be sharper
  (enhancements) — kept strictly separate below, because only the first class
  blocks a release.

## Corpus (anonymized by archetype)

A deliberate spread of archetypes — AWS IaC, container/ECS services, a
signing/OIDC publisher, an intentionally-vulnerable demo, and npm-published
libraries — chosen to exercise both **find** and **refuse** across Actions, IaC,
and publishing.

| # | Archetype | Primarily stressed |
|---|-----------|--------------------|
| 1 | Intentionally-vulnerable CDK IaC (AWS) | IaC detection, action-ref classification, unpinned installs |
| 2 | CDK / Python security tool | ref classification, publish signal, solo-maintainer rating, parse degradation |
| 3 | ECS / CDK service | job/workflow `env` capture, IaC detection, remove-vs-rotate |
| 4 | AWS IaC + CI | trigger qualifiers, ref classification, publish signal, environment existence |
| 5 | CloudFormation macro / signer | trigger qualifiers, environment existence, trusted publishing, solo-maintainer |
| 6 | Policy-as-code + CI | **`run_steps` bug** (curl \| python3), ref classification, IaC detection |
| 7 | Python app + CI | **`run_steps` bug**, no-`permissions`-block evidence gap, Dependabot scope |
| 8 | Intentionally-vulnerable demo | **`---` marker bug** (parse-wide), no-`permissions`-block, demo-scope guidance |
| 9 | npm library | trigger qualifiers, ref classification, publish signal, trusted publishing, run excerpts |
| 10 | npm library | ref classification, trigger qualifiers, publish signal, unpinned installs, run excerpts |

## Confirmed defects — FIXED in v0.3.0

These are helper **correctness** bugs (facts silently dropped), reproduced
directly and closed before release. They are the reason holding the release for
this pass was the right call. Each has a regression test; the parser fixes are
additionally cross-checked against PyYAML in the dev-only differential test.

1. **Block sequence at the same indent as its key was dropped**
   (`inspect_workflows.py`). When `steps:` and its `- ` items share one indent
   column — a common GitHub Actions style — the parser returned empty
   `actions`/`run_steps` and `uses_cache: false`. Every fact under such a
   `steps:` was invisible. *Impact:* whole jobs read as benign. *Fix:* a block
   sequence may share its key's indent; only a sequence (not a sibling mapping
   key) can. *Surfaced by:* several corpus repos with 4-space-style workflows.

2. **Leading `---` document-start marker discarded the entire parse**
   (`inspect_workflows.py`). A file beginning with `---` (very common) was read
   as a block sequence, so `parse_node` returned a list, `inspect_workflow_text`
   hit `not isinstance(data, dict)`, and **all** facts were dropped as
   `parse_partial`. *Impact:* the highest-severity class of miss — a real
   workflow read as unparseable/empty. *Fix:* treat `---`/`...` document markers
   as blank lines (single-document workflow subset). *Surfaced by:* the
   intentionally-vulnerable demo (#8), which flagged this highest priority.

3. **Plain `run:` steps were omitted from `run_steps[]`**
   (`inspect_workflows.py`). The emit gate was `if exprs or fetch_exec`, so a
   step like `run: make release` or `run: pytest` — command execution with no
   `${{ }}` — was never recorded, while a benign `uses:` step carrying only a
   trusted `${{ matrix.* }}` expression *was* recorded (as `has_run: false`),
   inflating and confusing the list. *Impact:* privileged command steps
   invisible; noise where there should be signal. *Fix:* emit one record per
   step that runs a command (`has_run: true`), references untrusted input, or
   fetches-and-executes, and attach a sanitized `run_excerpt`; benign
   trusted-expression `uses:` steps stay in `actions[]`. *Surfaced by:* the
   policy-as-code (#6) and Python-app (#7) repos, among others.

Adjacent fix shipped in the same pass:

4. **Fetch-then-execute now covers language interpreters.** `curl … | python3 -`
   (and `| node`, `| ruby`, `| perl`, `| php`) is download-and-run just like
   `| sh`, but only shells were matched. *Surfaced by:* the policy-as-code repo
   (#6) and an npm library (#10).

## Recommended enhancements — Tier 1 SHIPPED in v0.3.1; Tier 2–3 DEFERRED

These improve finding quality but are **feature additions**, not defects. They
expand the helper contract and the skill's guidance and want their own eval
coverage. Each stays inside the north star — helpers emit *facts*, references
teach *reasoning*. Attributions use the anonymized corpus index. Ordered by
consensus strength.

### Tier 1 — near-unanimous, high leverage — **SHIPPED in v0.3.1**

Both Tier-1 items shipped in `v0.3.1` as fact-only additions (no schema-id
change), each with unit, PyYAML-differential, and eval coverage. Left in place
below as the record of why they were built.

- **Action-ref kind classification** — *shipped v0.3.1* as `ref_kind` +
  `looks_like_version` on `actions[]`, plus `new_branch_like_mutable_references`
  in the git-diff delta. *(raised by 7+ corpus repos: #1, #2, #4, #6, #7, #9,
  #10)*. In v0.3.0 `pinned` was a single bool (true only for a 40-hex SHA),
  collapsing "tracking `@main`", "pinned to `@v4`", and "`@1.2.3`" into one
  "unpinned" bucket. A movable **branch** ref is materially riskier than a movable
  **version tag**, and the host could not tell them apart. *Fact-safe design (as
  shipped):* a `ref_kind` fact (`sha` | `movable` | `none`) plus a
  `looks_like_version` hint for movable refs — without claiming tag-vs-branch
  certainty, which is genuinely undecidable from the `uses:` string alone
  (GitHub resolves either). The same classification is wired into
  `inspect_git_diff.py`'s "newly mutable ref" delta.

- **Trigger qualifier fidelity** — *shipped v0.3.1* as a structured
  `trigger_details` map (per-event `branches`/`tags`/`paths`/`types` +
  `schedule.cron`), preserving `pull_request` vs `pull_request_target`; flat
  `triggers` retained. *(raised by #4, #5, #9, #10)*. In v0.3.0 `triggers` was a
  flat list of event names, so `on.push.tags`, `.branches`, `.paths`, and the
  critical `pull_request` vs `pull_request_target` distinction were lost — all
  load-bearing for reachability. *Fact-safe design (as shipped):* keep `triggers`
  for back-compat and add the structured `trigger_details`, leaving the privilege
  judgment to the host + references.

### Tier 2 — repeated, scoped to `discover_repo.py` / references

- **IaC framework detection** *(#1, #3, #6, #8)*: emit a presence fact for CDK /
  CloudFormation / SAM / Pulumi / Bicep so the host knows deployment identity and
  blast radius live here.
- **Publish / release signal** *(#2, #4, #9, #10)*: detect PyPI/npm publish,
  `publishConfig.provenance`, and release tooling (`release-it`, semantic-release)
  as facts that raise the stakes of a compromised pipeline.
- **Job/workflow-level `env` capture** *(#3)*: surface credential-shaped `env:`
  at workflow and job scope (names only; never values).
- **Unpinned package-manager install as a fetch-execute-adjacent fact** *(#1,
  #10)*: `npm i -g npm@latest`, `pip install <unpinned>`, `go install …@latest`
  pull mutable code into a privileged step.
- **`.pre-commit-config.yaml` as a security-relevant file** in `discover_repo`.

### Tier 3 — reference / eval guidance (no helper change)

- **Declared-but-nonexistent / unprotected `environment:` check** *(#4, #5)*: an
  `environment:` that doesn't exist, or exists without required reviewers, is not
  the deployment gate it appears to be.
- **npm/PyPI trusted-publishing (OIDC) guidance + refuse-false-positive evals**
  *(#5, #9, #10)*: OIDC trusted publishing is *safer* than a long-lived token and
  must not be flagged as a finding.
- **Solo-maintainer down-rating guidance** *(#2, #5)*: "require review" controls
  read differently on a single-maintainer repo; explain how that shifts severity
  vs. certainty.
- **No-`permissions`-block worked example** *(#7, #8)*: absence of a top-level
  `permissions:` block means the *default* token scope applies — record it as an
  `evidence_gap` / `needs_review`, not a silent pass.
- **Intentionally-vulnerable / demo-repo scoping** *(#8)*: guidance for when a
  repo is a teaching artifact — assess honestly, but frame severity in context
  rather than as production risk.
- **"Remove ≠ rotate"** *(#3)*: removing a leaked credential from source does not
  rotate it; remediation guidance must say so.
- **Dependabot does not harden branch-pinned actions** *(#7)*: Dependabot bumps
  versions; it does not convert a `@main`/`@v4` ref into a SHA pin, so its
  presence is not mitigation for mutable action refs.

## Operational note (harness, not skill)

The parallel feedback agents were initially pointed at a **shared** clone base
path (`/tmp/attestarc-feedback/`); siblings' cleanup steps deleted each other's
checkouts mid-run (all recovered by re-cloning to unique paths). This is a
property of how the pass was orchestrated, not of the skill. A future pass MUST
give each target a unique working directory and MUST NOT run destructive cleanup
in a shared parent.

## Outcome

- **Shipped in v0.3.0:** four helper correctness fixes (three parser defects +
  interpreter fetch-execute), each regression-tested and, for the parser,
  cross-checked against PyYAML.
- **Shipped in v0.3.1 (fast-follow):** both Tier-1 enhancements —
  action-ref kind classification (`ref_kind`/`looks_like_version` +
  `new_branch_like_mutable_references`) and trigger qualifier fidelity
  (`trigger_details`) — as fact-only additions with their own unit,
  differential, and eval coverage; no findings-schema id change.
- **Deferred to follow-up:** the Tier 2–3 enhancement backlog above — feature
  work that expands the fact contract and reasoning guidance and needs its own
  eval coverage, out of scope for the preview release.
- **No target repository was modified.** The pass was read-only end to end.
