# Real-world feedback — v0.3.0 read-only assessment pass

**Date:** 2026-08-23 · **Skill version under test:** v0.3.0 (`release/v0.3.0`)
· **Mode:** strictly **read-only**.

Before cutting the v0.3.0 "Public Preview", AttestArc was exercised against ten
real public repositories to see how the skill and its deterministic helpers
behave on code that was **not** written as a test fixture. This document is the
single consolidated record of that pass. It is scaffolding, not shipped skill
content.

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

## Targets

All under `github.com/avishayil/`. A deliberate spread: AWS IaC, container/ECS
services, signing/OIDC publishers, an intentionally-vulnerable demo, and two
npm-published React Native libraries.

| # | Repository | Shape | Primarily stressed |
|---|------------|-------|--------------------|
| 1 | `cdk-goat` | CDK IaC (intentionally vulnerable AWS) | IaC detection, action-ref classification, unpinned installs |
| 2 | `cdk-bucket-takeover-scanner` | CDK / Python tool | ref classification, publish signal, solo-maintainer rating, parse degradation |
| 3 | `jupyter-ecs-service` | ECS/CDK service | job/workflow `env` capture, IaC detection, remove-vs-rotate |
| 4 | `secure_ec2` | AWS IaC + CI | trigger qualifiers, ref classification, publish signal, environment existence |
| 5 | `cf-signer` | CloudFormation macro / signer | trigger qualifiers, environment existence, trusted publishing, solo-maintainer |
| 6 | `cloud-custodian-example` | Policy-as-code + CI | **`run_steps` bug** (curl \| python3), ref classification, IaC detection |
| 7 | `rag-search-homeassistant` | Python app + CI | **`run_steps` bug**, no-`permissions`-block evidence gap, Dependabot scope |
| 8 | `caponeme` | Intentionally-vulnerable demo | **`---` marker bug** (parse-wide), no-`permissions`-block, demo-scope guidance |
| 9 | `react-native-restart` | npm library | trigger qualifiers, ref classification, publish signal, trusted publishing, run excerpts |
| 10 | `react-native-user-avatar` | npm library | ref classification, trigger qualifiers, publish signal, unpinned installs, run excerpts |

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
   key) can. *Surfaced by:* several targets with 4-space-style workflows.

2. **Leading `---` document-start marker discarded the entire parse**
   (`inspect_workflows.py`). A file beginning with `---` (very common) was read
   as a block sequence, so `parse_node` returned a list, `inspect_workflow_text`
   hit `not isinstance(data, dict)`, and **all** facts were dropped as
   `parse_partial`. *Impact:* the highest-severity class of miss — a real
   workflow read as unparseable/empty. *Fix:* treat `---`/`...` document markers
   as blank lines (single-document workflow subset). *Surfaced by:* `caponeme`
   (flagged highest priority).

3. **Plain `run:` steps were omitted from `run_steps[]`**
   (`inspect_workflows.py`). The emit gate was `if exprs or fetch_exec`, so a
   step like `run: make release` or `run: pytest` — command execution with no
   `${{ }}` — was never recorded, while a benign `uses:` step carrying only a
   trusted `${{ matrix.* }}` expression *was* recorded (as `has_run: false`),
   inflating and confusing the list. *Impact:* privileged command steps
   invisible; noise where there should be signal. *Fix:* emit one record per
   step that runs a command (`has_run: true`), references untrusted input, or
   fetches-and-executes, and attach a sanitized `run_excerpt`; benign
   trusted-expression `uses:` steps stay in `actions[]`. *Surfaced by:*
   `cloud-custodian-example`, `rag-search-homeassistant`, and others.

Adjacent fix shipped in the same pass:

4. **Fetch-then-execute now covers language interpreters.** `curl … | python3 -`
   (and `| node`, `| ruby`, `| perl`, `| php`) is download-and-run just like
   `| sh`, but only shells were matched. *Surfaced by:* `cloud-custodian-example`
   and `react-native-user-avatar`.

## Recommended enhancements — DEFERRED (backlog)

These improve finding quality but are **feature additions**, not defects. They
expand the helper contract and the skill's guidance and want their own eval
coverage, so they are recorded here for a follow-up (target v0.3.1 / v0.4.0)
rather than bolted onto the preview release. Each stays inside the north star —
helpers emit *facts*, references teach *reasoning* — noted per item. Ordered by
consensus strength.

### Tier 1 — near-unanimous, high leverage

- **Action-ref kind classification** *(raised by 7+ targets: cdk-goat,
  cdk-bucket-takeover-scanner, secure_ec2, cloud-custodian-example,
  rag-search-homeassistant, react-native-restart, react-native-user-avatar)*.
  Today `pinned` is a single bool (true only for a 40-hex SHA), collapsing
  "tracking `@main`", "pinned to `@v4`", and "`@1.2.3`" into one "unpinned"
  bucket. A movable **branch** ref is materially riskier than a movable
  **version tag**, and the host currently can't tell them apart. *Fact-safe
  design:* add a `ref_kind` fact (`sha` | `movable` | `none`) plus a
  `looks_like_version` hint for movable refs — without claiming tag-vs-branch
  certainty, which is genuinely undecidable from the `uses:` string alone
  (GitHub resolves either). Wire the same classification into
  `inspect_git_diff.py`'s "newly mutable ref" delta.

- **Trigger qualifier fidelity** *(raised by 4+ targets: secure_ec2, cf-signer,
  react-native-restart, react-native-user-avatar)*. `triggers` is a flat list of
  event names, so `on.push.tags`, `.branches`, `.paths`, and the critical
  `pull_request` vs `pull_request_target` distinction are lost — all load-bearing
  for reachability. *Fact-safe design:* keep `triggers` for back-compat and add a
  structured `trigger_details` (per-event `branches`/`tags`/`paths`/`types`),
  leaving the privilege judgment to the host + references.

### Tier 2 — repeated, scoped to `discover_repo.py` / references

- **IaC framework detection** *(cdk-goat, jupyter-ecs-service, caponeme,
  cloud-custodian-example)*: emit a presence fact for CDK / CloudFormation / SAM
  / Pulumi / Bicep so the host knows deployment identity and blast radius live
  here.
- **Publish / release signal** *(secure_ec2, cdk-bucket-takeover-scanner,
  react-native-restart, react-native-user-avatar)*: detect PyPI/npm publish,
  `publishConfig.provenance`, and release tooling (`release-it`, semantic-release)
  as facts that raise the stakes of a compromised pipeline.
- **Job/workflow-level `env` capture** *(jupyter-ecs-service)*: surface
  credential-shaped `env:` at workflow and job scope (names only; never values).
- **Unpinned package-manager install as a fetch-execute-adjacent fact**
  *(react-native-user-avatar, cdk-goat)*: `npm i -g npm@latest`,
  `pip install <unpinned>`, `go install …@latest` pull mutable code into a
  privileged step.
- **`.pre-commit-config.yaml` as a security-relevant file** in `discover_repo`.

### Tier 3 — reference / eval guidance (no helper change)

- **Declared-but-nonexistent / unprotected `environment:` check** *(secure_ec2,
  cf-signer)*: an `environment:` that doesn't exist, or exists without required
  reviewers, is not the deployment gate it appears to be.
- **npm/PyPI trusted-publishing (OIDC) guidance + refuse-false-positive evals**
  *(react-native-restart, react-native-user-avatar, cf-signer)*: OIDC trusted
  publishing is *safer* than a long-lived token and must not be flagged as a
  finding.
- **Solo-maintainer down-rating guidance** *(cf-signer,
  cdk-bucket-takeover-scanner)*: "require review" controls read differently on a
  single-maintainer repo; explain how that shifts severity vs. certainty.
- **No-`permissions`-block worked example** *(rag-search-homeassistant,
  caponeme)*: absence of a top-level `permissions:` block means the *default*
  token scope applies — record it as an `evidence_gap` / `needs_review`, not a
  silent pass.
- **Intentionally-vulnerable / demo-repo scoping** *(caponeme)*: guidance for
  when a repo is a teaching artifact — assess honestly, but frame severity in
  context rather than as production risk.
- **"Remove ≠ rotate"** *(jupyter-ecs-service)*: removing a leaked credential
  from source does not rotate it; remediation guidance must say so.
- **Dependabot does not harden branch-pinned actions** *(rag-search-homeassistant)*:
  Dependabot bumps versions; it does not convert a `@main`/`@v4` ref into a SHA
  pin, so its presence is not mitigation for mutable action refs.

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
- **Deferred to follow-up:** the Tier 1–3 enhancement backlog above — feature
  work that expands the fact contract and reasoning guidance and needs its own
  eval coverage, out of scope for the preview release.
- **No target repository was modified.** The pass was read-only end to end.
