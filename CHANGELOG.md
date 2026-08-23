# Changelog

All notable changes to AttestArc are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-08-23

**Public Preview — GitHub & GitHub Actions.** Hardens the persistent-state and
helper layer against untrusted repositories, widens change-review coverage, and
corrects platform guidance. Deep support remains scoped to GitHub and GitHub
Actions; other platforms get the generic methodology at lower confidence.

### Changed (breaking: finding ids)

- **`findings.json` schema → version `2`.** Finding ids widen from 6 to 8 hex
  characters (`AA-GHA-81F21C7A`), and the stable fingerprint now hashes a
  canonical `subject` (e.g. an action ref or job name) instead of the free-text
  `condition` — re-wording an explanation no longer mints a new id, while two
  distinct issues on the same resource stay distinct. Existing `schema_version:
  1` files are not id-compatible; re-initialize local state.

### Added

- **State hardening (`state.py`).** The secret-value guard now walks *every*
  string leaf of a finding (not just `evidence`/`threat`), so a value leaked
  into `title`, `impact`, `remediation`, or `extensions` is refused. Durable
  string leaves are size-capped to bound prompt-injection payloads. All writes
  are confined to `--root` with a symlink-escape guard (a `.attestarc` or `.git`
  symlink pointing outside the repository is refused). `--root` is now inferred
  from `--file` when omitted.
- **Schema hardening (`assets/findings.schema.json`).** Stable objects are
  closed (`additionalProperties: false`) with an explicit open `extensions`
  namespace for host/tool data; `evidence.type` is an enum (`repository-file`,
  `git-diff`, `remote-config`, `tool-output`, `inference`); optional
  `observed_at` / `source_revision` / `last_verified_at` / `assessment_version`
  provenance fields added.
- **Change review (`inspect_git_diff.py`, `/attestarc changed`).** Capability
  deltas now cover job-level `permissions`, new `secrets: inherit`, new
  reusable-workflow calls and their pin state, new `environment:` deployments,
  new cache use, download-and-execute steps, new attacker-controlled input
  references, artifact publish/consume, and runner-label changes — in addition
  to workflow-level permissions, privileged triggers, mutable action refs, and
  untrusted checkout refs. Only the repository-root `.github/workflows/` is
  treated as active CI, and `parse_partial` is surfaced so an empty delta on a
  partially-parsed workflow is never read as "safe".
- **Docker image pin classification (`inspect_workflows.py`).** `docker://`
  references are classified as pinned only when addressed by digest
  (`@sha256:…`); a `:tag` or implicit `latest` is reported mutable (registry
  ports are not mistaken for tags).
- **`references/capabilities.md`** — the canonical capability vocabulary used in
  `threat.capabilities`, kept consistent across findings.
- **Hash-locked CI.** `ci-constraints.txt` pins `pytest` and its full
  transitive closure by version and sha256; CI installs with `pip install
  --require-hashes --only-binary=:all:`, so a moved tag or compromised
  re-release cannot change what CI runs (resolves the prior unpinned
  `pip install --upgrade pip pytest`).
- **Dev-only differential parser test.** With the optional `PyYAML` dev
  dependency installed, a test cross-checks the stdlib workflow parser against a
  real YAML implementation on the security-relevant facts. The shipped skill and
  helpers remain stdlib-only; the test skips cleanly when PyYAML is absent.
- **Expanded behavioral eval corpus + dev-only recorder.** Interactive
  find/refuse cases for the corrected behaviors — helper-shadowing, trigger-scoped
  cache poisoning (a write-capable-trigger *find* paired with fork-PR and
  `pull_request_target` read-only *refusals*), fork-PR effective-settings
  reasoning, `changed`-mode job-level capability gains, skill-activation
  precision, and the `parse_partial` negative-conclusion guard — plus a
  non-shipping recorder (`evals/record.py`) that logs host/model/version/verdict
  for manual judgment. No autonomous eval-scoring engine ships.

### Changed

- **`discover_repo.py`** redacts credentials embedded in a remote URL (emitting
  only host/slug/redacted URL) and distinguishes `current_branch` (checked-out)
  from the repository's true `default_branch` (from `refs/remotes/origin/HEAD`),
  with a note when the default cannot be determined locally — so
  protected-default-branch reasoning is never done off the current branch.
- **`SKILL.md`** resolves bundled helpers from `${CLAUDE_SKILL_DIR}` (or the
  directory containing `SKILL.md`) and passes the subject as `--root`, never a
  repo-relative `scripts/` path; wires `inspect_git_diff.py` into `changed`;
  documents the `parse_partial` no-false-negative contract and `subject`-based
  fingerprinting; frontmatter version → `0.3.0`.
- **`references/agent-safety.md`** adds the helper-shadowing policy: a `scripts/`
  directory inside the subject is untrusted content to assess, not code to run.

### Fixed

- **Cursor guidance corrected (again).** Cursor now has native Agent Skills: it
  auto-discovers `.cursor/skills/` and `.agents/skills/` and, for compatibility,
  reads `.claude/skills/` and `.codex/skills/`. Documentation and the installer
  describe native discovery and `/attestarc` slash invocation — no
  `.cursor/rules/*.mdc` shim. This supersedes the 0.2.0 note that claimed Cursor
  had no native Skills system.
- **GitHub Actions cache-scope reasoning.** Fork `pull_request` caches are
  scoped to the merge ref and cannot write the default-branch scope;
  `pull_request_target` / `issue_comment` / `workflow_run` get read-only
  default-branch cache access; only trusted triggers create or overwrite
  default-branch cache entries. Guidance corrected accordingly.
- **Fork-PR settings API endpoint.** Effective fork-PR token/secret settings are
  read from `/repos/{o}/{r}/actions/permissions/fork-pr-workflows-private-repos`
  (and `.../fork-pr-contributor-approval`), not `/actions/permissions/workflow`
  (which only reports `default_workflow_permissions`).
- **Workflow parser correctness (`inspect_workflows.py`), found by the
  real-repository feedback pass and cross-checked against PyYAML.** Three defects
  that silently dropped facts are fixed: (1) a block sequence indented at the
  *same* column as its mapping key (e.g. `steps:` and its `- ` items at one
  indent — common GitHub Actions style) is now parsed instead of yielding empty
  `actions`/`run_steps`; (2) a leading `---` document-start marker (or trailing
  `...`) no longer makes the whole file parse as a sequence and discard every
  fact; (3) every `run:` step is now reported in `run_steps[]` (with `has_run`
  and a sanitized `run_excerpt`), so plain command steps are no longer omitted,
  while a benign `uses:` step whose only expressions are trusted (e.g.
  `${{ matrix.* }}`) no longer masquerades as a run step. Fetch-then-execute
  detection also now covers a network fetch piped into a language interpreter
  (`curl … | python3 -`, `| node`, `| ruby`, `| perl`, `| php`), not only shells.
  Regression tests cover all three, and the dev-only differential test's corpus
  is extended with the document-marker and same-indent cases.

## [0.2.0] — 2026-08-23

Evolves AttestArc's reasoning from a knowledgeable checklist into an
attack-oriented security grammar. No new scanner engine — the change is in how
the skill reasons. Findings state is enriched additively (`schema_version` stays
`1`; existing `.attestarc/findings.json` files keep working).

### Added

- **Attack-oriented reasoning grammar** in `references/methodology.md`
  (rewritten): every candidate is reasoned as `ACTOR → ENTRY POINT →
  ATTACKER-CONTROLLED INPUT → EXECUTION / TRUST TRANSITION → CAPABILITY /
  IDENTITY → TARGET ASSET → SECURITY IMPACT`. A finding is asserted only when
  evidence supports each transition; otherwise its severity/confidence is lowered
  or it becomes `needs_review` with explicit `evidence_gaps`. Adds a capability
  vocabulary, the `present → reachable → exploitable → impactful` reachability
  ladder, actor/asset models, and reachability as a first-class severity input
  (`references/severity.md`).
- **`references/threats/` layer** — a portable attack-class catalog
  (`ci-cd-threats.md`, `source-integrity.md`, `identity.md`, `supply-chain.md`)
  covering PPE, `workflow_run` artifact/cache privilege bridging, cache
  poisoning, reusable-workflow transitive trust and `secrets: inherit`,
  download-and-execute, two-party source integrity across all consumable refs,
  OIDC off-repo trust policy, effective fork-PR token/secret settings, and
  generated-vs-verified supply-chain integrity. Domain files cross-reference
  these rather than duplicate them.
- **`references/agent-safety.md`** — a tool-use trust policy: never derive
  side-effecting commands from repository or tool content; treat tool/MCP output
  as data; treat a reloaded `findings.json` as untrusted and reconfirm before
  remediating.
- **Findings schema** — optional `threat` object (`actor`, `entrypoint`,
  `controlled_input`, `trust_transition`, `capabilities`, `target`,
  `reachability`, `preconditions`, `evidence_gaps`), `trust_boundary`,
  `related_findings`, and structured `evidence.key`/`value` fields. `state.py`
  preserves these across upserts and rejects secret values found in evidence or
  anywhere under `threat`.
- **`inspect_workflows.py` facts** — job-level `secrets` (`inherit`/mapping),
  `uses_pinned`, `uses_cache`, and per-step `fetch_execute` /
  `fetch_execute_excerpt`. Facts only; the host decides what they mean.
- Expanded adversarial and false-positive **evals** and fixtures
  (`workflow_run` artifact bridging, `secrets: inherit`, curl-pipe-release,
  seeded-findings injection, and safe variants that must not be flagged).

### Changed

- `SKILL.md` routes references as explicit per-domain pairs (`threats/*` + the
  platform file) and always-load core (`methodology`, `agent-safety`,
  `severity`); frontmatter `metadata.version` → `0.2.0`.
- `SPECIFICATION.md` bakes in the grammar, capability/reachability vocabularies,
  the `threats/` ownership boundary, the new schema fields and parser facts, and
  the agent tool-use trust policy as normative.

### Fixed

- **Cursor guidance corrected.** Cursor has no native Agent Skills system and
  does not auto-discover `.claude/skills/`; documentation (README, `SKILL.md`,
  `SPECIFICATION.md`, installer help) now describes the accurate path — Claude
  Code loads the skill natively, and Cursor references it via a
  `.cursor/rules/*.mdc` rule or `AGENTS.md`.

## [0.1.0] — 2026-08-23

Initial release.

### Added

- Installable Agent Skill for Claude Code and Cursor; the repository root is the
  skill package (`SKILL.md`, `references/`, `scripts/`, `assets/` at the root).
  Skill version is declared in `SKILL.md` frontmatter (`metadata.version`).
- `install.py` / `uninstall.py` default to `.claude/skills/attestarc/`, where
  Claude Code natively discovers Agent Skills; `--platform cursor`/`both` remain
  available. Installation ships only the skill payload, not development files.
- `SKILL.md` methodology: discover → assess → record → prioritize → explain →
  remediate → verify.
- Persistent findings state in `.attestarc/findings.json` with stable finding
  IDs and JSON schema (`assets/findings.schema.json`).
- Deterministic, stdlib-only helper scripts:
  - `state.py` — initialize, list, get, upsert, set-status, resolve, validate.
  - `discover_repo.py` — repository / delivery-system facts. Reports only
    root-level `.github/workflows/` as active CI (`workflow_files`); non-root
    workflows (fixtures, examples, vendored) are surfaced separately as
    `non_root_workflow_files` with a note, since GitHub only executes root
    workflows.
  - `inspect_workflows.py` — normalized GitHub Actions workflow facts.
  - `inspect_git_diff.py` — security-relevant change facts.
- Security references: methodology, severity, github, github-actions,
  dependencies, secrets-identity, supply-chain, remediation.
- Test suite (`tests/`): script unit tests and vulnerable/secure fixture
  repositories.
- Behavioral evaluations (`evals/`): agent-level cases with a judging rubric,
  distinct from the deterministic test suite.

### Scope

- Fully supported: GitHub, GitHub Actions.
- Generic awareness: Docker, common dependency ecosystems, release and
  supply-chain configuration.
- Detected but not deeply supported: GitLab CI, CircleCI, Jenkins, Travis CI,
  Azure Pipelines, Bitbucket Pipelines.
