# Changelog

All notable changes to AttestArc are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-23

Initial release.

### Added

- Installable Agent Skill for Claude Code and Cursor; the repository root is the
  skill package (`SKILL.md`, `references/`, `scripts/`, `assets/` at the root).
  Skill version is declared in `SKILL.md` frontmatter (`metadata.version`).
- `install.py` / `uninstall.py` default to `.claude/skills/attestarc/`, which is
  discovered by both Claude Code and Cursor; `--platform cursor`/`both` remain
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
