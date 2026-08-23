# Dependencies

AttestArc is **not** an SCA engine. Do not reproduce a vulnerability database or
enumerate CVEs. Assess dependency *hygiene and integrity* — the controls that
govern how dependencies enter and change in this repository. If a scanner
(Dependabot alerts, Snyk, Trivy, osv-scanner, …) is already available, you may
cite its output as supporting evidence.

Threat model: see `references/threats/supply-chain.md` for the attack classes
(dependency confusion, install-time code execution, unpinned resolution) and the
`Dependency → build` trust boundary. This file teaches how to observe those
controls in this repository.

## What to inspect

- **Manifests & lock files**: is there a lock file (`package-lock.json`,
  `poetry.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, …)? A lock file pins
  transitive versions and enables reproducible, reviewable installs. Its absence
  in an application (vs a library) is a meaningful weakness.
- **Automated updates**: Dependabot (`.github/dependabot.yml`) or Renovate
  configured? Crucially, does it also update **GitHub Actions**
  (`package-ecosystem: github-actions`)? Automated Action updates keep SHA pins
  fresh without manual toil.
- **Dependency review — present vs enforcing**: a dependency-review step
  (e.g. `actions/dependency-review-action`) existing in a workflow is not the
  same as it *blocking* a merge. Distinguish three states: absent; present but
  advisory (`warn-only: true`, `continue-on-error: true`, or the workflow not a
  required status check); present and enforcing (fails the PR and is required by
  the ruleset). Note the action defaults to `fail-on-severity: low` with
  `warn-only: false`, so an *unset* `fail-on-severity` **blocks by default** — it
  is only advisory when explicitly softened or not gated server-side. Only the last actually gates risky dependencies at
  the boundary. Report which state you observed and what evidence shows it — and
  where enforcement lives server-side that you could not verify, record an
  `evidence_gap` / `needs_review` rather than assuming it enforces.
- **Package sources / registries**: are private/internal packages resolved from
  a trusted private registry, with public fallback restricted? Mixed
  public/private resolution without scoping invites **dependency confusion**
  (an attacker publishes a public package with the internal name and higher
  version). Check for registry/scope configuration
  (`.npmrc`, `pip.conf`, `poetry` sources, scoped registries).
- **Install integrity — how CI installs, not just what is pinned.** A lock file
  only helps if the install command honours it. Prefer the reproducible,
  lock-respecting form and flag the mutable one, especially in privileged jobs:
  `npm ci` (fails if lockfile drifts) over `npm install` (may mutate the
  lockfile and resolve new versions); `pip install -r requirements.txt` with
  hashes / `--require-hashes` over an unpinned `pip install`; `yarn
  --frozen-lockfile` / `pnpm install --frozen-lockfile`; `poetry install`
  against a committed `poetry.lock`. An install step that can silently pull a
  different version than the lockfile records is a `Dependency → build` boundary
  weakness — worse when that job holds secrets, `id-token`, or publish rights.
- **Install-time execution**: postinstall/build scripts run arbitrary code
  (`EXECUTE_UNTRUSTED_CODE` sourced from a dependency). Note when CI runs
  untrusted install scripts in a privileged context; consider whether lifecycle
  scripts are disabled (`npm ci --ignore-scripts`) where feasible. Do not execute
  them yourself to investigate.

## Severity guidance

Missing lock file or absent update tooling is usually `medium` (hygiene /
defense-in-depth). Dependency-confusion exposure on an internal package that
CI installs with credentials can be `high`. Rate by reachability and blast
radius, per `core/severity.md`.

## Recording

`domain: dependencies`; categories such as `missing-lockfile`,
`no-dependency-updates`, `actions-not-auto-updated`, `dependency-confusion-risk`,
`no-dependency-review`, `advisory-only-dependency-review`,
`mutable-install-command`, `install-script-execution`. `resource` = the
manifest/config/workflow file observed.
