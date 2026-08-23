# Dependencies

AttestArc is **not** an SCA engine. Do not reproduce a vulnerability database or
enumerate CVEs. Assess dependency *hygiene and integrity* — the controls that
govern how dependencies enter and change in this repository. If a scanner
(Dependabot alerts, Snyk, Trivy, osv-scanner, …) is already available, you may
cite its output as supporting evidence.

## What to inspect

- **Manifests & lock files**: is there a lock file (`package-lock.json`,
  `poetry.lock`, `go.sum`, `Cargo.lock`, `Gemfile.lock`, …)? A lock file pins
  transitive versions and enables reproducible, reviewable installs. Its absence
  in an application (vs a library) is a meaningful weakness.
- **Automated updates**: Dependabot (`.github/dependabot.yml`) or Renovate
  configured? Crucially, does it also update **GitHub Actions**
  (`package-ecosystem: github-actions`)? Automated Action updates keep SHA pins
  fresh without manual toil.
- **Dependency review**: is there a dependency-review step/workflow on PRs
  (e.g. `actions/dependency-review-action`) to block known-bad or newly-added
  risky dependencies before merge?
- **Package sources / registries**: are private/internal packages resolved from
  a trusted private registry, with public fallback restricted? Mixed
  public/private resolution without scoping invites **dependency confusion**
  (an attacker publishes a public package with the internal name and higher
  version). Check for registry/scope configuration
  (`.npmrc`, `pip.conf`, `poetry` sources, scoped registries).
- **Install-time execution**: postinstall/build scripts run arbitrary code.
  Note when CI runs untrusted install scripts in a privileged context. Do not
  execute them yourself to investigate.

## Severity guidance

Missing lock file or absent update tooling is usually `medium` (hygiene /
defense-in-depth). Dependency-confusion exposure on an internal package that
CI installs with credentials can be `high`. Rate by reachability and blast
radius, per `references/severity.md`.

## Recording

`domain: dependencies`; categories such as `missing-lockfile`,
`no-dependency-updates`, `actions-not-auto-updated`, `dependency-confusion-risk`,
`no-dependency-review`. `resource` = the manifest/config file observed.
