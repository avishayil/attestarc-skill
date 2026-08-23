# GitHub repository & SCM controls

Repository-domain knowledge. Much of this is **server-side** state that cannot
be read from files. Query it only with trusted, already-available read-only
tooling; never require the user to mint an overprivileged token, and never guess.

## How to observe remote state

If `gh` is authenticated or a GitHub MCP server is available, prefer read-only
calls, e.g.:

```bash
gh api repos/{owner}/{repo}                                   # visibility, default branch
gh api repos/{owner}/{repo}/rulesets                          # rulesets
gh api repos/{owner}/{repo}/branches/{branch}/protection      # branch protection
gh api repos/{owner}/{repo}/actions/permissions               # Actions policy
gh api repos/{owner}/{repo}/environments                      # environments
```

If none is available, state that remote settings could not be verified and
assess only what is observable locally. Absence of access is not a finding.

## What to inspect

- **Default branch & protection / rulesets**: is PR review required? How many
  approvals? Are stale approvals dismissed on new commits? Are force pushes and
  branch deletion blocked? Is the ruleset actually enforced (not just "evaluate")?
- **Bypass permissions**: who can bypass required review or push directly —
  admins, specific apps, roles? Admin bypass of required review is a common,
  meaningful weakness.
- **CODEOWNERS**: does it exist, and does it cover sensitive paths
  (`.github/workflows/`, deployment/IaC, release config, auth code)? Is
  code-owner review actually required by the ruleset? A CODEOWNERS file with no
  enforcing rule is decorative.
- **Signed commits / protected tags**: are signed commits required on protected
  branches? Are release tags protected from being moved or deleted?
- **Repository visibility** and whether that matches expectations.
- **Actions policy**: are only selected/verified actions allowed? Can workflows
  create/approve PRs? What is the default `GITHUB_TOKEN` permission
  (read vs write)? A repo/org default of write-all is a broad weakness.
- **Environments**: required reviewers, wait timers, and branch/tag
  restrictions on production environments; secret scoping to environments.
- **Deploy keys, apps, bots**: enumerate write-capable identities and whether
  each is still needed and least-privilege.
- **Security features**: secret scanning + push protection, Dependabot alerts,
  code scanning — present and enabled where appropriate.

## Recording

Use `domain: repository`, a stable `category` (e.g. `branch-protection-bypass`,
`missing-codeowners-enforcement`, `unprotected-release-tags`,
`actions-default-write`), and `resource` naming the branch/ruleset/setting.
Evidence should be `type: remote-config` with the observed setting — only when
you actually observed it. Note explicitly that the value is server-side and
verified (or that it could not be verified).
