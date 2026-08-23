# GitHub repository & SCM controls

Repository-domain knowledge. Much of this is **server-side** state that cannot
be read from files. Query it only with trusted, already-available read-only
tooling; never require the user to mint an overprivileged token, and never guess.

Threat model: see `references/threats/source-integrity.md` for what an attacker
gains by reaching a consumable ref (`MODIFY_SOURCE`, `BYPASS_REVIEW`,
`MUTATE_RELEASE`) and why two-party review is the load-bearing control. This file
teaches how to observe and remediate those controls on GitHub.

## How to observe remote state

If `gh` is authenticated or a GitHub MCP server is available, prefer read-only
calls, e.g. (the endpoint set is the knowledge entry
`KE-ghapi-readonly-observation-endpoints`; resolve the current paths with
`python scripts/knowledge.py lookup --platform github --subject
remote-state-endpoints`, as GitHub adds/renames endpoints over time):

```bash
gh api repos/{owner}/{repo}                                   # visibility, default branch
gh api repos/{owner}/{repo}/branches                          # enumerate branches (find release/*, production/*)
gh api repos/{owner}/{repo}/tags                              # enumerate tags (find v*, release tags)
gh api repos/{owner}/{repo}/rulesets                          # rulesets (and their ref/tag targets)
gh api repos/{owner}/{repo}/branches/{branch}/protection      # branch protection
gh api repos/{owner}/{repo}/actions/permissions               # Actions policy (enabled, allowed_actions)
gh api repos/{owner}/{repo}/actions/permissions/workflow      # default GITHUB_TOKEN perms; can workflows approve PRs
gh api repos/{owner}/{repo}/actions/permissions/fork-pr-contributor-approval        # approval gate before fork PRs run
gh api repos/{owner}/{repo}/actions/permissions/fork-pr-workflows-private-repos     # fork-PR token/secret exposure (private repos)
gh api repos/{owner}/{repo}/environments                      # environments
```

The `actions/permissions/workflow` endpoint reports only the default
`GITHUB_TOKEN` permission (read vs write) and whether Actions may create/approve
PRs — **not** whether fork PRs receive write tokens or secrets
(`KE-ghapi-fork-pr-permission-semantics`). That effective fork-PR exposure comes
from the dedicated `fork-pr-*` endpoints above (the
contributor-approval gate, and for private repositories the token/secret
exposure setting), and it decides whether a plain `pull_request` is really
read-only (see `references/github-actions.md`). If the relevant setting cannot be
read, treat it as an `evidence_gap` and record the affected CI transition
`needs_review` rather than assuming the platform default.

If none is available, state that remote settings could not be verified and
assess only what is observable locally. Absence of access is not a finding.

## What to inspect

- **All consumable refs, not just the default branch.** Protection on `main` is
  not protection on everything that ships. Enumerate the refs something downstream
  trusts and check each: the default branch, `release/*`, `production/*` and other
  deploy branches, and the `v*` / release **tags** that CI, deployments, or
  `uses:` pin against. A tightly-protected `main` next to an unprotected
  `release/*` branch or a movable `v1` tag is a real gap — whatever consumes that
  ref inherits its weakest protection. Map each ref to *who can change it* and
  *what trusts it*.
- **Protection / rulesets on each ref**: is PR review required? How many
  approvals? Are stale approvals dismissed on new commits? Are force pushes and
  branch deletion blocked? For tags, is the tag protected from being moved or
  deleted? Is the ruleset actually **enforced** (`enforcement: active`), not just
  `evaluate`/`disabled`? Does its `conditions`/target actually include the ref you
  care about — a ruleset that names `~DEFAULT_BRANCH` does nothing for
  `release/*`. A rule that exists but is not enforced, or does not target the ref,
  is decorative.
- **Two-party review is the load-bearing control.** The property that matters is
  that a change reaching a consumable ref was reviewed by someone other than its
  author — required PR review with ≥1 approval, stale-approval dismissal, and no
  self-approval/bypass. Signed commits and linear history are complementary but
  weaker: a signature proves *who* authored a commit, not that a *second person*
  reviewed it. Prefer enforced two-party review over signing alone; note both.
- **Bypass permissions**: who can bypass required review or push directly —
  admins, specific apps, roles, deploy keys? Admin bypass of required review is a
  common, meaningful weakness: it means the two-party guarantee above does not
  actually hold for those identities. Enumerate every identity on the bypass list
  per ruleset.
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
`unprotected-consumable-ref`, `no-two-party-review`, `ruleset-not-enforced`,
`actions-default-write`, `fork-pr-write-tokens`), and `resource` naming the
branch/ruleset/tag/setting.
Evidence should be `type: remote-config` with the observed setting — only when
you actually observed it. Note explicitly that the value is server-side and
verified (or that it could not be verified).
