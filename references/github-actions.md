# GitHub Actions security

The deepest V1 reference. Read this whenever `.github/workflows/` is present.
Use `scripts/inspect_workflows.py` to get normalized facts, then reason here.
The script produces facts; **you** decide what they mean. Never treat an event
name or permission in isolation — evaluate combinations and repository context.

## What to gather first

Run `python scripts/inspect_workflows.py`. For each workflow you get: `triggers`,
workflow-level `permissions`, and per-job `runner`/`self_hosted`, `environment`,
`permissions`, `actions[]` (`name`, `ref`, `pinned`, `kind`), `run_steps[]`
(`expressions`, `references_untrusted_input`), and `checkout_refs[]`
(`references_untrusted_ref`). `parse_partial: true` means read the raw file
before concluding.

## Triggers

Events to understand:

```
pull_request  pull_request_target  workflow_run  workflow_call  workflow_dispatch
repository_dispatch  issue_comment  push  schedule
```

Key distinction — **trust of the code being run and the token available**:

- `pull_request` (from a fork) runs with a **read-only** `GITHUB_TOKEN` and no
  secrets by default. Running untrusted PR code here is expected and normally
  safe.
- `pull_request_target`, `workflow_run`, `issue_comment`, `repository_dispatch`
  run in the context of the **base repository**: they can carry secrets and a
  writable token, but are triggered by potentially untrusted actors.

The classic critical pattern (correlate into ONE finding):

```
pull_request_target        # runs with base-repo secrets/token
  + checkout of PR head     # actions/checkout with ref: the PR's head sha/ref
  + use of that code        # build/test/run scripts, or run: using PR content
  (+ id-token: write / write scopes / secrets)
= untrusted code executes with privileged identity → likely CRITICAL
```

`inspect_workflows.py` surfaces the pieces: a `pull_request_target` trigger, a
`checkout_refs[].references_untrusted_ref: true`, elevated `permissions`, and
`environment`/secrets usage. If you see the checkout of PR-controlled code under
a privileged trigger, that is the finding — do not split it up.

`workflow_run` is similarly dangerous: it runs trusted workflow code but is
triggered by another (possibly fork-initiated) workflow, and often downloads and
trusts artifacts from the triggering run. Check what it downloads and whether it
treats that data as trusted.

## Token permissions

Inspect `permissions:` at workflow and job scope.

- `write-all` (or a legacy default of broad write) — flag: the token can modify
  repository contents, releases, packages, deployments, etc. Recommend the
  minimum scopes actually used, ideally `contents: read` at the top with
  per-job elevation only where needed.
- Unnecessary write scopes: `contents: write`, `packages: write`,
  `actions: write`, `pull-requests: write`, `deployments: write`.
- `id-token: write` is **not** itself a vulnerability. It enables OIDC. It
  should prompt you to investigate the external workload identity it federates
  to (see `references/secrets-identity.md`): which cloud role/identity, what
  trust conditions (repo, ref, environment), and whether an untrusted trigger
  can reach it.

Interpret every scope in the context of the job that holds it. A release job
legitimately needs more than a lint job.

## External Actions and pinning

For every `uses:` distinguish `kind`: `local`, `external`, `reusable-workflow`,
`docker`.

- **Mutable reference** (`pinned: false`) on an `external` action — e.g.
  `docker/login-action@v3` or `@main` — means the exact code executed can change
  without any change in this repository. For third-party actions this is a real
  supply-chain risk, higher when the workflow is privileged (release, deploy,
  secrets, `id-token`). Recommend pinning to a full 40-hex commit SHA.
- First-party `actions/*` pinned to a tag is lower risk than an unknown
  third party, but SHA pinning is still the hardened state.
- **Never invent a SHA.** Resolve the SHA the intended version currently points
  to using trusted tooling (`gh api`, `git ls-remote https://github.com/OWNER/REPO
  TAG`), review it, then pin. Keep the human-readable version in a trailing
  comment: `uses: owner/action@<sha> # v3.1.0`.
- Reusable workflows (`uses: owner/repo/.github/workflows/x.yml@ref`) should be
  pinned too, and you should understand what secrets are passed to them.

## Untrusted input into shell / expressions

The dangerous pattern is interpolating attacker-controlled `${{ ... }}` context
directly into a `run:` shell (script injection):

```yaml
- run: echo "Title: ${{ github.event.pull_request.title }}"   # UNSAFE
```

A PR title of `$(malicious)` or with backticks executes on the runner.
`inspect_workflows.py` reports `references_untrusted_input` per run step with the
specific untrusted context. Attacker-controlled contexts include PR/issue
titles, bodies, branch names (`github.head_ref`), comments, review bodies, and
commit messages.

Safe pattern — pass through an environment variable and quote:

```yaml
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "Title: $TITLE"
```

Severity depends on the token/secret context of the workflow and whether the
trigger is reachable by untrusted actors.

## Runners

- GitHub-hosted (`ubuntu-latest`, …) are ephemeral.
- `self-hosted` runners are persistent and often on privileged networks. Running
  untrusted contributions on a self-hosted runner, or sharing a self-hosted
  runner between PR workloads and release/deploy workloads, is a serious risk
  (persistence, lateral movement, secret theft). Correlate `self_hosted: true`
  with untrusted triggers and with deployment capability.

## Environments

`environment:` can add protection rules (required reviewers, wait timers,
branch/tag restrictions) and scope secrets. A deployment job that uses a
production environment with required reviewers is stronger than one using raw
repository secrets. Note when a privileged job does **not** use an environment.

## Concrete examples

Unsafe (correlated critical):

```yaml
on: pull_request_target
permissions: { contents: write, id-token: write }
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.head.sha }} }
      - run: ./untrusted-build.sh
```

Hardened:

```yaml
on: pull_request            # fork PRs get a read-only token, no secrets
permissions: { contents: read }
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd719...  # pinned SHA (v4.2.2)
      - run: ./build.sh
```

Record findings with `domain: ci`, an appropriate `category` (e.g.
`mutable-action`, `excessive-permissions`, `pr-target-untrusted-checkout`,
`script-injection`, `self-hosted-untrusted`), and `resource` set to the workflow
path so ids stay stable.
