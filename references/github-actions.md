# GitHub Actions security

The deepest V1 reference. Read this whenever `.github/workflows/` is present.
Use `scripts/inspect_workflows.py` to get normalized facts, then reason here.
The script produces facts; **you** decide what they mean. Never treat an event
name or permission in isolation — evaluate combinations and repository context.

Threat model: see `references/threats/ci-cd-threats.md` for the portable attack
classes (untrusted-code execution, workflow-to-workflow privilege bridging, cache
poisoning, reusable-workflow trust, download-and-execute). This file teaches how
to observe and remediate them on GitHub Actions.

## What to gather first

Run `python scripts/inspect_workflows.py`. For each workflow you get: `triggers`
(flat event names) and `trigger_details` (per-event `branches`/`tags`/`paths`/
`types` and `schedule.cron` — see Triggers below), workflow-level `permissions`,
and per-job `runner`/`self_hosted`, `environment`,
`permissions`, `uses` / `uses_pinned` (job-level reusable-workflow call and
whether it is SHA-pinned), `secrets` (what a reusable-workflow call passes —
`"inherit"`, a name→source map, or none), `uses_cache` (the job reads/writes an
Actions cache), `actions[]` (`name`, `ref`, `pinned`, `ref_kind`,
`looks_like_version`, `kind` — see External Actions and pinning), `run_steps[]`
(`expressions`, `references_untrusted_input`, `fetch_execute`,
`fetch_execute_excerpt`), and `checkout_refs[]` (`references_untrusted_ref`).
`parse_partial: true` means read the raw file before concluding. These are
presence facts, not verdicts: a `uses_cache: true` or `secrets: inherit` is only
a finding once you close the attack chain to a reachable, valuable asset.

## Triggers

Events to understand:

```
pull_request  pull_request_target  workflow_run  workflow_call  workflow_dispatch
repository_dispatch  issue_comment  push  schedule
```

Key distinction — **trust of the code being run and the token available**:

- `pull_request` (from a fork) runs with a **read-only** `GITHUB_TOKEN` and no
  secrets **under the platform default**. Running untrusted PR code here is
  expected and normally safe.
- `pull_request_target`, `workflow_run`, `issue_comment`, `repository_dispatch`
  run in the context of the **base repository**: they can carry secrets and a
  writable token, but are triggered by potentially untrusted actors.

**Effective fork-PR permissions are a setting, not a constant.** The read-only /
no-secrets behaviour above is the *default*, and it can be widened server-side:
the repository/org Actions settings "Send write tokens to workflows from fork
pull requests" and "Send secrets to workflows from fork pull requests" (common on
some private-repo configurations) grant a fork PR a writable token and/or
secrets even on a plain `pull_request`. You cannot see this from the workflow
file. Reason from the default, but treat the effective setting as an
`evidence_gap`: if it is unverifiable, record the affected transition as
`needs_review` rather than assuming the default holds (correlate with
`references/github.md` remote-state discovery).

**Read the qualifiers, not just the event name.** `trigger_details` scopes
*where* an event fires, and the scope changes reachability:

- `push` restricted to `tags: [v*]` (and no `branches`) is a **release** trigger,
  not an everyday branch push — it fires when a maintainer cuts a tag, so it is a
  natural home for publish/`id-token` steps. `push` with `branches: [main]` is the
  post-merge default-branch path. A `push` with neither is broad. Do not treat a
  tags-only release push as an unrestricted branch push (a false positive), and do
  not treat a branch push as if it only fired on releases.
- `paths`/`paths-ignore` narrow which file changes fire the workflow; they gate
  reachability but are **not** a security boundary (a PR touching those paths
  still fires).
- `pull_request` vs `pull_request_target` is a distinct event key, never a
  qualifier — the parser preserves both. See the trust distinction above; this is
  the single most load-bearing trigger fact.

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

### Workflow → workflow privilege bridging

`workflow_run` runs **trusted, base-repo** workflow code (with secrets and a
writable token) but is *triggered by another workflow* — including one that ran
untrusted fork-PR code. The danger is the **data** that crosses from the low-trust
run into the privileged one:

- **Artifacts.** The privileged `workflow_run` job downloads artifacts produced
  by the triggering (possibly fork) run and treats them as trusted — e.g.
  unpacks them, reads a PR number or path from them, comments, or deploys. An
  attacker who controlled the first run controls those bytes. Category:
  `workflow-run-artifact-trust`.
- **Caches.** A privileged job restoring a cache that a lower-trust run populated
  inherits whatever that run wrote — see cache poisoning below.
- **Outputs / conclusion.** Branching on `github.event.workflow_run.*` fields the
  untrusted run influenced.

Close the chain: *fork PR → untrusted first workflow writes artifact/cache →
`workflow_run` job (secrets + write token) consumes it → capability
(`WRITE_REPOSITORY`, `PUBLISH_ARTIFACT`, `DEPLOY_TO_ENVIRONMENT`) → asset*. Check
what the job downloads/restores and whether it validates provenance before using
it. The `uses_cache` fact flags cache participation; artifact download shows up as
a `download-artifact` action or a `run_steps` fetch.

### Cache poisoning

The Actions cache is a **trust boundary**, not just a speed optimization: cache
entries are not signed or verified. What decides reachability is the **scope**
rule — GitHub scopes each cache entry to the git ref that created it, and a run
restores from its own ref with fallback to the repository's **default branch**
(and, for a pull request, its base branch). Reason about *who can write the scope
the privileged run restores from*:

- A **fork `pull_request`** run is isolated: its token is read-only and any cache
  it writes is confined to that PR's own scope. It **cannot** write an entry that
  a later run on the default or a protected branch will restore. The often-repeated
  "a fork PR poisons the default-branch cache" chain does **not** close — do not
  flag it on that basis.
- The cache *is* poisonable by an actor who can cause code to run **in a base-repo
  ref scope** with cache-write access: a lower-privileged collaborator pushing a
  topic branch, or a `pull_request_target` / `issue_comment` / `workflow_run` run
  a fork influenced (these run in the base repo, in a branch scope, with a
  writable token). Whatever such a run writes into a branch scope, a privileged
  run on that branch — or one that falls back to it — can later restore.

If the restored content is executable (compiled binaries, `node_modules`, a
toolchain, a downloaded dependency) and a privileged job runs it, an attacker who
poisoned that scope achieves `EXECUTE_UNTRUSTED_CODE` in the privileged context.

`uses_cache: true` on a job is the presence fact. To close the chain ask: can a
low-trust actor populate the key **in a scope** the privileged job restores from,
and does the privileged job *execute* what it restored (vs merely reading data)?
Category: `cache-trust-boundary`. Remediation directions: scope/segment cache keys
so untrusted-writable refs cannot populate keys trusted runs read, or avoid
restoring caches in privileged jobs that execute the restored content.

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
- **Not all mutable refs are equally risky — read `ref_kind` and
  `looks_like_version`.** `ref_kind: sha` is the hardened state (immutable commit
  or `@sha256:` digest). `ref_kind: movable` covers *both* a version tag (`@v4`,
  `@1.2.3`) and a branch (`@main`, `@master`), because the `uses:` string alone
  cannot tell them apart — GitHub resolves either against tags then branches. The
  `looks_like_version: true` hint separates them: a movable **version tag** is at
  least a deliberate release the maintainer cut, whereas a movable **branch**
  (`looks_like_version: false`) can be silently repointed to arbitrary code at any
  moment. Treat a branch-tracking ref in a privileged workflow as materially worse
  than a floating version tag, but pin *both* to a SHA for the hardened state.
  `looks_like_version` is a hint, not proof — a branch literally named `v2` would
  read as version-shaped; when the distinction is load-bearing, confirm with
  `git ls-remote` whether the ref is a tag or a branch.
- First-party `actions/*` pinned to a tag is lower risk than an unknown
  third party, but SHA pinning is still the hardened state.
- **Never invent a SHA.** Resolve the SHA the intended version currently points
  to using trusted tooling (`gh api`, `git ls-remote https://github.com/OWNER/REPO
  TAG`), review it, then pin. Keep the human-readable version in a trailing
  comment: `uses: owner/action@<sha> # v3.1.0`.
- **Docker-based actions are mutable references too.** A `kind: docker` step
  (`uses: docker://image:tag`, or an action whose `runs.using: docker` points at
  a registry `image:` tag rather than a digest) executes whatever that tag
  resolves to at run time — the same drift risk as an unpinned action, but the
  code is an opaque image. Prefer an immutable digest (`docker://image@sha256:…`).
  Category: `mutable-docker-action`.

**Local and composite actions are transitive code, not trusted leaves.** A
`uses: ./path` step (`kind: local`, flagged `transitive_code: true` with its
`local_path`) runs whatever that action's `action.yml`/`action.yaml` declares —
a `run:` script, a composite action's own steps, or another `uses:`. Living
in-repo does not make it trusted: it executes with the job's privilege and is a
place attacker-influenced changes can hide. Build scripts a workflow invokes
(`make`, `npm run build`, `./ci/*.sh`) are transitive code the same way. The
parser surfaces the reference but does **not** recurse — when a local/composite
action or invoked script is on a privileged or untrusted-reachable path, read
the referenced file as part of the assessment rather than assuming it is benign.

**Reusable workflows and `secrets: inherit`.** A job-level
`uses: owner/repo/.github/workflows/x.yml@ref` runs another workflow's code with
whatever secrets the caller passes. The facts to reason over:

- `uses_pinned: false` — the called workflow is a **mutable reference**; its code
  (and every action *it* runs) can change without a change here. On a privileged
  caller this is transitive supply-chain exposure. Category:
  `mutable-reusable-workflow`.
- `secrets: "inherit"` — the called workflow receives **all** of the caller's
  secrets, not an explicit subset. Combined with a mutable/third-party callee, or
  a callee reachable from an untrusted trigger, this hands the full secret set
  across a trust boundary you may not control. Prefer passing only the named
  secrets a workflow needs. Category: `reusable-workflow-secrets-inherit`.

Trace the transitive chain: caller trigger → callee ref (pinned?) → what the
callee does with the inherited secrets/token. A pinned, first-party callee
receiving one scoped secret is very different from `@main` with `inherit`.

**`actions/checkout` version semantics.** The checked-out ref is what matters,
not just the action version. Under `pull_request_target`/`workflow_run`, an
explicit `with: ref: ${{ github.event.pull_request.head.sha }}` (or `head.ref`)
checks out **attacker-controlled code** into a privileged context —
`inspect_workflows.py` flags this as `checkout_refs[].references_untrusted_ref`.
The checkout alone is inert; the trust transition closes when a later step
(build, test, install, `make`, a local action, an arbitrary script) then
**executes** that checked-out code with the privileged token/secrets in scope.
Trace to the executing step, not just the checkout.
Also note `persist-credentials: true` (the default before you set it false)
leaves the token on disk for later steps, and `fetch-depth`/submodule options
that pull additional untrusted content. The safe default checkout under a fork
`pull_request` is fine; the danger is re-pointing it at PR head under a
privileged trigger.

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

## Download-and-execute in `run:` steps

A step that fetches content from the network and pipes it straight into a shell
(`curl … | sh`, `wget … && chmod +x && ./…`, PowerShell `irm … | iex`) runs code
that is neither in the repository nor pinned — its behaviour is whatever the
remote server returns at run time, and the endpoint (or its DNS/TLS) can be
attacker-influenced. `inspect_workflows.py` surfaces this as
`run_steps[].fetch_execute: true` with a `fetch_execute_excerpt` of the matched
line. This is a **fact, not a verdict**: weigh it by the job's privilege and
trigger. `curl https://get.example.io | sh` installing a toolchain in a
release/deploy job (secrets, `id-token`, `packages: write`) is
`EXECUTE_UNTRUSTED_CODE` reaching a valuable capability → potentially high; the
same line in a throwaway lint job on `pull_request` is far weaker. Category:
`download-and-execute`. Remediation directions: pin to a versioned installer with
a checksum, vendor the script and review it, or replace it with a pinned action.

## Platform mitigations as reachability down-gates

Modern org/repo Actions settings can move a pattern back down the ladder from
`reachable` to `present`. Read them (via trusted `gh`/MCP) before rating, and
where you cannot, record `needs_review` with an `evidence_gap` — never assume a
mitigation is present, and never turn its absence into a finding:

- **Require-SHA-pinning policy** (`actions/*` allow-list / "require actions to be
  pinned to a full-length commit SHA"). Under an enforced policy, a movable
  `uses:` ref (`@v4`, `@main`) is rejected at run time, so the drift path is not
  reachable the usual way — the finding becomes "policy would need to lapse", not
  "runs arbitrary code now".
- **Workflow Execution Protections / fork-PR approval** — "require approval for
  all outside collaborators" (or all fork PRs) gates whether an untrusted trigger
  runs at all. An approval-gated fork `pull_request` is not attacker-reachable
  without a maintainer's action; note that human approval is the control and can
  be socially engineered, but it is a real gate.
- **Allowed-actions and reusable-workflow allow-lists** — restrict which external
  code can execute, narrowing the untrusted-code surface.

These are down-gates on **reachability**, not evidence of a finding. A movable
ref under an enforced SHA policy is hardening-at-most; the same ref with no such
policy (or an unverifiable one) stays reachable.

## Runners

`inspect_workflows.py` emits `self_hosted` and the runner `labels` as **facts**.
`self_hosted: true` is not itself the risk — do not equate it with "persistent".
What sets blast radius is three separable properties the label alone rarely
answers; record them as `evidence_gaps`/`needs_review` when the workflow can't:

- **Ephemeral vs persistent** — an ephemeral runner (fresh VM/container per job,
  `--ephemeral`, or an autoscaling set like actions-runner-controller) discards
  state between jobs, so cross-job persistence and lateral movement are far
  weaker than on a long-lived host that reuses its filesystem and credentials.
- **Runner-group scope** — which repos/workflows may target this runner. A group
  scoped to one trusted repo is very different from an org-wide group any repo
  (or a fork PR) can land jobs on.
- **Network segmentation** — what the runner's network reaches (production,
  cloud metadata endpoints, internal services). A segmented runner limits what a
  compromise touches.

The serious pattern is running **untrusted contributions** on a **persistent,
broadly-scoped, poorly-segmented** self-hosted runner, or sharing one between PR
workloads and release/deploy workloads (persistence, lateral movement, secret
theft). Correlate `self_hosted: true` with untrusted triggers and deployment
capability — but reason about those three properties, not the bool alone.

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
`script-injection`, `self-hosted-untrusted`, `workflow-run-artifact-trust`,
`cache-trust-boundary`, `reusable-workflow-secrets-inherit`,
`mutable-reusable-workflow`, `mutable-docker-action`, `download-and-execute`),
and `resource` set to the workflow path so ids stay stable.
