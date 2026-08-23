# Threat model: identity and secrets

How pipelines authenticate to the outside world, and how an attacker turns a
reached pipeline step into `READ_SECRET`, `REQUEST_WORKLOAD_IDENTITY`, or
`ASSUME_EXTERNAL_IDENTITY`. Pair this with `references/secrets-identity.md` for
GitHub observation and remediation.

## Workload identity / OIDC: the security moved off-repo

`id-token: write` federates a workflow to an external identity via OIDC instead
of a long-lived static key — generally the preferred direction. But it means the
real security control is now the **external trust policy**, which usually lives
*outside this repository*:

- AWS: the IAM role's trust relationship.
- GCP: the Workload Identity Federation pool/provider conditions.
- Azure: the federated credential's subject.

`id-token: write` by itself is not a finding. The chain is:

```
actor → trigger reachable by them → job with id-token: write
      → REQUEST_WORKLOAD_IDENTITY → external trust policy admits the token
      → ASSUME_EXTERNAL_IDENTITY → cloud/production asset
```

The decisive link is the trust policy's **subject conditions**. A policy keyed to
`repo:ORG/REPO:*` (any ref, any environment) is far weaker than one bound to
`ref:refs/heads/main` or `environment:production`. A loose policy plus an
untrusted-reachable trigger (`pull_request_target`, `workflow_run`) is the
fork-PR-to-cloud-identity path — potentially critical.

The OIDC token carries more than the `repo:ORG/REPO` **slug**, which is *mutable*
(changes on rename/transfer, re-registerable after deletion). Current guidance
(`KE-oidc-immutable-claims`, `KE-oidc-job-workflow-ref`, `KE-oidc-aud-validation`
— dated; resolve the current form via the knowledge plane): a robust policy binds
the **immutable** `repository_id` / `repository_owner_id` claims; scopes a
reusable-workflow identity on `job_workflow_ref` pinned to a tag/SHA; and
validates the token **audience (`aud`)**. A policy trusting only the mutable
slug, or accepting any audience, is
weaker than the presence of `id-token: write` alone would suggest — reason about
*which claim conditions* the relying party enforces, not just that OIDC is used.

Because the trust policy is off-repo, you usually **cannot observe it** from the
repository. Do not assume it is loose *or* tight: record the identity request as
`needs_review` with `reachability: unknown` and an `evidence_gap` naming the
exact trust policy needed (the role/pool the workflow assumes).

## Static credentials and blast radius

A long-lived credential is a standing `READ_SECRET`/`ASSUME_EXTERNAL_IDENTITY`
capability. Reason about blast radius, not just presence:

- A **committed** credential is the worst case — it is in history and in every
  clone. Removing it from the working tree does **not** rotate it; it remains
  valid and remains in git history. The finding stays open until it is actually
  rotated.
- Scope matters: environment secrets < repository secrets < organization secrets
  for blast radius. A secret reachable by an untrusted trigger, or shared across
  PR and release workflows, is reachable by a wider set of actors.
- Store only secret **names/sources** as evidence, never values.

## Effective fork-PR token and secret settings

The common belief "fork `pull_request` gets a read-only token and no secrets" is
the *default*, not a guarantee (`KE-gha-fork-pr-exposure-settings` — resolve the
current setting keys via the knowledge plane). Repository/org/enterprise settings
can change the effective state — especially on private repositories — via:

```
run_workflows_from_fork_pull_requests     send_write_tokens_to_workflows
send_secrets_and_variables                require_approval_for_fork_pr_workflows
```

If those grant fork PRs a writable token or secrets, a plain `pull_request` from
a fork can carry the same `READ_SECRET`/`WRITE_REPOSITORY` capability you would
normally attribute only to `pull_request_target`.

When you cannot read these settings, do not silently assume the default. Reason:
*"safe under GitHub's default fork policy, but the effective fork token/secret
policy was not verified"* → `needs_review`, `reachability: unknown`, with the
four settings above listed as the `evidence_gap`.
