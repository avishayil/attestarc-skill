# Secrets & identity

How the repository and its CI authenticate, and where privilege transitions
happen. **Never** put a secret value into `findings.json` or any output — store
only metadata (name, source, scope).

Threat model: see `references/threats/identity.md` for the capability chain
`READ_SECRET` / `REQUEST_WORKLOAD_IDENTITY` → `ASSUME_EXTERNAL_IDENTITY` and why
the external trust policy is usually the decisive, off-repo control. This file
teaches how to observe credentials and identity federation in this repository.

## Static credentials

Look for long-lived credentials in CI and config:

- Cloud keys (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `GCP_SA_KEY`,
  `AZURE_CREDENTIALS`), service-account JSON, registry tokens, API keys.
- Credentials **committed** to the repository (in code, `.env`, config, or
  history) are the worst case. If you find one, treat it as exposed and
  requiring rotation — removing it from the working tree does **not** rotate it,
  and it remains in history.

Record only: `{"secret_detected": true, "source": "...", "name": "AWS_DEPLOY_KEY"}`
— never the value. Confirm nothing you write matches a secret pattern.

## Workload identity / OIDC

`id-token: write` federates the workflow to an external identity via OIDC
instead of a static key — generally the preferred direction. But the security
now lives in the **trust policy** of the external identity (AWS IAM role trust,
GCP Workload Identity Federation, Azure federated credentials):

- Which subject conditions are required? A trust policy that allows
  `repo:ORG/REPO:*` (any ref, any environment) is far weaker than one scoped to
  `ref:refs/heads/main` or a specific `environment:production`.
- **Prefer immutable claims over the mutable slug**
  (`KE-oidc-immutable-claims` — this is dated guidance; resolve the current form
  with `knowledge.py lookup --platform oidc --subject oidc-subject`). The
  `repo:ORG/REPO` subject is a *slug* that changes on rename/transfer and can be
  re-registered by another owner after a repo is deleted/renamed. GitHub's OIDC
  token also carries `repository_id` and `repository_owner_id` — **immutable
  numeric** claims that survive rename/transfer. A trust policy that binds these
  (via custom claim conditions) is more robust than one keyed only on the slug.
- **Reusable-workflow trust via `job_workflow_ref`** (`KE-oidc-job-workflow-ref`).
  When the identity should be usable only from a specific reusable workflow, the
  policy should condition on `job_workflow_ref`
  (`ORG/REPO/.github/workflows/x.yml@ref`), and — because a ref is movable — pin it
  to a tag/SHA the maintainer controls. This is how you scope a cloud identity to
  "only this pipeline", not "any workflow in the repo".
- **Validate the `aud` (audience)** (`KE-oidc-aud-validation`). The relying party
  (AWS/GCP/Azure or a custom verifier) must check the token audience, and the
  workflow should request the provider-appropriate audience rather than leaving a
  permissive default. An unvalidated audience widens which tokens the trust policy
  will accept.
- Can an **untrusted trigger** reach the OIDC-enabled job? Correlate with
  `references/github-actions.md`: `pull_request_target`/`workflow_run` +
  `id-token: write` + a broad trust policy is a path from a fork PR to a cloud
  identity → potentially `critical`.
- The trust policy usually lives outside the repo (in cloud IaC or the cloud
  console). It is the decisive control, and it is almost always an
  **off-repo `evidence_gap`**: without it you cannot tell whether
  `REQUEST_WORKLOAD_IDENTITY` actually reaches `ASSUME_EXTERNAL_IDENTITY` for an
  untrusted actor. If you cannot observe it, do not resolve the chain by
  assumption in either direction — record the transition as `needs_review` and
  name exactly what you need (the IAM role trust JSON, the WIF pool/provider
  condition, the Azure federated-credential subject). If the cloud IaC *is* in
  this repo, read it and cite the subject conditions as evidence.

## Secret scope

- Prefer **environment secrets** (scoped, with protection rules) over broad
  **repository secrets** for production credentials.
- Note when secrets are available to workflows triggered by untrusted actors, or
  shared across PR and release workloads.
- Organization secrets exposed to all repositories widen blast radius.
- **Effective fork-PR reachability is a server-side setting**
  (`KE-gha-fork-pr-exposure-settings`). Under the platform default a fork
  `pull_request` gets no secrets, but the repo/org options that send write tokens
  or secrets to fork PRs (and `secrets: inherit` into reusable workflows) can
  widen this — you cannot see it in the workflow file. Correlate
  with `references/github-actions.md` and `references/github.md`; if the effective
  setting is unverifiable, treat "a fork PR can read this secret" as
  `needs_review` with an `evidence_gap`, not a confident critical or a dismissal.

## Recording

`domain: identity-secrets`; categories such as `static-cloud-credential`,
`committed-secret`, `broad-oidc-trust`, `secret-reachable-by-untrusted-trigger`.
For remediation of exposed credentials, see `core/remediation.md` §secrets.
