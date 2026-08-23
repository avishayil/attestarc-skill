# Secrets & identity

How the repository and its CI authenticate, and where privilege transitions
happen. **Never** put a secret value into `findings.json` or any output — store
only metadata (name, source, scope).

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
- Can an **untrusted trigger** reach the OIDC-enabled job? Correlate with
  `references/github-actions.md`: `pull_request_target`/`workflow_run` +
  `id-token: write` + a broad trust policy is a path from a fork PR to a cloud
  identity → potentially `critical`.
- The trust policy usually lives outside the repo (in cloud IaC or the cloud
  console). If you cannot observe it, say so and record `needs_review`.

## Secret scope

- Prefer **environment secrets** (scoped, with protection rules) over broad
  **repository secrets** for production credentials.
- Note when secrets are available to workflows triggered by untrusted actors, or
  shared across PR and release workloads.
- Organization secrets exposed to all repositories widen blast radius.

## Recording

`domain: identity-secrets`; categories such as `static-cloud-credential`,
`committed-secret`, `broad-oidc-trust`, `secret-reachable-by-untrusted-trigger`.
For remediation of exposed credentials, see `references/remediation.md` §secrets.
