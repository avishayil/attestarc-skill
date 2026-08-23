# Capability vocabulary

The canonical vocabulary for `threat.capabilities` in a finding. A **capability**
is what an attacker can *achieve* once they reach a step or identity — not which
YAML key or setting happens to exist. `core/methodology.md` introduces the
idea and carries a compact inline list for quick reference; **this file is the
authoritative catalog**. Use these exact tokens so findings correlate across a
repository (two findings that both grant `PUBLISH_ARTIFACT` are related even if
their configuration looks nothing alike). Extend the vocabulary when a case
genuinely needs a capability not listed here, and prefer an existing token over a
near-synonym.

Two rules govern how capabilities are used:

- **A capability is a fact about reach, gated by reachability.** The enabling
  configuration (a write scope, a privileged trigger, a bypass permission) is
  necessary but not sufficient. Record the capability, then walk
  `present → reachable → exploitable → impactful` (see `core/methodology.md`)
  before rating anything. `id-token: write` on a protected-tag release grants
  `REQUEST_WORKLOAD_IDENTITY` but is not itself a critical finding.
- **Capabilities chain.** The interesting findings are where a low-trust actor
  reaches one capability that unlocks another:
  `EXECUTE_UNTRUSTED_CODE` in a job holding `READ_SECRET` → the secret;
  `MODIFY_PIPELINE` → `EXECUTE_UNTRUSTED_CODE` on the next run. Name every link
  you can evidence in `threat.capabilities`; leave gaps in `evidence_gaps`.

The tokens, grouped by the asset class they act on.

## Code & pipeline execution

- **`EXECUTE_UNTRUSTED_CODE`** — run attacker-influenced code inside a trusted
  execution context (a runner with a token/secrets, a privileged job). Granted by
  checking out and building/running a fork PR head under `pull_request_target` or
  `workflow_run`, by interpreting an attacker-controlled file (Makefile,
  `package.json` script), by a `${{ }}` expression interpolated into a shell, or
  by restoring a poisoned cache/artifact that then runs. The most load-bearing
  capability: it is the usual gateway to every capability below. See
  `references/threats/ci-cd-threats.md` (PPE, cache poisoning, download-and-execute).
- **`MODIFY_PIPELINE`** — change what the pipeline itself does on a future run:
  edit a workflow file, a called reusable workflow, a composite action the
  pipeline uses, or CI config the runner reads. Distinct from a one-shot
  execution — it persists and re-triggers. Chains straight back into
  `EXECUTE_UNTRUSTED_CODE` with whatever privilege the modified pipeline holds.

## Source & review integrity

- **`MODIFY_SOURCE`** — alter the source that ships: push to or land a change on a
  consumable ref (default branch, `release/*`, a `v*` tag CI/`uses:` pins to). The
  abstract outcome; on GitHub it is reached by direct push, by a writable
  `GITHUB_TOKEN` (`WRITE_REPOSITORY`), or by defeating review (`BYPASS_REVIEW`).
  See `references/threats/source-integrity.md`.
- **`WRITE_REPOSITORY`** — a **raw permission-scope observation**, not a terminal
  capability: a repository-write grant on the workflow token or an identity
  (`contents: write`, `packages: write`, `actions: write`, `pull-requests: write`,
  a deploy key, an app installation). Always **map it to the resource-specific
  capability it realizes** — `MODIFY_SOURCE`, `MUTATE_RELEASE`, `MODIFY_PIPELINE`,
  or `PUBLISH_ARTIFACT` — by naming *which ref/asset* the write reaches. Do not
  report `WRITE_REPOSITORY` as the impact on its own; it is the mechanism, the
  resource-specific token is the finding.
- **`BYPASS_REVIEW`** — land a change on a protected ref without the two-party
  review that is the load-bearing control: admin bypass of required review, a
  ruleset in `evaluate`/`disabled` mode, a rule that does not target the ref, or
  self-approval. **Absent or decorative CODEOWNERS is a distinct, evidence-gated
  sub-case**: it only realizes `BYPASS_REVIEW` where review is not otherwise
  required for the ref (no required-reviewers rule, or CODEOWNERS review not
  enforced) — confirm that before claiming it, do not infer bypass from a missing
  `CODEOWNERS` file alone. See `references/github.md`.
- **`APPROVE_CHANGE`** — supply the *approving* review or the required environment
  approval itself (a bot/token that can approve PRs, "Allow GitHub Actions to
  approve pull requests", an environment reviewer an attacker controls). Turns a
  one-party change into an apparently-reviewed one; a force-multiplier for
  `MODIFY_SOURCE`/`DEPLOY_TO_ENVIRONMENT`.

## Secrets & identity

- **`READ_SECRET`** — read repository/organization/environment secrets or the
  workflow token in a context an attacker influences. Granted by `secrets:
  inherit` into a callee, by secrets exposed to a job reachable from an untrusted
  trigger, or by any `EXECUTE_UNTRUSTED_CODE` in a job that holds secrets. Ask
  *which* secrets and what they in turn unlock.
- **`REQUEST_WORKLOAD_IDENTITY`** — mint an OIDC token (`id-token: write`) that
  federates to an external identity provider. Not a vulnerability on its own — it
  is the *entry* to `ASSUME_EXTERNAL_IDENTITY`; the finding lives in what the
  external trust policy allows.
- **`ASSUME_EXTERNAL_IDENTITY`** — actually assume a cloud role / external
  identity the OIDC token federates to (an AWS role, GCP WIF, an npm/registry
  trusted publisher). The impactful end of the OIDC chain: severity is set by what
  that identity can do off-repo and how loosely its trust conditions (repo, ref,
  environment) are scoped. See `references/secrets-identity.md`.

## Artifacts & releases

- **`READ_ARTIFACT`** — read build artifacts, caches, or logs across a trust
  boundary (e.g. a privileged `workflow_run` downloading a fork run's artifact).
  Interesting when the bytes are later trusted or executed rather than merely
  inspected.
- **`PUBLISH_ARTIFACT`** — publish a package/image/release asset consumers trust:
  `packages: write`, a registry push, `npm publish`, a container push, a trusted
  publisher. Downstream supply-chain reach — ask who consumes it.
- **`MUTATE_ARTIFACT`** — overwrite or replace an *existing* artifact/cache/package
  that a later, more-privileged step consumes (cache poisoning, clobbering an
  uploaded artifact a `workflow_run` re-downloads). The bridge that converts a
  low-trust write into high-trust execution or publication.
- **`MUTATE_RELEASE`** — create, move, or alter a release, release asset, or a
  release/`v*` tag: `contents: write` on a release ref, a movable major tag, an
  unprotected release branch. Directly poisons what downstream `uses:`/deployments
  pin to.

## Deployment

- **`DEPLOY_TO_ENVIRONMENT`** — cause a deployment to a real environment
  (production, staging) — via an `environment:` job, a deploy workflow, or a
  writable deployment API scope. Severity follows the blast radius of the
  environment and whether required reviewers/branch restrictions actually gate it.
- **`MODIFY_DEPLOYMENT_POLICY`** — change the *rules* that gate deployment:
  environment required-reviewers, wait timers, branch/tag restrictions, or the
  ruleset protecting a deploy branch. Weakens the control itself, enabling a later
  `DEPLOY_TO_ENVIRONMENT`; treat like `MODIFY_PIPELINE` for the deploy path.

## Recording

Put the tokens an attacker would gain, in chain order, in `threat.capabilities`.
The capability is *achieved reach*, so only assert a link the evidence supports;
where a link depends on server-side state or a file you could not read, record it
in `threat.evidence_gaps` and lower confidence or mark `needs_review` rather than
assuming the chain closes.
