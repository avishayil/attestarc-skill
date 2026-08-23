# Fixture: workflow-run-artifact

**Status: vulnerable.**

Models a low-trust build → poisoned-artifact → privileged-release bridge.

- `pr-build.yml` runs on `pull_request` (reachable by any fork), correctly holds
  only `contents: read`, and uploads a `dist` artifact. On its own this is fine.
- `publish.yml` runs on `workflow_run` (completion of "PR Build"). It downloads
  the artifact produced by the *triggering* run and executes/publishes it while
  holding `id-token: write` and `packages: write` in the `production`
  environment. The artifact contents were controlled by the fork PR.

The trust transition is **workflow → workflow**: a fork contributor controls the
artifact bytes in the unprivileged build, and the privileged workflow consumes
them without any independent validation (no checksum/signature check, no
provenance verification). Reaching capabilities `PUBLISH_ARTIFACT`,
`REQUEST_WORKLOAD_IDENTITY`, and `EXECUTE_UNTRUSTED_CODE` against the artifact
and identity assets.

Expected: a **critical** correlated finding describing the cross-workflow bridge.

A *safe* counterpart — a `workflow_run` consumer that independently verifies the
artifact (checksum/signature/provenance) before use, or rebuilds from a trusted
source rather than trusting the downloaded bytes — should **not** be flagged
critical. That safe variant is exercised as a described variant in
`evals/cases/safe-workflow-run-with-validated-artifact.yaml` rather than as a
second workflow here, to keep this fixture unambiguously the vulnerable case.
