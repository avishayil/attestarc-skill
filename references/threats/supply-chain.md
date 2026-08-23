# Threat model: supply chain

Integrity of what the build consumes and what it ships. Pair this with
`references/supply-chain.md` (release/artifact observation) and
`references/dependencies.md` (dependency hygiene) for GitHub-specific how-to.

Two principles drive almost every finding here: **anything executable pulled into
the build needs an immutable identity**, and **a control only counts when it is
verified/enforced, not merely generated**.

## Generated is not verified

The most common overclaim in supply-chain security is crediting a control for
existing. Producing an attestation the pipeline never checks changes nothing for
an attacker. Hold each pair apart:

```
SBOM generated            ≠   SBOM consumed / gated on
provenance generated      ≠   provenance verified before deploy
artifact signed           ≠   signature enforced at deploy/pull time
image digest known        ≠   deployment pins that digest
dependency-review present ≠   dependency-review enforcing (fail-on-severity)
```

For each, ask *where is the verification step, and what happens on failure?* If
nothing consumes the artifact, or a failed check does not block, the chain that
would stop a `PUBLISH_ARTIFACT`/`MUTATE_RELEASE` attack does not close — it is
hardening at best, not assurance.

## Immutable identity for anything executable

Any executable fetched into CI can change under you if it is referenced by a
moving pointer. The `dependency → build` boundary opens whenever a mutable
reference lets a third party (or a `compromised maintainer` of that dependency)
inject code:

- Actions and **reusable workflows** — prefer a full commit SHA over a tag/branch.
- **Docker images and base images** — `image:latest` / `image:v3` can be
  retagged; prefer `image@sha256:…`. A `docker://tool:tag` action is the same
  class of risk as an unpinned Action.
- **Downloaded binaries and curl'd scripts** — pin to a digest/release and verify
  a checksum or signature (see download-and-execute in
  `references/threats/ci-cd-threats.md`).

The rule of thumb: *anything executable fetched into CI should have an immutable
identity when practical.* Weight the risk by the privilege of the job that runs
it.

## Dependency install integrity

"A lock file exists" is shallow. The question is whether CI actually installs the
**reviewed, locked** set — otherwise the review of the lock file protects
nothing:

- `npm ci` (honors the lockfile, fails on drift) vs `npm install` (may resolve
  new versions); `--ignore-scripts` where practical to avoid install-time
  execution.
- `pip install --require-hashes` / hashed constraints vs unpinned installs.
- `poetry sync`/locked, `cargo --locked`, `bundler --frozen`, `pnpm --frozen-
  lockfile`.

A pipeline that reviews a lockfile but then runs an install command free to pull
different versions has a `dependency → build` gap. Do not turn AttestArc into an
SCA scanner — reason about *install integrity*, not the CVE list.

## SLSA Build as an internal ladder

Use this to reason about build trustworthiness — never to lead with a level.
Levels follow the **SLSA v1.2 Build track**:

- **L1** — the build produces provenance describing how it was made.
- **L2** — that provenance is hosted and authenticated (signed by the build
  platform), not self-asserted.
- **L3** — the build runs in a hardened, isolated environment that a tenant
  cannot tamper with.

Map observations to the ladder to decide *how much* to trust an artifact's
origin, then frame the finding by the concrete integrity gap (e.g. "provenance is
generated but never verified before deploy"), not the number.
