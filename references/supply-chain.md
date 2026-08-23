# Supply chain

Build and release integrity: can you trust that a published artifact was built
from the reviewed source, by the expected pipeline, and cannot be silently
altered? Reason from observable repository/CI evidence; V1 needs no native
registry integrations. Standards like SLSA and OpenSSF may inform your thinking
internally, but never lead the user experience with framework scores.

## What to inspect

- **Build provenance / who builds releases**: are release artifacts built by CI
  from a protected ref, or can they be built and pushed from a developer laptop
  or an unprotected branch? CI-controlled, ref-gated builds are stronger.
- **Build-once / promote**: is the same artifact built once and promoted across
  environments, or rebuilt per environment (allowing drift between what was
  tested and what ships)?
- **Artifact references & tags**: are container base images and deployed images
  referenced by **immutable digest** (`image@sha256:...`) or by mutable tag
  (`:latest`, `:v1`)? Mutable tags mean the running artifact can change without
  a source change — the same class of risk as unpinned Actions.
- **Signing & verification**: are artifacts/images signed (e.g. Sigstore/cosign,
  GPG) and is the signature actually **verified** at deploy/pull time? Signing
  without verification provides little assurance.
- **Provenance / SBOM**: is build provenance (e.g. GitHub artifact attestations,
  SLSA provenance) generated, and is an SBOM produced and retained? Note absence
  where the delivery path warrants it — but rate it as hardening, not a
  standalone crisis.
- **Release tags**: are release tags protected from being moved or deleted
  (see `references/github.md`)? A movable release tag undermines everything
  downstream that trusts it.

## Correlate with CI and identity

The release path usually spans domains: a release workflow (CI) with
`packages: write`/`id-token: write` (identity) that pushes an image (supply
chain). Assess it as one delivery path and correlate findings rather than
scattering them.

## Recording

`domain: supply-chain`; categories such as `mutable-image-reference`,
`unsigned-artifacts`, `no-provenance`, `release-not-ci-controlled`,
`unprotected-release-tags`. Where the decisive evidence lives outside the repo
(registry settings, deploy-time verification), state what additional evidence is
required and consider `needs_review`.
