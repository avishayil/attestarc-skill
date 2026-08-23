# Supply chain

Build and release integrity: can you trust that a published artifact was built
from the reviewed source, by the expected pipeline, and cannot be silently
altered? Reason from observable repository/CI evidence; V1 needs no native
registry integrations. Standards like SLSA and OpenSSF may inform your thinking
internally, but never lead the user experience with framework scores.

Threat model: see `references/threats/supply-chain.md` for the `CI → artifact`
boundary and why *generated ≠ verified*. This file teaches how to observe the
release path in this repository.

**Generated is not verified.** The recurring trap in this domain is treating the
*production* of a security artifact as if it were the *enforcement* of it. An SBOM
that is generated but never diffed or gated, provenance that is emitted but never
checked at deploy, a signature created but never validated at pull/deploy — each
provides assurance only at the step that *consumes and enforces* it. For every
control below, separate two questions: is it **generated/present**, and is it
**verified/enforced** (and where — in-repo, or in a deploy system you cannot
see)? Rate present-but-unenforced as hardening, and record the enforcement point
you could not observe as an `evidence_gap` / `needs_review`.

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
- **Signing & verification** (generated vs verified): are artifacts/images signed
  (e.g. Sigstore/cosign, GPG)? That is generation. The security comes from the
  signature being **verified** at pull/deploy time against an expected identity
  (`cosign verify --certificate-identity …`), not merely produced. A signing step
  with no corresponding verification step provides little assurance — say which
  you observed.
- **Provenance / SBOM** (generated vs verified): is build provenance (GitHub
  artifact attestations, SLSA provenance) generated, and an SBOM produced and
  retained? Then ask the harder question: is the provenance **verified** before
  deploy (`gh attestation verify`, policy admission) and is the SBOM actually
  *used* (diffed, policy-gated) rather than archived? Note absence where the
  delivery path warrants it, and note present-but-unverified as hardening — not a
  standalone crisis, and not a solved problem.
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
`unsigned-artifacts`, `signing-without-verification`, `no-provenance`,
`provenance-not-verified`, `sbom-generated-not-enforced`,
`release-not-ci-controlled`, `unprotected-release-tags`. Where the decisive
evidence lives outside the repo
(registry settings, deploy-time verification), state what additional evidence is
required and consider `needs_review`.
