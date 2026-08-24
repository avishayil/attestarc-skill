# Security policy

AttestArc is a security tool, so we take the security of this repository
seriously. This file has two parts: how to **report** a vulnerability, and a
transparent summary of **how AttestArc's own security model works**. The full,
normative rationale lives in [`THREAT_MODEL.md`](THREAT_MODEL.md) and
[`SPECIFICATION.md`](SPECIFICATION.md) §20–24; a visual overview is on the
[security page](https://avishay.co.il/attestarc-skill/security.html).

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
(the **Security → Report a vulnerability** tab of this repository) rather than
opening a public issue. Include enough detail to reproduce the problem.

We aim to acknowledge reports within a few business days.

## Supported versions

AttestArc is distributed as a versioned Agent Skill (`metadata.version` in
`SKILL.md`). Security fixes are applied to the latest released version; there are
no long-term support branches. Please upgrade to the latest release before
reporting, and include the version you observed the issue on.

| Version | Supported          |
|---------|--------------------|
| Latest release (`0.5.x`) | :white_check_mark: |
| Older   | :x:                |

## The AttestArc security model

AttestArc is a skill that can **learn**: it consults versioned platform facts
(the *knowledge plane*) that change what a finding means. That capability creates
a specific risk — **poisoning its knowledge is equivalent to compromising scanner
logic.** An attacker who could teach AttestArc that a dangerous pattern is "safe"
would suppress a real finding without ever touching the target repository.
AttestArc's knowledge plane is therefore treated as **security-critical code**,
and the pipeline that produces it as a software supply chain to be defended.

The primary rule:

> **Nothing learned at runtime may directly modify the trusted security brain.**
> AI may discover knowledge, propose knowledge, and propose changes to itself, but
> a *deterministic* trust policy decides what becomes trusted, and the running
> assessor can never grant itself more trust.

### Three trust zones

AttestArc's reasoning corpus is partitioned by trust. The kernel/knowledge
boundary is enforced in **code** (the assessor reads knowledge only through a
verify-gate, its helpers contain no network code, the kernel is not writable
during an assessment) and in **process** (all changes land via reviewed PRs into a
protected `main`, gated by the eval corpus and SHA-pinned Actions; the attest+publish
job is confined to a protected `knowledge-release` environment restricted to
`knowledge-v*` tags, and release tags must be signed and are immutable; root-of-trust
files additionally require two-party review — the second-approval gate is enforced
where a second reviewer is available, and is aspirational on a single-maintainer
repository, see `THREAT_MODEL.md` §6).

```
┌──────────────────────────────────────────────────────────────────────┐
│ KERNEL — highly trusted, always loaded, NEVER runtime-mutated          │
│   SKILL.md, core/ (methodology, severity, agent-safety, promotion-…),  │
│   verification helpers, schemas, eval corpus                           │
│   → changes only via reviewed PR; root-of-trust files need two parties │
├──────────────────────────────────────────────────────────────────────┤
│ VERIFIED KNOWLEDGE — trusted for reasoning                             │
│   attested, versioned, temporal, provenance-backed packs (knowledge/)  │
│   → drives a conclusion ONLY after the verification chain passes       │
├──────────────────────────────────────────────────────────────────────┤
│ CANDIDATE KNOWLEDGE — untrusted                                        │
│   LLM extractions (candidate schema: no status/confidence/authority),  │
│   web/changelog deltas, researcher & user claims                       │
│   → MAY shape which questions are asked; MUST NOT change a conclusion  │
└──────────────────────────────────────────────────────────────────────┘
```

### Three principals

The security-assessment path and the network-facing update path are separate
principals with disjoint capabilities — **skill modes plus a development
workflow**, not a hosted multi-agent runtime. This separation is *structural and
documented* (the assessor path simply contains no fetch step; ingestion lives
upstream), not an in-session sandbox.

| Principal | May | MUST NOT |
|-----------|-----|----------|
| **Assessor** (`/attestarc`) | Read repo; read *verified* knowledge; write `findings.json` | Reach the network; write kernel or knowledge; grant itself trust |
| **Updater** (`/attestarc knowledge refresh`) | Read allow-listed sources over the network; write *candidate* knowledge; promote per policy | Access the target repository; write the kernel; sign/publish releases |
| **Evolver** (dev-time) | Read candidates/evals; propose branch changes + evals | Write the production skill; release; modify or delete trusted evals in the same trust step |

The Assessor and Updater are separated precisely so a malicious repository cannot
turn the assessment path into a network-egress or exfiltration channel.

### Attestation-anchored updates

The root of trust for *knowledge bundles* is an **external anchor**
(`knowledge/trust-anchor.json`) that ships inside the skill package and lives
*outside* any downloaded bundle. (The *package itself* is authenticated at install
time by a separate anchor — see "Installing the package" below.) It pins the
Sigstore build-provenance identity (repo + signer workflow +
the reviewed git **ref** + OIDC issuer) an official knowledge bundle must have been
produced under, so **a bundle can never declare its own trust.** The SAN identity is
**artifact-specific**: a bundle must be signed from `refs/tags/knowledge-v<N>`
(`cert_identity_regexp_bundle`) and a revocation from `refs/heads/main`
(`cert_identity_regexp_revocation`), so neither can impersonate the other and a bundle
cannot be minted off `main`. Verification shells out to the system
`gh attestation verify` (no Python crypto dependency). There are two entry points
in `scripts/knowledge_verify.py`:

```
verify_download  (Updater; network/gh)          verify_installed (Assessor; no network/gh)
  gh attestation verify <archive>+<manifest>      is the root the in-package snapshot?
    --repo / --cert-identity-regex / --issuer       → yes: bootstrap-trusted (integrity only)
    (SAN binds workflow path AND the bundle ref)  → no:  trusted ONLY if client state records
  → manifest pack hashes + no undeclared pack             this version+digest was attested
  → fresh (short TTL; freeze protection)          → pack hashes + no undeclared pack
  → version > client_state.highest_version        → not revoked
  → prev_digest REQUIRED once installed, and       → else untrusted
    chains to the high-water manifest head
  → not revoked
  ANY failure → DISCARD the download (keep LKG)
```

`verify_download` decides *whether* a bundle may be installed and mutates nothing.
Actually installing it and advancing the high-water mark is done by exactly one
path — `knowledge_verify.py install` — which **verifies the archive's own
attestation before extracting it**, then **safe-extracts** the archive (refusing
absolute paths, `..`, and symlink/hardlink members before writing anything),
re-verifies the staged bytes, atomically renames the snapshot into place, and only
then atomically advances client state. Rollback memory (`~/.attestarc/state/`) and
installed snapshots (`~/.attestarc/knowledge/snapshots/`) live in separate
directories, and a *corrupt* (not merely absent) client-state file fails closed:
the Updater refuses to advance and the assessor falls back to the in-package
snapshot until an explicit reinit. The `prev_digest` chain is checked against a
**high-water manifest head** that only ever moves forward — a revocation can roll the
active snapshot back to an older last-known-good but never lowers that head, so an
in-order release after a revocation still chains and installs. Once anything is
installed, a downloaded manifest that omits `prev_digest` or fails to chain to the
head is discarded (fail-closed), never treated as a first install.

This defends against knowledge tampering, rollback to vulnerable knowledge, a
freeze on a stale version, a forged bundle, mix-and-match of files, and a
malicious mirror. Trust is **identity-constrained**: a valid attestation for some
*other* repo/workflow does not satisfy the anchor. Anti-rollback is judged against
the client's own persistent memory (`~/.attestarc/state/trusted-state.json`),
never a value inside the bundle. A compromised version can be revoked via an
**attested kill switch** ([`THREAT_MODEL.md`](THREAT_MODEL.md) §8): the single
public path attestation-verifies the revocation record against the anchor, rolls
the active snapshot back to the last retained non-revoked one, and re-observes
affected findings rather than silently resolving them.

### Installing the package

The attestation story above covers *knowledge bundles*. The **skill package**
itself has a separate root of trust, `bootstrap-anchor.json`, which lives at the
repo root *outside* the shipped payload. Be precise about what install-time
verification you get:

- **A `git clone` of a signed release tag does NOT verify the tag's SSH
  signature.** Git checks out the ref; it does not validate any signature unless
  you explicitly run `git verify-tag`. Installing from a clone is fully supported
  (and still runs the in-package knowledge integrity + trust-contract gate), but it
  makes **no** cryptographic claim about who produced the package.
- **The cryptographic install-time check is `python install.py --from-tarball
  <path>`.** It runs `gh attestation verify` on the release tarball against
  `bootstrap-anchor.json` (repo + OIDC issuer + the
  `release-skill.yml@refs/tags/v<semver>` identity) **before extracting anything**,
  then safe-extracts and installs only the verified contents. The tarball is
  produced and attested by `.github/workflows/release-skill.yml` under an
  exact-HEAD gate. Fail-secure: a missing `gh`, a verify failure, or a missing
  anchor aborts the install with nothing extracted.

### Core invariants

- **Evidence required** — every finding cites something observed; no evidence, no
  finding.
- **Read-only, offline assessor** — assessment never writes the kernel or
  knowledge plane and never reaches the network.
- **No runtime self-elevation** — nothing learned at runtime modifies the trusted
  kernel; the running assessor can never grant itself more trust.
- **Fail-secure** — a download with no valid, identity-matched attestation (or a
  tampered/rolled-back/frozen one) is **discarded** and the last-known-good
  retained; unavailable knowledge falls back to the in-package snapshot; a stale
  (expired) snapshot stays usable but its down-gate facts stop driving conclusions
  (only scrutiny-increasing facts keep driving); conflict or unknown version routes
  to `needs_review`. Never fetch-then-trust.
- **Integrity is necessary, not sufficient** — a matching attested pack hash proves
  only that these are the released bytes. Before it is trusted, a snapshot must also
  pass `validate_snapshot`: every entry schema-valid, every source's authority
  matching the registry's classification of its URL (never the value in the pack),
  and no secret-looking value present. This runs at install time and on the assessor
  read path; a partially-parsed pack fails closed rather than being reasoned over.
- **Verified drives, candidate only asks** — only verified knowledge may drive a
  conclusion; candidate knowledge may raise an investigation question but never
  closes a chain; a read that skips the verify-gate can surface facts but never
  drives one. The model produces only a *candidate* (no `status`/`confidence`, no
  self-declared source authority); a **deterministic** policy assigns those and
  promotes. Promotion demands a **self-verifying** quarantine receipt (stored bytes
  re-hash to the receipt id; cross-origin redirects rejected), computes conflict and
  a semantic diff against a **mandatory, pinned** last-released snapshot (never the
  working tree, and the changed-path/eval diff is **derived from git**, not from
  caller flags), **derives** the security direction (a lowering or uncertain change
  routes to review — never read from a model field), and consumes a **digest-bound**
  passing **eval-result artifact** — bound to the candidate, baseline, and eval
  corpus, so a bare `{"passed": true}` or a recycled result never counts (missing or
  unbound → fail closed). An additive edit of an active entry routes to review even
  without an explicit supersede.
- **Promotion is enforced at release** — the tier seen in a PR is not, by itself, what
  ships. `verify-promotions` runs in the release workflow before the manifest is built
  and fails the release unless every active shipped entry is accounted for by the
  digest-pinned bootstrap approval, a still-recomputing auto-promote decision, or a
  review-tier decision with a recorded approver (`knowledge/promotions/`). This makes
  the promotion policy the **only** path to a shipped active entry, not merely *a* path
  a hand-edited pack could sidestep.
- **Secrets stay out** — secret values are never persisted to `findings.json` —
  not even as a hash (a low-entropy secret is recoverable from its sha256, so a
  secret-like injection attempt is recorded with the hash withheld) — and secrets or
  private repository content never enter the learning pipeline.
- **Knowledge changes re-observe** — a knowledge change never auto-resolves a
  finding; it marks dependents `requires_reverification`, which re-observes the
  actual condition.

## Scope

This project is an installable Agent Skill; **the repository root is the skill
package.** The trust-critical surfaces, and example concerns for each, are:

- **Kernel** (`SKILL.md`, `core/`, verification helpers, schemas, eval corpus) —
  e.g. a path that lets the running skill modify the kernel during an assessment,
  or a verification helper that returns a verdict rather than a fact.
- **Knowledge plane** (`knowledge/`, `scripts/knowledge.py`,
  `scripts/knowledge_verify.py`, `scripts/knowledge_compile.py`,
  `knowledge/trust-anchor.json`, `knowledge/sources.yaml`, `knowledge/promotions/`,
  `schemas/eval-result.schema.json`) — e.g. a candidate that drives a conclusion
  without passing the verify-gate; an active pack entry shipped without going through
  the promotion policy (a hand-edited pack); a recycled or unbound eval-result
  satisfying auto-promote; knowledge promoted without a valid, identity-matched
  attestation; a forged bundle or revocation being trusted; authority taken from a
  candidate's self-declaration rather than derived from the source registry.
- **Release / attestation** (`.github/workflows/release-knowledge.yml`,
  `.github/workflows/release-skill.yml`, `bootstrap-anchor.json`) — e.g. a
  bundle published without provenance, an attestation minted from an unreviewed ref, or
  an old reviewed commit retagged as a higher version (the bundle job runs only on a
  `knowledge-v*` tag push and refuses to build unless the tagged commit **is the current
  tip of `main`** — an exact-HEAD gate, not mere ancestry — while the revocation job runs
  only on a `main` dispatch; the attest+publish job is confined to a `knowledge-release`
  environment restricted to signed, immutable `knowledge-v*` tags, and the anchor binds
  the certificate's git ref per artifact kind, not just the workflow path), a rollback/
  freeze that a client accepts, or a **package tarball** installed without verifying its
  provenance against `bootstrap-anchor.json` (the skill-release job attests the tarball
  under the same exact-HEAD gate; `install.py --from-tarball` verifies before extracting).
- **Helper scripts and installer** — e.g. a helper mishandling untrusted
  repository content, a secret value reaching `.attestarc/findings.json`, or the
  installer writing outside the intended skills directory.

Findings state (`.attestarc/findings.json`) is created in the repositories you
assess, never in this repository, and the knowledge cache lives under
`~/.attestarc/knowledge/`, outside any assessed repo.
