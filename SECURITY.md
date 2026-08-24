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
during an assessment) and in **process** (reviewed PRs, two-party review for
root-of-trust files).

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
│   LLM extractions, web/changelog deltas, researcher & user claims      │
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

The root of trust is an **external anchor** (`knowledge/trust-anchor.json`) that
ships inside the SSH-signed skill release and lives *outside* any downloaded
bundle. It pins the Sigstore build-provenance identity (repo + signer workflow +
OIDC issuer) an official knowledge bundle must have been produced under, so **a
bundle can never declare its own trust.** Verification shells out to the system
`gh attestation verify` (no Python crypto dependency). There are two entry points
in `scripts/knowledge_verify.py`:

```
verify_download  (Updater; network/gh)          verify_installed (Assessor; no network/gh)
  gh attestation verify <manifest>                is the root the in-package snapshot?
    --repo / --signer-workflow / --issuer           → yes: bootstrap-trusted (integrity only)
  → identity matches trust-anchor?                  → no:  trusted ONLY if client state records
  → manifest pack hashes + no undeclared pack             this version+digest was attested
  → fresh (short TTL; freeze protection)          → pack hashes + no undeclared pack
  → version > client_state.highest_version        → not revoked
  → prev_digest chains to installed LKG           → else untrusted
  → not revoked
  ANY failure → DISCARD the download (keep LKG)
```

This defends against knowledge tampering, rollback to vulnerable knowledge, a
freeze on a stale version, a forged bundle, mix-and-match of files, and a
malicious mirror. Trust is **identity-constrained**: a valid attestation for some
*other* repo/workflow does not satisfy the anchor. Anti-rollback is judged against
the client's own persistent memory (`~/.attestarc/knowledge/trusted-state.json`),
never a value inside the bundle. A compromised version can be revoked via an
**attested kill switch** ([`THREAT_MODEL.md`](THREAT_MODEL.md) §8), which
re-observes affected findings rather than silently resolving them.

### Core invariants

- **Evidence required** — every finding cites something observed; no evidence, no
  finding.
- **Read-only, offline assessor** — assessment never writes the kernel or
  knowledge plane and never reaches the network.
- **No runtime self-elevation** — nothing learned at runtime modifies the trusted
  kernel; the running assessor can never grant itself more trust.
- **Fail-secure** — a download with no valid, identity-matched attestation (or a
  tampered/rolled-back/frozen one) is **discarded** and the last-known-good
  retained; expired/unavailable knowledge falls back to the in-package snapshot;
  conflict or unknown version routes to `needs_review`. Never fetch-then-trust.
- **Verified drives, candidate only asks** — only verified knowledge may drive a
  conclusion; candidate knowledge may raise an investigation question but never
  closes a chain.
- **Secrets stay out** — secret values are never persisted to `findings.json`, and
  secrets or private repository content never enter the learning pipeline.
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
  `knowledge/trust-anchor.json`, `knowledge/sources.yaml`) — e.g. a candidate that
  drives a conclusion without passing the verify-gate; knowledge promoted without a
  valid, identity-matched attestation; a forged bundle or revocation being trusted;
  authority taken from a candidate's self-declaration rather than derived from the
  source registry.
- **Release / attestation** (`.github/workflows/release-knowledge.yml`) — e.g. a
  bundle published without provenance, or a rollback/freeze that a client accepts.
- **Helper scripts and installer** — e.g. a helper mishandling untrusted
  repository content, a secret value reaching `.attestarc/findings.json`, or the
  installer writing outside the intended skills directory.

Findings state (`.attestarc/findings.json`) is created in the repositories you
assess, never in this repository, and the knowledge cache lives under
`~/.attestarc/knowledge/`, outside any assessed repo.
