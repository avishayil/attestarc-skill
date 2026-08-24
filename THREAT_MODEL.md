# AttestArc Threat Model

- **Status:** Draft — normative for the self-evolving architecture (0.5.x).
- **Scope:** The security of **AttestArc itself** as a software supply chain — its
  kernel, its knowledge plane, and its evolution pipeline. This is distinct from
  the security *of the assessed repository*, which is the product's subject and is
  covered by `SPECIFICATION.md`.
- **Audience:** Contributors. Keep in sync with `SPECIFICATION.md` and `CLAUDE.md`.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are interpreted as in RFC 2119.

**How to read this, and where else the model is documented.** This document is the
**normative** source for AttestArc's own security. Two other surfaces summarize it
for different audiences and MUST stay consistent with it (see the doc-sync rule in
`CLAUDE.md`):

- [`SECURITY.md`](SECURITY.md) — the public summary and vulnerability-reporting
  policy; it feeds the GitHub Security tab.
- The [security page](https://avishay.co.il/attestarc-skill/security.html) on the
  project site — a visual overview with the same trust zones, principals, and
  verify-chain.

Where they overlap, this document is authoritative and the others mirror it; the
trust-zone description (§2) and the verify-chain diagram (§4) are the canonical text.
A glossary of the coined terms is in §9.

## 1. Why AttestArc needs its own threat model

Once AttestArc can dynamically learn facts that alter security verdicts,
**poisoning its knowledge becomes equivalent to compromising scanner logic.** An
attacker who can teach AttestArc that `pull_request_target` is safe can suppress a
Critical finding without ever touching the target repository. Therefore AttestArc's
knowledge plane is **security-critical code**, and the pipeline that produces it is
a software supply chain that MUST be defended as one.

The primary rule:

> **Nothing learned at runtime may directly modify the trusted security brain.**
> AI may discover knowledge, propose knowledge, and propose changes to itself, but
> a *deterministic* trust policy decides what becomes trusted, and the running
> assessor can never grant itself more trust.

## 2. Trust zones

AttestArc is partitioned into three zones. The kernel/knowledge boundary is
enforced in **code** (the assessor reads knowledge only through a verify-gate, its
helpers contain no network code, and the kernel is not writable at assessment time)
and in **process** (reviewed PRs, two-party review for root-of-trust files). The
separation of the *principals* (§3) is **structural and documented**, not an
in-session sandbox: a host that pre-approves a tool (Claude Code `allowed-tools`,
Cursor) does not remove it, so AttestArc cannot claim to strip the network from a
running session. Instead the assessor path simply contains no fetch step, and
ingestion lives upstream (§3, §4).

### 2.1 KERNEL — highly trusted

`SKILL.md`, `core/` (methodology, capabilities, severity, evidence, agent-safety,
remediation, promotion-policy), the verification helpers (`scripts/knowledge_verify.py`,
`scripts/state.py`, `scripts/_pathsafe.py`), the schemas, and the eval corpus.

- Changes rarely.
- Changes ONLY through reviewed pull requests, gated by the eval corpus and (for
  root-of-trust files, §6) two-party review.
- MUST NOT be writable by the running skill during an assessment.

### 2.2 VERIFIED KNOWLEDGE — trusted for reasoning

Attested, versioned, temporal, provenance-backed knowledge packs (`knowledge/`).

- MAY be refreshed by the Updater principal (§3), never by the Assessor.
- Trusted for reasoning ONLY after passing the verification chain (§4): the
  in-package snapshot is bootstrap-trusted (it rode in on the signed skill
  release); a refreshed snapshot is trusted only if persistent client state records
  that its exact version + manifest digest was attestation-verified.
- Every entry MUST carry provenance (a registry-derived source, bound to a fetched
  object), and the pack set is only trusted after `check_consistency` passes.

### 2.3 CANDIDATE KNOWLEDGE — untrusted

LLM extractions, web discoveries, changelog deltas, researcher claims, user
feedback, and conflicting evidence.

- MAY influence which *investigation questions* AttestArc asks.
- MUST NOT change a security conclusion.
- Becomes verified only by passing deterministic promotion policy (§6).

## 3. Principals

Three principals with disjoint capabilities. They are **skill modes plus a
development workflow**, not a hosted multi-agent runtime; the host coding agent
provides all orchestration.

| Principal | May | MUST NOT |
|-----------|-----|----------|
| **Assessor** (`/attestarc`) | Read repo; read *verified* knowledge; write `findings.json` | Reach the network; write kernel or knowledge; grant itself trust |
| **Updater** (`/attestarc knowledge refresh`) | Read allow-listed sources over the network; write *candidate* knowledge; promote per policy | Access the target repository; write the kernel; sign/publish releases |
| **Evolver** (dev-time) | Read candidates/evals; propose branch changes + evals | Write the production skill; release; modify or delete trusted evals in the same trust step |

The Assessor and the Updater are separated precisely so that a malicious repository
cannot turn the security-assessment path into a network egress or data-exfiltration
channel.

## 4. Update security (attestation-based)

The root of trust is an **external anchor** that ships inside the SSH-signed skill
release — `knowledge/trust-anchor.json` — and lives OUTSIDE any downloaded bundle.
It pins the Sigstore build-provenance identity (repo + signer workflow + OIDC
issuer) that an official knowledge bundle must have been produced under. A bundle
can therefore never declare its own trust; the homemade root/timestamp/snapshot/
targets role-file protocol is gone.

Two verification entry points in `knowledge_verify.py`:

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

This defends against: knowledge tampering, rollback to vulnerable knowledge, freeze
on a stale version, a forged bundle (no valid attestation), mix-and-match of files
(the attestation covers the manifest, which pins every pack), and a malicious
mirror. Trust is **identity-constrained** by construction — a valid attestation for
some *other* repo/workflow does not satisfy the anchor. Fail-secure means the failed
download is discarded entirely; no metadata from it participates in a fallback, and
the independently-verified last-known-good is retained. Attestation verification
shells out to the system `gh attestation verify` (no Python crypto dependency;
mirrors the `ssh-keygen` shell-out convention) and is required only in the Updater
path — the Assessor verifies against recorded client state with no network or `gh`.

## 5. Fail-secure runtime policy

The runtime NEVER fetches-then-trusts. On any anomaly it degrades safely:

| Condition | Response |
|-----------|----------|
| Attestation absent / identity mismatch (download) | **Discard** the download; keep the installed last-known-good |
| Manifest/pack tampered, rolled back, or frozen (expired) | **Discard** the download; keep the installed last-known-good |
| Downloaded bundle presents `mode: bootstrap` | **Reject** — bootstrap is valid ONLY for the in-package snapshot |
| Installed knowledge expired | Warn; the in-package snapshot remains bootstrap-usable |
| Knowledge unavailable | Fall back to the in-package snapshot |
| Knowledge conflict (authoritative vs authoritative) | `status: disputed` → downgrade dependent conclusions to `needs_review` |
| Source unavailable | Do not invent an answer |
| Unknown platform/version | `needs_review` |
| Updater looks compromised | Disable the Updater |
| Knowledge changed after a finding was recorded | Mark dependents `requires_reverification`; re-observe |

Uncertainty MUST route to `needs_review`, never to "ask the LLM what seems
reasonable."

## 6. Promotion policy and root-of-trust files

Promotion from candidate to verified is **deterministic** (`core/promotion-policy.md`).
The LLM may *propose*; it may never `promote()`.

- **Auto-promote** — authoritative vendor doc/changelog + structured claim +
  provenance bound to a quarantined object + no conflict + no supersede of an
  active claim + evals pass + not a security-*negative* change.
- **Require review (PR)** — changes reachability/severity semantics, or is
  security-negative (i.e. previously-vulnerable becomes "safe" — the exact shape a
  poisoning attempt takes).
- **Two-party review** — changes to root-of-trust files: `core/agent-safety.md`,
  `core/promotion-policy.md`, `scripts/knowledge_verify.py`, `scripts/knowledge.py`,
  `scripts/knowledge_compile.py`, `knowledge/sources.yaml`,
  `knowledge/trust-anchor.json`, `schemas/knowledge*.schema.json`,
  `schemas/learning-candidate.schema.json`, `.github/workflows/release-knowledge.yml`,
  or **any weakening/deletion of a trusted eval**.
- **Never auto-promote** — blog / issue / researcher post / model inference →
  candidate only.

Authority is assigned by the source registry (`knowledge/sources.yaml`), never by
the model. The eval corpus is itself root-of-trust: a candidate MAY *add* paired
find/refuse evals but MUST NOT weaken or delete trusted evals in the same trust step.

## 7. Findings, provenance, and invalidation

- Every finding derived from a knowledge entry MUST record its
  `knowledge_dependencies` (`{id, content_hash}`; `content_hash` is REQUIRED — an
  id alone cannot reliably invalidate a finding when the underlying claim changes).
- When a dependency is superseded/revoked, dependent findings surface
  `requires_reverification` (a read-time view; stored status is never silently
  mutated). A knowledge change MUST NEVER auto-resolve a finding.
- Secrets and private repository content MUST NEVER enter the learning pipeline;
  learning defaults to local-only. Sanitized attack *shapes* (not code) are the only
  material that may generalize.

## 8. Kill switch

A compromised knowledge version MUST be revocable: publishing a revocation causes
clients to disable that version, roll back to the last verified snapshot, and mark
findings assessed under it `requires_reverification`. This path is designed before
it is needed.

## 9. Glossary

Terms coined in this document and reused across `SECURITY.md`, `SPECIFICATION.md`,
and the security page.

- **Trust anchor** — the external root of trust (`knowledge/trust-anchor.json`)
  that ships inside the SSH-signed skill release and lives outside any downloaded
  bundle. It pins the Sigstore build-provenance identity (repo + signer workflow +
  OIDC issuer) an official bundle must have been produced under. Two-party review
  to change.
- **Bootstrap-trusted** — the trust status of the *in-package* knowledge snapshot:
  it is trusted for integrity (its packs match the manifest) *because it rode in on
  the attested skill release*, not because it declares itself trusted. A
  *downloaded* bundle presenting `mode: bootstrap` is always rejected.
- **Verified-LKG (last-known-good)** — a refreshed snapshot that is trusted only
  because persistent client state records that its exact version + manifest digest
  was attestation-verified. The retained LKG is what fail-secure falls back to.
- **Quarantine receipt (`QR-…`)** — a record binding an upstream fetched document
  (stored by content hash) to its registry-derived provenance. Candidate knowledge
  references a receipt; the document is inert data, never instructions.
- **Derived authority** — a source's authority integer, obtained by reclassifying
  its URL through the identity-scoped source registry (`knowledge/sources.yaml`),
  never taken from a candidate's self-declaration. A candidate whose declared
  authority/publisher/type disagrees with the derived values is rejected.
- **`requires_reverification`** — a read-time view surfaced on a finding whose
  knowledge dependency was superseded or revoked. The stored status is never
  silently mutated and a knowledge change never auto-resolves a finding; the
  condition is re-observed.
- **`needs_review`** — the fail-secure landing state for uncertainty: an unknown
  platform/version, an unverifiable snapshot, or an authoritative-vs-authoritative
  conflict routes here rather than to an improvised LLM judgment.
