# AttestArc Threat Model

- **Status:** Draft — normative for the self-evolving architecture (0.5.x).
- **Scope:** The security of **AttestArc itself** as a software supply chain — its
  kernel, its knowledge plane, and its evolution pipeline. This is distinct from
  the security *of the assessed repository*, which is the product's subject and is
  covered by `SPECIFICATION.md`.
- **Audience:** Contributors. Keep in sync with `SPECIFICATION.md` and `CLAUDE.md`.

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are interpreted as in RFC 2119.

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

AttestArc is partitioned into three zones. The boundary between them is enforced in
**code and process**, not merely in prompt text.

### 2.1 KERNEL — highly trusted

`SKILL.md`, `core/` (methodology, capabilities, severity, evidence, agent-safety,
remediation, promotion-policy), the verification helpers (`scripts/knowledge_verify.py`,
`scripts/state.py`, `scripts/_pathsafe.py`), the schemas, and the eval corpus.

- Changes rarely.
- Changes ONLY through reviewed pull requests, gated by the eval corpus and (for
  root-of-trust files, §6) two-party review.
- MUST NOT be writable by the running skill during an assessment.

### 2.2 VERIFIED KNOWLEDGE — trusted for reasoning

Signed, versioned, temporal, provenance-backed knowledge packs (`knowledge/`).

- MAY be refreshed automatically by the Updater principal (§3), never by the
  Assessor.
- Trusted for reasoning ONLY after passing the full verification chain (§4).
- Every entry MUST carry provenance and a valid threshold signature.

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

## 4. Update security (TUF-inspired)

Knowledge packs are distributed and verified like software updates, using the
separation-of-roles / threshold / expiry / anti-rollback ideas from The Update
Framework. The client (`knowledge_verify.py`) MUST verify **before use**:

```
trusted root
  → signature threshold satisfied   (ssh-keygen -Y verify; no Python crypto dep)
  → timestamp fresh                 (not expired)
  → snapshot consistent             (references the targets)
  → target hash + size match
  → version monotonic               (reject rollback / freeze)
  → load
```

This defends against: knowledge tampering, rollback to vulnerable knowledge, freeze
on a stale version, a single compromised signing key (threshold), mix-and-match of
knowledge files, and a malicious mirror.

Signatures MUST be identity-constrained (expected issuer, source repository, release
workflow, ref) — the existence of a valid signature is not sufficient. Root keys are
the maintainer SSH public keys recorded as allowed-signers in `knowledge/root.json`.

## 5. Fail-secure runtime policy

The runtime NEVER fetches-then-trusts. On any anomaly it degrades safely:

| Condition | Response |
|-----------|----------|
| Signature invalid | **Reject** the pack |
| Knowledge expired | Use last-known-good bundled snapshot + warn |
| Knowledge unavailable | Use bundled snapshot |
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

- **Auto-promote** — authoritative vendor doc/changelog + structured claim + no
  conflict + evals pass + valid signature + not a security-*negative* change.
- **Require review (PR)** — changes reachability/severity semantics, or is
  security-negative (i.e. previously-vulnerable becomes "safe" — the exact shape a
  poisoning attempt takes).
- **Two-party review** — changes to root-of-trust files: `core/agent-safety.md`,
  `core/promotion-policy.md`, `scripts/knowledge_verify.py`, `knowledge/root.json`,
  the release workflow, or **any weakening/deletion of a trusted eval**.
- **Never auto-promote** — blog / issue / researcher post / model inference →
  candidate only.

Authority is assigned by the source registry (`knowledge/sources.yaml`), never by
the model. The eval corpus is itself root-of-trust: a candidate MAY *add* paired
find/refuse evals but MUST NOT weaken or delete trusted evals in the same trust step.

## 7. Findings, provenance, and invalidation

- Every finding derived from a knowledge entry MUST record its
  `knowledge_dependencies` (`{id, version|content_hash}`).
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
