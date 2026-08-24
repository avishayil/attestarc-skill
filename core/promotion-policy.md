# Promotion policy (root of trust)

How a knowledge claim moves from **candidate** (untrusted) to **verified**
(trusted for reasoning). This file is itself a **root-of-trust artifact**:
changing it changes what AttestArc will believe, so edits require two-party
review (§ *Root-of-trust files* below and `THREAT_MODEL.md` §6).

The governing rule (from `THREAT_MODEL.md`):

> AI may *discover*, *propose*, and *propose changes to itself*. A
> **deterministic** policy — not the model — decides what becomes trusted. The
> running assessor can never grant itself more trust.

The model may call `propose`; it may **never** call `promote`. Promotion is a
deterministic decision made by policy over facts, gated by review and evals.

## Inputs the policy reads (never model opinion)

- **Source authority** — an integer assigned by the source registry
  (`knowledge/sources.yaml`) and **derived** by reclassifying each source URL
  (HTTPS-only, origin + path-prefix scoped), never chosen or asserted by the model.
  A candidate whose declared authority/publisher/type disagrees with the derived
  values is rejected. Tiers: vendor docs 100, vendor changelog 95, vendor repo 90,
  standard 90, security org 80, research 60, issue 40, community 20, arbitrary web 0.
- **Claim structure** — did slot extraction produce a well-formed
  `KnowledgeEntry` (schema-valid, `applies_to` bound, temporal fields present)?
- **Conflict** — does the claim contradict an existing *authoritative* entry?
- **Security-regression direction** — does adopting the claim make AttestArc
  treat a previously-flagged pattern as safe (**negative**), keep risk the same
  (**neutral**), or increase scrutiny (**positive**)? A negative-direction change
  is the exact shape a poisoning attempt takes.
- **Eval result** — does the full corpus (existing + any paired evals shipped
  with the change) pass?
- **Provenance / attestation** — for published packs, a valid Sigstore
  build-provenance attestation whose identity matches the external trust anchor
  (`knowledge/trust-anchor.json`), verified via `gh attestation verify` in
  `scripts/knowledge_verify.py`. The provenance of a *candidate* is bound to a
  quarantine receipt over the fetched object.

## Promotion tiers

**Auto-promote** — all of: authoritative source (derived authority ≥ 90) +
well-formed structured claim bound to a quarantine receipt + no conflict with an
authoritative entry + does not supersede an active claim + evals pass + (for
published packs) a valid attestation + direction is **not** security-negative.

**Require review (single-maintainer PR)** — any of: the change supersedes or
conflicts with an existing active/authoritative claim (a conflict is adjudicated →
`disputed` until resolved); the change alters reachability or severity semantics;
the direction is **security-negative** (previously-vulnerable → "safe").

**Two-party review** — any change to a root-of-trust file:
`core/agent-safety.md`, `core/promotion-policy.md`, `scripts/knowledge_verify.py`,
`scripts/knowledge.py`, `scripts/knowledge_compile.py`, `knowledge/sources.yaml`,
`knowledge/trust-anchor.json`, `schemas/knowledge*.schema.json`,
`schemas/learning-candidate.schema.json`, the release workflow
(`.github/workflows/release-knowledge.yml`), **or any weakening or deletion of a
trusted eval.**

**Never auto-promote** — blog post, issue comment, researcher claim, forum post,
or model inference. These are recorded as **candidate** only. Candidate knowledge
MAY shape which investigation questions AttestArc asks; it MUST NOT drive a
security conclusion.

## The eval corpus is root of trust

A candidate MAY *add* paired find / refuse-false-positive evals. A candidate MUST
NOT weaken, loosen, or delete a trusted eval **in the same trust step** — doing so
would let a poisoning change also remove the test that catches it. Eval deletions
are two-party review, always.

## Direction matters more than confidence

A high-authority source proposing a *security-negative* change still gets human
review, because that is precisely where a compromised-source or
tampered-changelog attack lands. Confidence gates auto-promotion of
scrutiny-*increasing* changes; it never fast-tracks scrutiny-*decreasing* ones.
