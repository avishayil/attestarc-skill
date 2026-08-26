---
attestarc:
  applies_to:
    version: "SLSA v1.2"
  confidence: "authoritative"
  id: "KE-slsa-source-track"
  last_verified: "2026-08-24"
  platform: "slsa"
  sources:
    -
      authority: 90
      publisher: "SLSA"
      retrieved_at: "2026-08-24"
      type: "standard"
      url: "https://slsa.dev/spec/v1.2/source-requirements"
  status: "active"
  subject: "slsa-source-track"
  valid_from: "2025-01-01"
sources:
  -
    author: "SLSA"
    resource: "https://slsa.dev/spec/v1.2/source-requirements"
status: "stable"
tags:
  - "slsa"
  - "slsa-source-track"
title: "slsa-source-track"
type: "standard"
---
SLSA v1.2 Source track levels: L1 Version controlled (source in a VCS identifying revisions); L2 History & source provenance (history protected/retained AND the platform issues signed source provenance attestations, not merely authenticated commits); L3 Continuous technical controls with evidence (continuity/authenticity assured by enforced, tamper-resistant controls that produce evidence); L4 Two-party review (every change to protected source reviewed by two trusted parties, including re-review after any modification to the final revision).
