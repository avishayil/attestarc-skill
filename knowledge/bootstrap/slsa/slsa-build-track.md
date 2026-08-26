---
attestarc:
  applies_to:
    version: "SLSA v1.2"
  confidence: "authoritative"
  id: "KE-slsa-build-track"
  last_verified: "2026-08-24"
  platform: "slsa"
  sources:
    -
      authority: 90
      publisher: "SLSA"
      retrieved_at: "2026-08-24"
      type: "standard"
      url: "https://slsa.dev/spec/v1.2/build-requirements"
  status: "active"
  subject: "slsa-build-track"
  valid_from: "2025-01-01"
sources:
  -
    author: "SLSA"
    resource: "https://slsa.dev/spec/v1.2/build-requirements"
status: "stable"
tags:
  - "slsa"
  - "slsa-build-track"
title: "slsa-build-track"
type: "standard"
---
SLSA v1.2 Build track levels: L1 the build produces provenance describing how it was made; L2 that provenance is hosted and authenticated (signed by the build platform), not self-asserted; L3 the build runs in a hardened, isolated environment a tenant cannot tamper with.
