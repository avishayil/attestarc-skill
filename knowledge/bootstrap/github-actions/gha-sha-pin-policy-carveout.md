---
attestarc:
  applies_to:
    product: "github.com"
  confidence: "authoritative"
  effect: "risk-increasing"
  id: "KE-gha-sha-pin-policy-carveout"
  last_verified: "2026-08-24"
  platform: "github-actions"
  sources:
    -
      authority: 100
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-docs"
      url: "https://docs.github.com/organizations/managing-organization-settings"
  status: "active"
  subject: "require-sha-pinning"
  valid_from: "2023-01-01"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/organizations/managing-organization-settings"
status: "stable"
tags:
  - "github-actions"
  - "require-sha-pinning"
title: "require-sha-pinning"
type: "platform-semantics"
---
The org/repo 'require actions to be pinned to a full-length commit SHA' policy applies to Action step.uses references, not to job-level reusable-workflow calls (job.uses org/repo/.github/workflows/x.yml@ref). Under an enforced policy a movable step.uses Action ref is rejected at run time, but a reusable-workflow call may still legitimately use a tag or branch. So a mutable reusable-workflow ref is NOT down-gated by SHA enforcement.
