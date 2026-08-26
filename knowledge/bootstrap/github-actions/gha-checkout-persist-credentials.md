---
attestarc:
  applies_to:
    action: "actions/checkout"
    product: "github.com"
  confidence: "authoritative"
  effect: "risk-increasing"
  id: "KE-gha-checkout-persist-credentials"
  last_verified: "2026-08-24"
  platform: "github-actions"
  sources:
    -
      authority: 90
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-repo"
      url: "https://github.com/actions/checkout"
  status: "active"
  subject: "actions-checkout-credentials"
  valid_from: "2023-01-01"
sources:
  -
    author: "GitHub"
    resource: "https://github.com/actions/checkout"
status: "stable"
tags:
  - "github-actions"
  - "actions-checkout-credentials"
title: "actions-checkout-credentials"
type: "platform-semantics"
---
actions/checkout leaves the GITHUB_TOKEN on disk for later steps by default (persist-credentials: true) unless the step sets persist-credentials: false.
