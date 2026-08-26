---
attestarc:
  applies_to:
    product: "github.com"
  confidence: "authoritative"
  id: "KE-oidc-immutable-claims"
  last_verified: "2026-08-24"
  platform: "oidc"
  sources:
    -
      authority: 100
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-docs"
      url: "https://docs.github.com/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect"
  status: "active"
  subject: "oidc-subject"
  valid_from: "2026-01-01"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect"
status: "stable"
tags:
  - "oidc"
  - "oidc-subject"
title: "oidc-subject"
type: "guidance"
---
The GitHub OIDC token's repo:ORG/REPO subject is a mutable slug that changes on rename/transfer and can be re-registered by another owner after a repo is deleted/renamed. The token also carries immutable numeric claims repository_id and repository_owner_id. Current guidance: a cloud trust policy that binds these immutable claims (via custom claim conditions) is more robust than one keyed only on the mutable slug.
