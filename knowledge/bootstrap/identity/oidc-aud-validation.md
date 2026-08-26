---
attestarc:
  applies_to:
    product: "github.com"
  confidence: "authoritative"
  id: "KE-oidc-aud-validation"
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
  subject: "oidc-audience"
  valid_from: "2024-01-01"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect"
status: "stable"
tags:
  - "oidc"
  - "oidc-audience"
title: "oidc-audience"
type: "guidance"
---
The relying party (AWS/GCP/Azure or a custom verifier) must validate the OIDC token audience (aud), and the workflow should request a provider-appropriate audience rather than leaving a permissive default. An unvalidated or default-permissive audience widens which tokens the trust policy will accept.
