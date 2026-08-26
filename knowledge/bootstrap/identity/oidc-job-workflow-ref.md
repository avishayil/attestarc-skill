---
attestarc:
  applies_to:
    product: "github.com"
  confidence: "authoritative"
  id: "KE-oidc-job-workflow-ref"
  last_verified: "2026-08-24"
  platform: "oidc"
  sources:
    -
      authority: 100
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-docs"
      url: "https://docs.github.com/actions/deployment/security-hardening-your-deployments/using-openid-connect-with-reusable-workflows"
  status: "active"
  subject: "oidc-subject"
  valid_from: "2024-01-01"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/actions/deployment/security-hardening-your-deployments/using-openid-connect-with-reusable-workflows"
status: "stable"
tags:
  - "oidc"
  - "oidc-subject"
title: "oidc-subject"
type: "guidance"
---
To scope a cloud identity to a specific reusable workflow (not any workflow in the repo), the external trust policy should condition on the OIDC job_workflow_ref claim (ORG/REPO/.github/workflows/x.yml@ref), pinned to a tag/SHA the maintainer controls because a ref is movable.
