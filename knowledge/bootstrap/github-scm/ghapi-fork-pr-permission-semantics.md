---
attestarc:
  applies_to:
    product: "github.com"
  confidence: "authoritative"
  id: "KE-ghapi-fork-pr-permission-semantics"
  last_verified: "2026-08-24"
  platform: "github"
  sources:
    -
      authority: 100
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-docs"
      url: "https://docs.github.com/rest/actions/permissions"
  status: "active"
  subject: "fork-pr-permission-endpoints"
  valid_from: "2024-01-01"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/rest/actions/permissions"
status: "stable"
tags:
  - "github"
  - "fork-pr-permission-endpoints"
title: "fork-pr-permission-endpoints"
type: "api"
---
The actions/permissions/workflow endpoint reports ONLY the default GITHUB_TOKEN permission (read vs write) and whether Actions may create/approve PRs. It does NOT report whether fork PRs receive write tokens or secrets. That effective fork-PR exposure comes from the dedicated endpoints: actions/permissions/fork-pr-contributor-approval (the approval gate) and, for private repositories, actions/permissions/fork-pr-workflows-private-repos (token/secret exposure). This is what decides whether a plain pull_request is really read-only.
