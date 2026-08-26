---
attestarc:
  applies_to:
    product: "github.com"
  confidence: "authoritative"
  id: "KE-ghapi-readonly-observation-endpoints"
  last_verified: "2026-08-24"
  platform: "github"
  sources:
    -
      authority: 100
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-docs"
      url: "https://docs.github.com/rest"
  status: "active"
  subject: "remote-state-endpoints"
  valid_from: "2024-01-01"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/rest"
status: "stable"
tags:
  - "github"
  - "remote-state-endpoints"
title: "remote-state-endpoints"
type: "api"
---
Read-only REST endpoints for observing server-side SCM controls: repos/{o}/{r} (visibility, default branch); .../branches and .../tags (enumerate consumable refs); .../rulesets and .../branches/{b}/protection (protection rules and targets); .../actions/permissions (Actions policy, allowed_actions); .../actions/permissions/workflow (default GITHUB_TOKEN perms, may workflows approve PRs); .../actions/permissions/fork-pr-contributor-approval (approval gate before fork PRs run); .../actions/permissions/fork-pr-workflows-private-repos (fork-PR token/secret exposure on private repos); .../environments.
