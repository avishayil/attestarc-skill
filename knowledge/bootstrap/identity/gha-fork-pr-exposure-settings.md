---
attestarc:
  applies_to:
    events:
      - "pull_request"
    product: "github.com"
  confidence: "authoritative"
  id: "KE-gha-fork-pr-exposure-settings"
  last_verified: "2026-08-24"
  platform: "github"
  sources:
    -
      authority: 100
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-docs"
      url: "https://docs.github.com/actions/security-guides/security-hardening-for-github-actions"
  status: "active"
  subject: "fork-pr-settings"
  valid_from: "2024-01-01"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/actions/security-guides/security-hardening-for-github-actions"
status: "stable"
tags:
  - "github"
  - "fork-pr-settings"
title: "fork-pr-settings"
type: "platform-semantics"
---
Repository/org/enterprise settings can change the effective fork pull_request token/secret exposure away from the read-only/no-secrets default, especially on private repositories, via settings including: run_workflows_from_fork_pull_requests, send_write_tokens_to_workflows, send_secrets_and_variables, and require_approval_for_fork_pr_workflows. When granted, a plain fork pull_request can carry the READ_SECRET/WRITE_REPOSITORY capability otherwise attributed only to pull_request_target. These settings are not visible in the workflow file.
