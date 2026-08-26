---
attestarc:
  applies_to:
    events:
      - "pull_request_target"
      - "workflow_run"
      - "issue_comment"
      - "repository_dispatch"
    product: "github.com"
  confidence: "authoritative"
  effect: "risk-increasing"
  id: "KE-gha-privileged-trigger-context"
  last_verified: "2026-08-24"
  platform: "github-actions"
  sources:
    -
      authority: 100
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-docs"
      url: "https://docs.github.com/actions/using-workflows/events-that-trigger-workflows"
  status: "active"
  subject: "privileged-triggers"
  valid_from: "2023-01-01"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/actions/using-workflows/events-that-trigger-workflows"
status: "stable"
tags:
  - "github-actions"
  - "privileged-triggers"
title: "privileged-triggers"
type: "platform-semantics"
---
pull_request_target, workflow_run, issue_comment, and repository_dispatch run in the context of the base repository: they can carry secrets and a writable GITHUB_TOKEN, yet are triggered by potentially untrusted actors. pull_request (from a fork) does not, by default.
