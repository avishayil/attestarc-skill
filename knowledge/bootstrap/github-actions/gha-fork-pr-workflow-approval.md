---
attestarc:
  applies_to:
    events:
      - "pull_request"
    product: "github.com"
  confidence: "authoritative"
  effect: "mitigation"
  id: "KE-gha-fork-pr-workflow-approval"
  last_verified: "2026-08-24"
  platform: "github-actions"
  sources:
    -
      authority: 100
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-docs"
      url: "https://docs.github.com/actions/managing-workflow-runs/approving-workflow-runs-from-public-forks"
  status: "active"
  subject: "fork-pr-workflow-approval"
  valid_from: "2023-01-01"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/actions/managing-workflow-runs/approving-workflow-runs-from-public-forks"
status: "stable"
tags:
  - "github-actions"
  - "fork-pr-workflow-approval"
title: "fork-pr-workflow-approval"
type: "platform-semantics"
---
The 'require approval for fork pull request workflows' setting (options: first-time contributors, all outside collaborators, or all fork pull requests; API field require_approval_for_fork_pr_workflows) gates whether a workflow triggered by a fork pull_request runs at all. An approval-gated fork pull_request is not attacker-reachable without a maintainer approving the run; the approval is a real gate but is a human decision and can be socially engineered.
