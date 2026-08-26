---
attestarc:
  applies_to:
    events:
      - "pull_request"
    product: "github.com"
  claim_key: "gha.pull_request_target.fork_token_default"
  confidence: "authoritative"
  effect: "mitigation"
  id: "KE-gha-forkpr-token-default"
  last_verified: "2026-08-24"
  platform: "github-actions"
  sources:
    -
      authority: 100
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-docs"
      url: "https://docs.github.com/actions/security-guides/automatic-token-authentication"
  status: "active"
  subject: "fork-pr-permissions"
  valid_from: "2023-01-01"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/actions/security-guides/automatic-token-authentication"
status: "stable"
tags:
  - "github-actions"
  - "fork-pr-permissions"
title: "fork-pr-permissions"
type: "platform-semantics"
---
A workflow triggered by pull_request from a fork runs with a read-only GITHUB_TOKEN and no access to secrets by default. This is the platform DEFAULT, not a constant: the repository/org Actions settings 'Send write tokens to workflows from fork pull requests' and 'Send secrets to workflows from fork pull requests' can widen it, and those settings are not visible in the workflow file.
