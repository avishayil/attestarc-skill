---
attestarc:
  applies_to:
    action: "actions/checkout"
    events:
      - "pull_request_target"
      - "workflow_run"
    product: "github.com"
  claim_key: "gha.checkout.fork_pr_ref_default"
  confidence: "authoritative"
  effect: "mitigation"
  id: "KE-gha-checkout-forkpr-refusal"
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
  subject: "pull_request_target"
  valid_from: "2026-06-18"
sources:
  -
    author: "GitHub"
    resource: "https://github.com/actions/checkout"
status: "stable"
tags:
  - "github-actions"
  - "pull_request_target"
title: "pull_request_target"
type: "platform-semantics"
---
Modern actions/checkout refuses to check out fork-PR code under pull_request_target and workflow_run unless the step sets 'with: allow-unsafe-pr-checkout: true'. Versions predating this guard do not refuse. The refusal is specific to actions/checkout: untrusted code can still enter a privileged job via git fetch/curl of the PR ref, another action, or a composite/local step.
