---
attestarc:
  applies_to:
    product: "github.com"
  confidence: "authoritative"
  effect: "mitigation"
  id: "KE-gha-potentially-malicious-workflow-hold"
  last_verified: "2026-08-24"
  platform: "github-actions"
  sources:
    -
      authority: 95
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-changelog"
      url: "https://github.blog/changelog/2026-07-28-github-actions-holds-potentially-malicious-workflows-for-approval/"
  status: "active"
  subject: "potentially-malicious-workflow-hold"
  valid_from: "2026-07-28"
sources:
  -
    author: "GitHub"
    resource: "https://github.blog/changelog/2026-07-28-github-actions-holds-potentially-malicious-workflows-for-approval/"
status: "stable"
tags:
  - "github-actions"
  - "potentially-malicious-workflow-hold"
title: "potentially-malicious-workflow-hold"
type: "platform-semantics"
---
For public repositories on github.com, GitHub Actions automatically holds certain workflow runs it identifies as potentially malicious BEFORE execution; a held run does not execute until a repository collaborator with write access reviews and approves it through an authenticated web session. GitHub applies this automatically with no administrator configuration, and it is NOT currently provided by GitHub Enterprise Server. The public documentation does NOT specify deterministic criteria for which runs are classified potentially malicious. Because the detection is opaque, this is defense-in-depth ONLY: it MUST NOT statically down-gate an otherwise-reachable attack path — treat the path as reachable unless the specific run is OBSERVED to have been held.
