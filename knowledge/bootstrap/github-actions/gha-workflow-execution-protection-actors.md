---
attestarc:
  applies_to:
    product: "github.com"
  claim_key: "gha.workflow_execution_protection.actor_rules"
  confidence: "authoritative"
  effect: "mitigation"
  id: "KE-gha-workflow-execution-protection-actors"
  last_verified: "2026-08-24"
  platform: "github-actions"
  sources:
    -
      authority: 100
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-docs"
      url: "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/actions-policies/workflow-execution-protections"
    -
      authority: 95
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-changelog"
      url: "https://github.blog/changelog/2026-06-18-control-who-and-what-triggers-github-actions-workflows/"
  status: "active"
  subject: "workflow-execution-protection-actors"
  valid_from: "2026-06-18"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/actions-policies/workflow-execution-protections"
  -
    author: "GitHub"
    resource: "https://github.blog/changelog/2026-06-18-control-who-and-what-triggers-github-actions-workflows/"
status: "stable"
tags:
  - "github-actions"
  - "workflow-execution-protection-actors"
title: "workflow-execution-protection-actors"
type: "platform-semantics"
---
Workflow Execution Protections (GitHub; Public Preview announced 2026-06-18, rulesets-backed at enterprise/org/repo level, subject to change) can enforce an allow list of ACTORS permitted to trigger GitHub Actions workflows. Actor rules can target individual users, repository roles (Read/Maintain/Admin), GitHub Apps, Copilot, and Dependabot. When a rule is ACTIVE (enforced) GitHub evaluates it BEFORE workflow execution and a disallowed actor does not start the workflow; a ruleset in EVALUATE mode only observes what would be blocked and does NOT enforce. This down-gates reachability ONLY when an enforced rule is observed to target this repository AND match the assessed execution — the policy's mere existence does not.
