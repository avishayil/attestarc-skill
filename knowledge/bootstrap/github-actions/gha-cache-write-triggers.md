---
attestarc:
  applies_to:
    events:
      - "pull_request_target"
      - "issue_comment"
      - "workflow_run"
      - "pull_request"
      - "push"
      - "workflow_dispatch"
      - "repository_dispatch"
      - "delete"
      - "registry_package"
      - "page_build"
      - "schedule"
    product: "github.com"
  claim_key: "gha.cache.write_scope_default"
  confidence: "authoritative"
  effect: "mitigation"
  id: "KE-gha-cache-write-triggers"
  last_verified: "2026-08-24"
  platform: "github-actions"
  sources:
    -
      authority: 100
      publisher: "GitHub"
      retrieved_at: "2026-08-24"
      type: "vendor-docs"
      url: "https://docs.github.com/actions/using-workflows/caching-dependencies-to-speed-up-workflows"
  status: "active"
  subject: "cache-write"
  valid_from: "2026-06-26"
sources:
  -
    author: "GitHub"
    resource: "https://docs.github.com/actions/using-workflows/caching-dependencies-to-speed-up-workflows"
status: "stable"
tags:
  - "github-actions"
  - "cache-write"
title: "cache-write"
type: "platform-semantics"
---
Actions cache entries are scoped to the git ref that created them; a run restores from its own ref with fallback to the default branch (and, for a PR, its base branch). Only push, workflow_dispatch, repository_dispatch, delete, registry_package, page_build, and schedule write the default-branch cache scope. The low-trust triggers pull_request_target, issue_comment, and workflow_run get READ-ONLY cache access and cannot create or overwrite any cache entry. A fork pull_request is confined to its own PR merge-ref scope, from which a later default/protected-branch run does not restore.
