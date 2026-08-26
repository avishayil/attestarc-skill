---
attestarc:
  emits: "facts"
  entrypoint: "scripts/inspect_git_diff.py"
  executes_repo_code: false
  id: "AC-inspect-git-diff"
  network: false
  parameters:
    -
      default: "."
      description: "repository root (default: .)"
      flag: "--root"
      name: "root"
      required: false
    -
      default: null
      description: "base revision (default: HEAD for a working-tree compare)"
      flag: "--base"
      name: "base"
      required: false
    -
      default: null
      description: "head revision (default: the working tree)"
      flag: "--head"
      name: "head"
      required: false
    -
      default: false
      description: "compare the staged index against HEAD (boolean flag)"
      flag: "--staged"
      name: "staged"
      required: false
  read_only: true
  receipt:
    forbidden_keys:
      - "conclusion"
      - "finding"
      - "findings"
      - "remediation"
      - "severity"
      - "verdict"
      - "verdicts"
    key_types:
      changed_files: "array"
      git: "object"
      notes: "array"
      workflow_changes: "array"
    required_keys:
      - "changed_files"
      - "git"
      - "notes"
      - "workflow_changes"
  runtime: "python3"
  spec_ref: "SPECIFICATION.md §12.4"
title: "inspect_git_diff — security-relevant change facts from git diff"
type: "Attested Computation"
---
`inspect_git_diff.py` computes security-relevant *change* facts from a
read-only `git diff` (working tree vs HEAD by default; staged and revision-range
options). For each changed **root** `.github/workflows/` file it emits the
before/after permission/trigger snapshots and a `security_delta` of capability
gains (permissions, new privileged triggers, new self-hosted runners, newly-mutable
action/reusable refs, newly-inherited secrets, new environments, new cache use, new
download-and-execute steps, removed job `if:` guards, …). Facts, not findings;
`parse_partial` propagates so an empty delta on an unparsed workflow is not read as
"safe" (SPECIFICATION.md §12.4).

Modeled as an OKF *Attested Computation*. The receipt is an object carrying `git`,
`changed_files`, `workflow_changes`, and `notes`. The `attester` validates that
structure and refuses verdict-shaped keys; the exploitability judgment is the
Host's.
