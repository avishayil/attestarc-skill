---
attestarc:
  emits: "facts"
  entrypoint: "scripts/inspect_workflows.py"
  executes_repo_code: false
  id: "AC-inspect-workflows"
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
      description: "workflow files (positional; default: all under the root .github/workflows/)"
      flag: ""
      name: "paths"
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
      workflows: "array"
    required_keys:
      - "workflows"
  runtime: "python3"
  spec_ref: "SPECIFICATION.md §12.3"
title: "inspect_workflows — GitHub Actions workflow fact extraction"
type: "Attested Computation"
---
`inspect_workflows.py` parses GitHub Actions workflow YAML with a
dependency-free, safe parser and emits normalized per-workflow *facts*: triggers
and their qualifiers, workflow- and job-level permissions, runner/self-hosted and
environment facts, action references with pinning/`ref_kind`, reusable-workflow
`uses`/`secrets`, cache use, per-job reachability (`if`/`needs`/`strategy`/
`continue_on_error`), `run_steps[]`, and `checkout_refs[]`. On ambiguous input it
sets `parse_partial: true` rather than raising, and it emits **no** security
verdict (SPECIFICATION.md §12.3).

Modeled as an OKF *Attested Computation*. The CLI receipt is an object with a
single `workflows` array (one entry per inspected file). The `attester` checks that
structure and refuses any verdict-shaped key; whether a `fetch_execute`, inherited
secret, mutable ref, or restored cache *matters* stays the Host's judgment.
