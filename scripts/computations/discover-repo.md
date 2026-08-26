---
attestarc:
  emits: "facts"
  entrypoint: "scripts/discover_repo.py"
  executes_repo_code: false
  id: "AC-discover-repo"
  network: false
  parameters:
    -
      default: "."
      description: "repository root to scan (read-only)"
      flag: "--root"
      name: "root"
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
      detected: "object"
      git: "object"
      notes: "array"
    required_keys:
      - "detected"
      - "git"
      - "notes"
  runtime: "python3"
  spec_ref: "SPECIFICATION.md §12.2"
title: "discover_repo — read-only repository fact discovery"
type: "Attested Computation"
---
`discover_repo.py` walks a repository **read-only** and emits structured
*facts* about it — git status and a credential-redacted remote, and a `detected`
map of SCM, CI systems, languages, package managers, containers, IaC, security
files, and the root vs non-root workflow files. It never executes repository code,
never reaches the network, and asserts **no** security verdict; the Host decides
what the facts mean (SPECIFICATION.md §2.6, §12.2).

Modeled here as an OKF *Attested Computation* so the shape of its fact receipt is
described as data. The `attestarc.receipt` block is the **structural** contract the
`attester` checks: the receipt must be an object carrying `git`, `detected`, and
`notes`, and MUST NOT carry any verdict-shaped key (`verdict`, `finding`,
`severity`, …). The attester validates structure only — it is never a security
judgment, and running the computation stays the Host's job.
