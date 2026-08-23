# AttestArc evals

These are **behavioral evaluations of the agent** — the reasoning AttestArc
performs when a host (Claude Code, Cursor) loads `SKILL.md`. They are distinct
from `tests/`, which verify the deterministic helper *code* (`scripts/`) with
`pytest`.

- `tests/`  → "does the deterministic code work?" (unit tests, run with pytest)
- `evals/`  → "does the *agent* behave well?" (judgment, run interactively)

There is deliberately **no eval-runner engine** in V1. An automated harness that
scored the agent would drift AttestArc toward a standalone product; that is a
non-goal (see `SPECIFICATION.md` §Non-goals and the north star). Each case is a
structured specification you run interactively against the host, then judge
against the rubric below.

## How to run a case

1. Install the skill (`python install.py`) or point the host at this repo.
2. If the case names a `fixture`, open that fixture repo as the working
   repository (the paths are under `tests/fixtures/`).
3. Issue the case's `command` / `prompt` to the host.
4. Judge the transcript against the case's `expect` / `prohibit` lists and the
   rubric.

## Rubric

A good AttestArc run:

1. **Discovers evidence** before drawing conclusions (runs discovery, reads the
   relevant files/workflows).
2. **Investigates before declaring** — reasons about exploitability rather than
   pattern-matching.
3. **Distinguishes observation from vulnerability** — a fact is not a finding.
4. **Avoids false positives** — stays quiet on secure repositories.
5. **Prioritizes by real impact** — correlates an attack path into one finding;
   shows a small, actionable set, not an exhaustive checklist.
6. **Proposes repository-specific remediation** — fits the existing patterns.
7. **Preserves findings state** — stable ids, evidence, no duplicates, human
   decisions (accepted_risk / false_positive / resolved) not silently reopened.
8. **Recognizes a fix** — verifies by re-observation before marking `resolved`;
   never persists a secret value.

## Case format

Each file in `cases/` is a YAML document:

```yaml
name: short-kebab-case-id
description: one line
fixture: tests/fixtures/<name>        # optional; the working repo for the case
command: /attestarc [args]            # what the user runs
prompt: >                             # natural-language ask (may equal command)
  ...
expect:                               # behaviors that MUST occur
  - ...
prohibit:                             # behaviors that MUST NOT occur
  - ...
notes: >                              # optional guidance for the judge
  ...
```

Cases are documentation-grade specs; keep them aligned with `SPECIFICATION.md`.
