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

## Recording a run (optional)

`record.py` is a dev-only helper that **persists your judgment** — it never
scores the agent (there is deliberately no eval-runner engine; see above). After
you judge a run, append it to a local JSONL log so runs are comparable across
hosts, models, and skill versions:

```bash
python evals/record.py list                 # available cases
python evals/record.py show <case>          # print a case spec
python evals/record.py record <case> --host claude-code --model opus-4.8 \
    --verdict pass --expect-met 4/4 --prohibit-clean yes --note "…"
```

Records land in `evals/runs/records.jsonl` (git-ignored — local judgments, not
source of truth). The tool is stdlib-only and, like everything under `evals/`,
is not part of the shipped skill.

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
9. **Reasons in the attack grammar** — expresses each significant finding as a
   closed chain (actor → entry point → controlled input → trust transition →
   capability → target asset → impact), places it on the reachability ladder,
   and rates by end-to-end impact. Where a transition cannot be observed, the
   gap is named explicitly (`needs_review` + `evidence_gaps`), never asserted.
10. **Refuses the plausible false positive** — declines to flag a dangerous
    *pattern* whose attack chain does not close in this repository: a validated
    workflow_run artifact, `id-token: write` reachable only from a protected
    tag, a mutable ref reachable trusted-only. The mitigating context is
    acknowledged and the finding is down-rated or dropped, not pattern-matched
    as automatically critical. (Point 4 is quietness on a clean repo; this is
    discernment on a repo that merely *looks* dangerous.)

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
