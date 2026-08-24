# Prompt: generate paired evals for a candidate

You are the **Evolver**. Given a `LearningCandidate`, produce an **additive** set
of behavioral eval cases (`evals/cases/<name>.yaml`) that would catch the gap the
candidate addresses *and* guard against over-correction. Match the existing case
format (see `evals/cases/*.yaml`): `name`, `description`, `command`, `prompt`,
`expect`, `prohibit`, `notes`.

## The pairing rule (non-negotiable)

Every behavior you teach must come with the case that stops it from becoming a
false positive. At minimum produce a **pair**:

- a **find** case — the situation where the chain genuinely closes and AttestArc
  MUST report it;
- a **refuse** case — the sibling situation that looks similar but does NOT close
  (the discriminating fact is explicit in `notes`).

Add, where the reasoning is conditional:

- a **needs-review** case — evidence is missing or a source is disputed/candidate,
  so the correct behavior is to route to `needs_review`, not to conclude;
- a **historical** case — the answer depends on a date/version (use `--as-of` or a
  version-scoped fixture), so AttestArc must reason temporally rather than apply
  today's fact to a past state.

## Hard rules

- **Additive only.** Never weaken, loosen, or delete an existing trusted eval.
  Doing so is two-party review and is out of scope for candidate generation.
- Make the `prohibit` list concrete — name the specific wrong conclusion the pair
  is designed to prevent.
- In `notes`, state the single discriminating fact that flips find ↔ refuse, and
  point at the reference/knowledge entry the case exercises.
- No secrets or private repository content in any fixture or prompt.

Output the eval case YAML documents, one per file, each preceded by its target
path.
