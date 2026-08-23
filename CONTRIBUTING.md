# Contributing to AttestArc

Thanks for your interest in improving AttestArc. This document explains how the
project is structured, how to develop against it, and what a good contribution
looks like.

## What AttestArc is (and is not)

AttestArc is an installable **Agent Skill**, not a standalone security product.
The repository root *is* the skill package. The host coding agent (Claude Code)
provides the reasoning and orchestration; this repository provides the
methodology, expertise, deterministic helpers, and persistent findings contract.

Please read [`CLAUDE.md`](CLAUDE.md) and [`SPECIFICATION.md`](SPECIFICATION.md)
before making non-trivial changes. `SPECIFICATION.md` is the normative north
star: if you change behavior, the findings schema, script contracts, scope, or
conformance criteria, update it in the same change set.

Core conventions:

- **Scripts emit facts, not verdicts.** Helpers return structured observations;
  the host agent decides what they mean. Don't build a scanner engine.
- **Helpers are stdlib-only.** No third-party runtime dependencies.
- **References teach investigation, not signature lists.** They teach how to
  reason about an attack class, not a checklist to match.
- **Never crash the host.** On unparseable input, degrade gracefully (e.g.
  `parse_partial: true` plus a raw excerpt) and exit cleanly.
- **Secret values are never persisted** to `findings.json`.

## Development setup

You need **Python 3.9+** (standard library only) and **git**. The test suite
uses `pytest`:

```bash
python -m pytest        # must pass with only the standard library + pytest
```

The suite covers the deterministic helper code (`scripts/`) against fixture
repositories under `tests/fixtures/`. Behavioral evaluations of the *agent* live
in [`evals/`](evals/README.md); they are structured, judged specs run
interactively — there is no eval-runner engine.

## Making a change

1. Keep it simple. If an implementation starts growing, ask whether it needs to
   exist because AttestArc is a *skill*, or whether it's drifting toward a
   standalone product. If the latter, simplify.
2. Match the surrounding style; keep helpers deterministic and side-effect-free
   during assessment (assessment is read-only).
3. Add or update tests for any helper behavior change, and add both **find** and
   **refuse-false-positive** eval coverage when you change reasoning guidance.
4. Update `SPECIFICATION.md` and `CHANGELOG.md` when behavior or contracts
   change.
5. Run `python -m pytest` and confirm it is green.

## Pull requests

- Describe the change and its motivation, and note how it aligns with
  `SPECIFICATION.md`.
- Confirm the test suite passes and mention any eval cases you added.
- Keep commits focused. Signed commits are appreciated.

## Reporting security issues

Do **not** open a public issue for a vulnerability. See
[`SECURITY.md`](SECURITY.md) for the private reporting process.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
