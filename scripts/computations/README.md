# Attested-Computation concepts

This tree models AttestArc's deterministic, fact-emitting kernel helpers —
`discover_repo.py`, `inspect_workflows.py`, `inspect_git_diff.py` — as OKF
**Attested Computation** concepts (`*.md`), plus a structural `attester.py`.

It is a **different trust zone** from the verified-knowledge plane:

- These concepts describe **kernel scripts**, so they are **root-of-trust** and
  two-party reviewed (SPECIFICATION.md §24.2, THREAT_MODEL.md §6). They are **not**
  knowledge-attested as volatile facts and **must not** live under
  `knowledge/bootstrap/`.
- The on-disk shape is documented by `schemas/okf-computation.schema.json`. Each
  concept keeps everything trust-relevant under the `attestarc:` namespace; native
  OKF fields (`type`, `title`) are advisory.
- The load-bearing invariant is `emits: facts`. `attester.py` is a **structural
  receipt validator only** — it checks that a receipt a helper emitted has the
  declared shape and carries no verdict-shaped key. It **never** emits a security
  verdict and **never** runs a helper (SPECIFICATION.md §2.6, §12.5, §17).

```bash
# structural self-check over every concept in this tree
python scripts/computations/attester.py verify-concepts

# validate a receipt a helper emitted (facts, never a verdict)
python scripts/discover_repo.py --root . \
  | python scripts/computations/attester.py check scripts/computations/discover-repo.md -
```
