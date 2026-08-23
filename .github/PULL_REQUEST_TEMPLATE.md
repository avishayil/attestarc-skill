<!--
Thanks for contributing to AttestArc. Please keep changes focused and aligned
with SPECIFICATION.md. See CONTRIBUTING.md for conventions.
-->

## Summary

<!-- What does this change do, and why? -->

## Type of change

- [ ] Reasoning / references (methodology, threats, domain expertise)
- [ ] Deterministic helper (facts only — stdlib, no verdicts)
- [ ] Findings schema / state contract
- [ ] Installer / packaging
- [ ] Documentation / getting-started site
- [ ] Other

## Checklist

- [ ] Aligned with [`SPECIFICATION.md`](../SPECIFICATION.md); updated it in this
      change set if behavior, schema, script contracts, scope, or conformance
      changed.
- [ ] Helpers stay **stdlib-only** and emit **facts, not verdicts**; assessment
      remains read-only.
- [ ] No secret values are ever written to `findings.json`.
- [ ] `python -m pytest` passes locally.
- [ ] Added/updated tests for helper changes.
- [ ] Added/updated **find** and **refuse-false-positive** eval coverage for
      reasoning changes (if applicable).
- [ ] Updated [`CHANGELOG.md`](../CHANGELOG.md) if user-visible behavior changed.

## Dogfood note

<!--
If this touches the skill's own security posture (workflows, permissions,
release), note the result of running AttestArc on this repository.
-->
