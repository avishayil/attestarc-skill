# Severity and confidence

Use qualitative levels only. Never numeric security scores, and never inflate
severity because a control appears in a standard.

## Severity

Judge by the credible real-world impact **in this repository**, given who can
reach the weakness and what it grants. Severity is a function of two things you
should already have from the reasoning grammar (`core/methodology.md`):

- **Reachability** — where the issue sits on the `present → reachable →
  exploitable → impactful` ladder, and by which actor (`direct`, `conditional`,
  `trusted-only`, `unknown`). A `present`-only pattern is not yet a real risk.
- **Capability / asset** — what the reached capability grants and which asset it
  affects (source, secrets, identity, artifact, production).

An issue that is only `present`, or reachable `trusted-only`, is rated lower
than the same issue reachable `direct` by any fork. If reachability is
`unknown` because you could not verify a transition, prefer `needs_review` with
`evidence_gaps` over a confident high/critical.

**critical** — a credible path exists to one of:
- production compromise;
- privileged identity compromise (cloud role, deploy credential);
- artifact / release compromise;
- arbitrary code execution in a privileged CI context;
- an equivalent high-impact trust-boundary violation.

Example: a fork PR can cause code to run with a production-capable OIDC identity.

**high** — a meaningful control weakness giving substantial attacker leverage,
but additional conditions are required to reach full impact.

Example: a release workflow uses a mutable third-party Action reference; the
maintainer's tag could be moved to malicious code, but that requires compromising
or coercing the third party.

**medium** — an important hardening or defense-in-depth weakness.

Example: workflow changes do not require CODEOWNER review; Dependabot is absent.

**low** — limited-impact security hygiene.

Example: SECURITY.md is missing; a non-privileged workflow lacks an explicit
top-level `permissions: read` block.

## Confidence

**high** — direct configuration/file/API evidence you observed.

**medium** — strong inference from multiple observations, not a single direct
fact.

**low** — heuristic suspicion requiring confirmation. Low-confidence
observations should normally be recorded as `status: needs_review` rather than
asserted as definite findings.

## Calibration reminders

- Severity is about impact and reachability, confidence is about certainty of
  the evidence — keep them independent.
- A dangerous pattern reachable only by trusted maintainers is usually lower
  severity than the same pattern reachable by any fork.
- When two findings form one attack path, rate the correlated finding by the
  path's end-to-end impact.
- A single observed fact whose attack chain does not close is not a finding at
  full severity — down-rate it or record `needs_review`. `id-token: write` on a
  release that only runs from a protected tag is not, by itself, critical.
