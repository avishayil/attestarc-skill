# Security policy

AttestArc is a security tool, so we take the security of this repository
seriously.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via GitHub Security Advisories
(the **Security → Report a vulnerability** tab of this repository) rather than
opening a public issue. Include enough detail to reproduce the problem.

We aim to acknowledge reports within a few business days.

## Supported versions

AttestArc is distributed as a versioned Agent Skill (`metadata.version` in
`SKILL.md`). Security fixes are applied to the latest released version; there are
no long-term support branches. Please upgrade to the latest release before
reporting, and include the version you observed the issue on.

| Version | Supported          |
|---------|--------------------|
| Latest release (`0.2.x`) | :white_check_mark: |
| Older   | :x:                |

## Scope

This project is an installable Agent Skill: `SKILL.md`, `references/`, stdlib-only
helper `scripts/`, and `assets/`. Security-relevant concerns include, for
example:

- A helper script mishandling untrusted repository content (see the
  untrusted-data invariant in `SKILL.md` and `SPECIFICATION.md`).
- A path where a secret value could be persisted to `.attestarc/findings.json`.
- The installer writing outside the intended skills directory.

Findings state (`.attestarc/findings.json`) is created in the repositories you
assess, never in this repository.
