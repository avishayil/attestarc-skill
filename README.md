# AttestArc

Security expertise for your coding agent.

[![CI](https://github.com/avishayil/attestarc-skill/actions/workflows/ci.yml/badge.svg)](https://github.com/avishayil/attestarc-skill/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Getting started](https://img.shields.io/badge/docs-getting%20started-22C55E.svg)](https://avishayil.github.io/attestarc-skill/)

Install AttestArc into Claude Code (or wire it into Cursor) and run:

    /attestarc

AttestArc discovers how the current repository is built and delivered, finds
security issues that matter, and guides you through fixing them.

No dashboard.
No scanner service.
No compliance report.

It works inside the repository, with the coding agent you already use.

**New here?** Start with the [getting-started site](https://avishayil.github.io/attestarc-skill/).

---

## What it is

AttestArc is an installable [Agent Skill](https://code.claude.com/docs/en/skills)
for software supply-chain security. It is **not** a standalone scanner — it has
no LLM runtime, server, database, or UI of its own. Instead it teaches the host
coding agent (Claude Code, Cursor) *what to inspect, what matters, how to record
findings, and how to safely remediate them.*

The principle:

> **The engineer provides the repository. AttestArc provides the security methodology.**

## Install

### Prerequisites

- **Python 3.8+** (standard library only — no third-party packages) and **git**.
- **GitHub CLI (`gh`)** — optional, recommended for read-only remote checks
  (branch protection, rulesets, Actions policy).

### Claude Code (recommended)

AttestArc is a native Claude Agent Skill: Claude Code automatically discovers
skills under `.claude/skills/`. The simplest install is a clone:

```bash
# Global — available in every repository you open
git clone https://github.com/avishayil/attestarc-skill.git ~/.claude/skills/attestarc

# Or per-project — scoped to one repository
git clone https://github.com/avishayil/attestarc-skill.git .claude/skills/attestarc
```

Prefer to copy only the skill payload (leaving development files behind)? Use the
installer:

```bash
git clone https://github.com/avishayil/attestarc-skill.git
cd attestarc-skill

python install.py                                  # current project → .claude/skills/attestarc/
python install.py --scope user                     # global → ~/.claude/skills/attestarc/
python install.py --scope project --target /path/to/project
```

Then, in Claude Code, run `/attestarc`.

### Cursor

Cursor does **not** have a native Skills system — it uses project **rules**
(`.cursor/rules/*.mdc`) and `AGENTS.md`, and it does not auto-discover
`.claude/skills/`. You can still use AttestArc in Cursor by cloning the skill and
pointing a rule at it:

```bash
git clone https://github.com/avishayil/attestarc-skill.git .cursor/attestarc
```

Create `.cursor/rules/attestarc.mdc`:

```mdc
---
description: AttestArc — software supply-chain security assessment and remediation
alwaysApply: false
---
When asked to assess, harden, review, or remediate repository / CI-CD /
GitHub Actions / dependency / secrets / supply-chain security, act as the
security engineer described in `.cursor/attestarc/SKILL.md`. Follow its
lifecycle, and load the files under `.cursor/attestarc/references/` on demand.
```

Then ask Cursor's agent to *"assess this repository's supply-chain security with
AttestArc"* (or `@`-mention the rule).

### Uninstall

```bash
python uninstall.py                # current project
python uninstall.py --scope user   # global
```

Installation only copies the skill payload (`SKILL.md`, `references/`,
`scripts/`, `assets/`, `LICENSE`, `README.md`) into the host's skills directory.
Development files (`tests/`, `evals/`, the installer) are not shipped, and
unrelated host configuration is never modified.

## Usage

Once installed, in your coding agent:

```text
/attestarc                  Full relevant assessment of the repository
/attestarc findings         Show unresolved findings, most important first
/attestarc fix <id>         Reconfirm, remediate, and verify a finding
/attestarc verify           Re-check open/remediating findings
/attestarc changed          Review the security impact of current changes
/attestarc github-actions   Focus on GitHub Actions
/attestarc repository       Focus on repository / SCM controls
/attestarc supply-chain     Focus on release, artifacts, provenance, identity
```

AttestArc also loads automatically for clearly relevant requests such as
"harden this repo", "review the GitHub Actions", or "is our release process
secure?".

## What it looks for (V1)

- **GitHub repository controls** — branch protection, rulesets, CODEOWNERS,
  review requirements, signed commits, protected tags.
- **GitHub Actions** — dangerous trigger combinations, token permissions,
  mutable Action references, untrusted input, runners, OIDC, environments.
- **Dependencies** — update tooling, lock files, dependency review, registries.
- **Identity & secrets** — static credentials, workload identity, secret scope.
- **Supply chain** — build integrity, artifact identity, signing, provenance.
- **Changed files** — the security impact of the diff you're working on.

Fully supported in V1: **GitHub** + **GitHub Actions**. Other CI systems
(GitLab CI, CircleCI, Jenkins, …) are detected and reviewed with a generic
methodology at lower confidence.

## Runtime footprint

AttestArc keeps a single local working file in the repositories it assesses:

```text
.attestarc/findings.json
```

This is its structured memory — it lets the agent remember findings across
sessions, avoid duplicates, and know what was already remediated. AttestArc
adds `.attestarc/` to `.git/info/exclude` rather than editing your tracked
`.gitignore`, so no unrelated repository change is generated.

Secret values are **never** written to `findings.json`.

## Development

**The repository root is the skill package.** Its layers:

```text
SKILL.md      how AttestArc thinks and operates   (reasoning)
references/   what AttestArc knows                (expertise)
scripts/      what it can measure deterministically (facts)
assets/       contracts and structured resources  (schemas)
evals/        how we know the agent is good       (behavioral evals)
tests/        proof the deterministic code works  (pytest)
```

Helper scripts are stdlib-only deterministic utilities (no third-party
dependencies) that emit *facts*, not security verdicts — the host agent decides
what the facts mean.

```bash
python -m pytest        # deterministic code tests (no dependencies required)
```

`evals/` holds interactive behavioral evaluations of the *agent* (see
[`evals/README.md`](evals/README.md)); they are judged, not run by pytest.

See [`SPECIFICATION.md`](SPECIFICATION.md) for the normative specification,
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how to contribute, and `CLAUDE.md` for
development rules. Security issues: see [`SECURITY.md`](SECURITY.md). Release
history: [`CHANGELOG.md`](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).
