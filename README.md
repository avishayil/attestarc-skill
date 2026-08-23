# AttestArc

Security expertise for your coding agent.

Install AttestArc into Claude Code or Cursor and run:

    /attestarc

AttestArc discovers how the current repository is built and delivered, finds
security issues that matter, and guides you through fixing them.

No dashboard.
No scanner service.
No compliance report.

It works inside the repository, with the coding agent you already use.

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

From a clone of this repository:

```bash
# Current project — serves BOTH Claude Code and Cursor
python install.py

# Global (available in every repo you open), still both clients
python install.py --scope user

# Install into a specific repository
python install.py --scope project --target /path/to/project
```

A single install to `.claude/skills/attestarc/` is discovered by **both** Claude
Code and Cursor (Cursor also scans `.claude/skills/`). Use `--platform cursor`
only if you specifically want a separate `.cursor/skills/attestarc/` copy, or
`--platform both` for both locations.

Uninstall mirrors the same flags:

```bash
python uninstall.py --scope user
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

See [`SPECIFICATION.md`](SPECIFICATION.md) for the normative specification and
`CLAUDE.md` for development rules.

## License

MIT — see [LICENSE](LICENSE).
