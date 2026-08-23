# Remediation

Read this before changing anything. Remediation is part of the product: the goal
is *understand → fix → verify*, not *scan → report*.

## Workflow

```
Finding → Reconfirm → Understand existing pattern → Choose least-disruptive
secure fix → Explain → Apply when authorized → Verify → Resolve
```

1. **Reconfirm** the finding still exists (re-read the file/setting or re-run the
   helper). Repositories change between sessions; never fix a stale finding.
2. **Understand the existing pattern** so the fix matches local conventions and
   does not break the build.
3. **Choose the least-disruptive secure fix.** Prefer the smallest change that
   removes the risky condition.
4. **Explain** current state, proposed change, and likely engineering impact.
5. **Apply** by editing the working tree, once you have user intent/authorization
   (`fix <id>` or an explicit request is authorization for local edits).
6. **Verify** by re-observing the condition.
7. **Resolve** via `scripts/state.py resolve <id>` with what you observed.

Do **not** `git commit` or `git push` unless the user explicitly asks. Set the
finding to `remediating` while working:
`python scripts/state.py set-status <id> remediating`.

## Local (working-tree) remediations

Safe to implement on request: reducing Action `permissions`, SHA-pinning
Actions, adding/adjusting `.github/dependabot.yml`, adding CODEOWNERS, hardening
a workflow trigger, converting unsafe expression interpolation to env-var
passthrough, scoping to an environment, adding SECURITY.md.

**Pinning an Action — never invent a SHA.** Resolve the SHA the intended version
points to, review it, then pin, keeping the version in a comment:

```bash
git ls-remote https://github.com/docker/login-action v3      # or: gh api ...
# uses: docker/login-action@<resolved-sha>  # v3.x.y
```

## Remote configuration remediations

Branch protection, rulesets, org/repo Actions policy, environment protection,
secret-scanning settings — these have wider consequences. Before making any
remote change, show:

```
Current configuration
Proposed configuration
Expected engineering impact
```

Make the change only with explicit user authorization, using trusted tooling.

## Secret remediation

You may remove a secret from code/config, replace its usage with an
environment/provider reference, and guide migration to workload identity. But be
honest: **removing a committed credential does not rotate it**, and it remains in
git history. Keep the finding unresolved until the credential is actually rotated
by its owner; document the rotation steps.

## Verification (mandatory)

Never resolve a finding merely because a file was edited. Re-run the relevant
observation:

- Pinned Action: re-parse and confirm the ref is a full 40-hex SHA.
- Reduced permissions: re-parse and confirm the scopes.
- Remote setting: re-query it read-only and confirm the new value.

Then record it:

```json
{"status": "resolved",
 "verification": {"status": "verified", "checked_at": "...",
                  "observed": "immutable full commit SHA"}}
```

If verification fails, keep the finding open and explain why. Rollback: since
changes are working-tree edits and uncommitted, reverting is `git checkout --` /
`git restore` on the touched files.
