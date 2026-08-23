#!/usr/bin/env python3
"""Inspect security-relevant repository changes and emit normalized *facts*.

Compares two revisions (default: working tree vs HEAD) using read-only git,
and reports the security-capability deltas that matter most for review:

* changed files;
* workflow permission changes (especially id-token / contents:write);
* new privileged triggers (pull_request_target, workflow_run);
* new self-hosted runners;
* new / newly-mutable external Action references;
* new attacker-controlled checkout refs.

Facts, not findings. The host agent decides the security impact of the change.

Usage::

    inspect_git_diff.py [--root .] [--base REV] [--head REV] [--staged]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

# Reuse the workflow parser so before/after are normalized identically.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import inspect_workflows as iw  # noqa: E402

_WRITE_SENSITIVE = ("id-token", "contents", "packages", "actions",
                    "deployments", "pull-requests")
_PRIVILEGED_TRIGGERS = ("pull_request_target", "workflow_run")


def _git(args, cwd):
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                             text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def _changed_files(root, base, head, staged):
    args = ["diff", "--name-only"]
    if staged:
        args.append("--cached")
    if base:
        args.append(base)
    if head:
        args.append(head)
    out = _git(args, root)
    if out is None:
        return []
    return [ln for ln in out.splitlines() if ln.strip()]


def _read_revision(root, rev, path, staged):
    """Return file text at a revision, or None if absent."""
    if rev is None and not staged:
        # working tree
        full = os.path.join(root, path)
        if not os.path.exists(full):
            return None
        try:
            with open(full, "r", encoding="utf-8") as fh:
                return fh.read()
        except (OSError, UnicodeDecodeError):
            return None
    spec = f"{rev}:{path}" if rev else f":{path}"  # ':path' = staged index
    return _git(["show", spec], root)


def _permission_set(perms):
    """Normalize permissions to a comparable {scope: level} dict."""
    if perms == "write-all":
        return {s: "write" for s in _WRITE_SENSITIVE} | {"_all": "write"}
    if perms == "read-all":
        return {"_all": "read"}
    if isinstance(perms, dict):
        return {str(k): str(v) for k, v in perms.items()}
    return {}


def _workflow_facts(text):
    if text is None:
        return None
    wf = iw.inspect_workflow_text(text, "")
    return wf


def _diff_workflow(before_wf, after_wf):
    """Compute the security-capability delta between two workflow snapshots."""
    delta = {}

    before_perms = _permission_set(before_wf["permissions"] if before_wf else None)
    after_perms = _permission_set(after_wf["permissions"] if after_wf else None)
    gained_perms = {}
    for scope, level in after_perms.items():
        if scope == "_all":
            if before_perms.get("_all") != level:
                gained_perms[scope] = {"before": before_perms.get("_all"),
                                       "after": level}
            continue
        before_level = before_perms.get(scope)
        if before_level != level and level == "write":
            gained_perms[scope] = {"before": before_level or "none",
                                   "after": level}
    if gained_perms:
        delta["permissions_gained"] = gained_perms

    before_trig = set(before_wf["triggers"]) if before_wf else set()
    after_trig = set(after_wf["triggers"]) if after_wf else set()
    new_priv = sorted((after_trig - before_trig) & set(_PRIVILEGED_TRIGGERS))
    if new_priv:
        delta["new_privileged_triggers"] = new_priv

    def self_hosted(wf):
        return any(j.get("self_hosted") for j in wf["jobs"]) if wf else False
    if self_hosted(after_wf) and not self_hosted(before_wf):
        delta["new_self_hosted_runner"] = True

    def action_refs(wf):
        return {a["uses"] for j in wf["jobs"] for a in j["actions"]} if wf else set()
    new_actions = sorted(action_refs(after_wf) - action_refs(before_wf))
    new_mutable = []
    if after_wf:
        after_actions = {a["uses"]: a for j in after_wf["jobs"]
                         for a in j["actions"]}
        for uses in new_actions:
            a = after_actions.get(uses)
            if a and a["kind"] == "external" and a["pinned"] is False:
                new_mutable.append(uses)
    if new_actions:
        delta["new_action_references"] = new_actions
    if new_mutable:
        delta["new_mutable_action_references"] = new_mutable

    def untrusted_checkout(wf):
        return [c["ref"] for j in wf["jobs"] for c in j["checkout_refs"]
                if c["references_untrusted_ref"]] if wf else []
    before_co = set(untrusted_checkout(before_wf))
    new_co = sorted(set(untrusted_checkout(after_wf)) - before_co)
    if new_co:
        delta["new_untrusted_checkout_refs"] = new_co

    return delta


def inspect_diff(root=".", base=None, head=None, staged=False):
    root = os.path.abspath(root)
    is_git = _git(["rev-parse", "--is-inside-work-tree"], root) == "true\n"
    if not is_git:
        return {"git": {"repository": False}, "changed_files": [],
                "workflow_changes": [],
                "notes": ["Not a git repository; no diff available."]}

    changed = _changed_files(root, base, head, staged)
    workflow_changes = []
    for path in changed:
        norm = path.replace(os.sep, "/")
        if "/.github/workflows/" not in f"/{norm}" and not norm.startswith(
            ".github/workflows/"
        ):
            continue
        if not norm.endswith((".yml", ".yaml")):
            continue
        before_text = _read_revision(root, base or "HEAD", path, staged=False)
        after_text = _read_revision(root, head, path, staged=staged)
        before_wf = _workflow_facts(before_text)
        after_wf = _workflow_facts(after_text)
        delta = _diff_workflow(before_wf, after_wf)
        entry = {
            "path": norm,
            "added": before_text is None and after_text is not None,
            "removed": after_text is None and before_text is not None,
            "before": {
                "permissions": before_wf["permissions"] if before_wf else None,
                "triggers": before_wf["triggers"] if before_wf else [],
            },
            "after": {
                "permissions": after_wf["permissions"] if after_wf else None,
                "triggers": after_wf["triggers"] if after_wf else [],
            },
            "security_delta": delta,
        }
        workflow_changes.append(entry)

    return {
        "git": {"repository": True},
        "changed_files": changed,
        "workflow_changes": workflow_changes,
        "notes": [],
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="AttestArc git diff inspector")
    p.add_argument("--root", default=".")
    p.add_argument("--base", default=None,
                   help="base revision (default: HEAD for working-tree compare)")
    p.add_argument("--head", default=None,
                   help="head revision (default: working tree)")
    p.add_argument("--staged", action="store_true",
                   help="compare the staged index against HEAD")
    args = p.parse_args(argv)
    result = inspect_diff(args.root, base=args.base, head=args.head,
                          staged=args.staged)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
