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

# Action-name suffixes that publish or consume build artifacts. A newly-added
# publisher (release/artifact/pages) in a privileged workflow can let a
# compromised build write attacker-controlled outputs; a newly-added consumer
# can import an artifact as trusted input. Facts only — the host decides.
_ARTIFACT_PUBLISH = (
    "actions/upload-artifact",
    "actions/upload-pages-artifact",
    "softprops/action-gh-release",
    "ncipollo/release-action",
    "svenstaro/upload-release-action",
)
_ARTIFACT_DOWNLOAD = (
    "actions/download-artifact",
    "dawidd6/action-download-artifact",
)


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


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _aggregate_perms(wf):
    """Union of workflow-level and job-level permissions as {scope: level}.

    A capability gained anywhere in the workflow matters, so job-level
    ``permissions:`` (which can add ``id-token: write`` even when the top level
    is read-only) are folded in. ``write`` dominates ``read`` in the union.
    """
    agg: dict[str, str] = {}
    if not wf:
        return agg

    def merge(perms):
        for scope, level in _permission_set(perms).items():
            if agg.get(scope) != "write":
                agg[scope] = level

    merge(wf["permissions"])
    for j in wf["jobs"]:
        merge(j.get("permissions"))
    return agg


def _all_actions(wf):
    return {a["uses"]: a for j in wf["jobs"] for a in j["actions"]} if wf else {}


def _reusable_calls(wf):
    """Job-level reusable-workflow calls -> {uses: pinned}."""
    return {j["uses"]: j.get("uses_pinned") for j in wf["jobs"]
            if isinstance(j.get("uses"), str)} if wf else {}


def _secrets_inherit_jobs(wf):
    return {j.get("id") for j in wf["jobs"]
            if j.get("secrets") == "inherit"} if wf else set()


def _environments(wf):
    envs = set()
    if not wf:
        return envs
    for j in wf["jobs"]:
        env = j.get("environment")
        if isinstance(env, str):
            envs.add(env)
        elif isinstance(env, dict) and isinstance(env.get("name"), str):
            envs.add(env["name"])
    return envs


def _runner_labels(wf):
    labels = set()
    if not wf:
        return labels
    for j in wf["jobs"]:
        r = j.get("runner")
        if isinstance(r, str):
            labels.add(r)
        elif isinstance(r, list):
            labels.update(str(x) for x in r)
        elif isinstance(r, dict):
            labels.update(str(x) for x in _as_list(r.get("labels")))
    return labels


def _cache_jobs(wf):
    return {j.get("id") for j in wf["jobs"] if j.get("uses_cache")} if wf else set()


def _fetch_execute_excerpts(wf):
    out = set()
    if not wf:
        return out
    for j in wf["jobs"]:
        for s in j.get("run_steps", []):
            if s.get("fetch_execute"):
                out.add(s.get("fetch_execute_excerpt") or f"job:{j.get('id')}")
    return out


def _untrusted_input_refs(wf):
    out = set()
    if not wf:
        return out
    for j in wf["jobs"]:
        for s in j.get("run_steps", []):
            out.update(s.get("references_untrusted_input", []))
    return out


def _untrusted_checkout_refs(wf):
    return {c["ref"] for j in wf["jobs"] for c in j["checkout_refs"]
            if c["references_untrusted_ref"]} if wf else set()


def _artifact_uses(wf, names):
    out = set()
    for a in _all_actions(wf).values():
        low = a["name"].lower()
        if any(low.endswith(n) or f"{n}/" in low for n in names):
            out.add(a["uses"])
    return out


def _self_hosted(wf):
    return any(j.get("self_hosted") for j in wf["jobs"]) if wf else False


def _diff_workflow(before_wf, after_wf):
    """Compute the security-capability delta between two workflow snapshots.

    Every key is a *fact* about what the change introduced (never a verdict):
    the host agent decides, guided by the workflow's triggers, whether a gained
    capability is reachable by an untrusted actor.
    """
    delta = {}

    # Permissions, aggregated over workflow + job scopes.
    before_perms = _aggregate_perms(before_wf)
    after_perms = _aggregate_perms(after_wf)
    gained_perms = {}
    for scope, level in after_perms.items():
        if scope == "_all":
            if before_perms.get("_all") != level and level == "write":
                gained_perms[scope] = {"before": before_perms.get("_all") or "none",
                                       "after": level}
            continue
        if level == "write" and before_perms.get(scope) != "write":
            gained_perms[scope] = {"before": before_perms.get(scope) or "none",
                                   "after": level}
    if gained_perms:
        delta["permissions_gained"] = gained_perms

    # New privileged triggers.
    before_trig = set(before_wf["triggers"]) if before_wf else set()
    after_trig = set(after_wf["triggers"]) if after_wf else set()
    new_priv = sorted((after_trig - before_trig) & set(_PRIVILEGED_TRIGGERS))
    if new_priv:
        delta["new_privileged_triggers"] = new_priv

    # Runners.
    if _self_hosted(after_wf) and not _self_hosted(before_wf):
        delta["new_self_hosted_runner"] = True
    new_labels = sorted(_runner_labels(after_wf) - _runner_labels(before_wf))
    if new_labels:
        delta["new_runner_labels"] = new_labels

    # Action references (external, docker, reusable-workflow steps).
    after_actions = _all_actions(after_wf)
    new_actions = sorted(set(after_actions) - set(_all_actions(before_wf)))
    if new_actions:
        delta["new_action_references"] = new_actions
    # A mutable reference is a new external action OR docker image not pinned by
    # SHA / digest. (Previously docker images were ignored.)
    new_mutable = sorted(
        uses for uses in new_actions
        if after_actions[uses]["kind"] in ("external", "docker")
        and after_actions[uses]["pinned"] is False
    )
    if new_mutable:
        delta["new_mutable_action_references"] = new_mutable

    # Reusable-workflow calls at the job level, and their pin state.
    before_reusable = _reusable_calls(before_wf)
    after_reusable = _reusable_calls(after_wf)
    new_reusable = sorted(set(after_reusable) - set(before_reusable))
    if new_reusable:
        delta["new_reusable_workflow_calls"] = new_reusable
    new_unpinned_reusable = sorted(
        u for u in new_reusable if after_reusable[u] is False
    )
    if new_unpinned_reusable:
        delta["new_unpinned_reusable_workflow_calls"] = new_unpinned_reusable

    # secrets: inherit newly passed to a called workflow.
    new_inherit = sorted(
        j for j in (_secrets_inherit_jobs(after_wf) - _secrets_inherit_jobs(before_wf))
        if j is not None
    )
    if new_inherit:
        delta["new_secrets_inherit_jobs"] = new_inherit

    # Deployment environments newly referenced.
    new_envs = sorted(_environments(after_wf) - _environments(before_wf))
    if new_envs:
        delta["new_environments"] = new_envs

    # Cache usage newly introduced (cache poisoning is only interesting when the
    # writer runs with elevated trust; the entry's triggers give that context).
    new_cache = sorted(
        j for j in (_cache_jobs(after_wf) - _cache_jobs(before_wf)) if j is not None
    )
    if new_cache:
        delta["new_cache_jobs"] = new_cache

    # Fetch-then-execute one-liners newly introduced.
    new_fetch = sorted(_fetch_execute_excerpts(after_wf)
                       - _fetch_execute_excerpts(before_wf))
    if new_fetch:
        delta["new_fetch_execute"] = new_fetch

    # New references to attacker-controlled input in run/env/with.
    new_untrusted_input = sorted(
        _untrusted_input_refs(after_wf) - _untrusted_input_refs(before_wf)
    )
    if new_untrusted_input:
        delta["new_untrusted_input_references"] = new_untrusted_input

    # New attacker-controlled checkout refs.
    new_co = sorted(_untrusted_checkout_refs(after_wf)
                    - _untrusted_checkout_refs(before_wf))
    if new_co:
        delta["new_untrusted_checkout_refs"] = new_co

    # Artifact publishing / consumption newly introduced.
    new_publish = sorted(_artifact_uses(after_wf, _ARTIFACT_PUBLISH)
                         - _artifact_uses(before_wf, _ARTIFACT_PUBLISH))
    if new_publish:
        delta["new_artifact_publishers"] = new_publish
    new_download = sorted(_artifact_uses(after_wf, _ARTIFACT_DOWNLOAD)
                          - _artifact_uses(before_wf, _ARTIFACT_DOWNLOAD))
    if new_download:
        delta["new_artifact_consumers"] = new_download

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
    notes: list[str] = []
    any_partial = False
    for path in changed:
        norm = path.replace(os.sep, "/")
        # Only the repository-root .github/workflows/ actually executes. A
        # nested match (examples, vendored copies, test fixtures) is not active
        # CI, mirroring discover_repo.py; do not diff it as a live pipeline.
        if not norm.startswith(".github/workflows/"):
            continue
        if not norm.endswith((".yml", ".yaml")):
            continue
        before_text = _read_revision(root, base or "HEAD", path, staged=False)
        after_text = _read_revision(root, head, path, staged=staged)
        before_wf = _workflow_facts(before_text)
        after_wf = _workflow_facts(after_text)
        delta = _diff_workflow(before_wf, after_wf)
        parse_partial = bool(
            (before_wf and before_wf.get("parse_partial"))
            or (after_wf and after_wf.get("parse_partial"))
        )
        any_partial = any_partial or parse_partial
        entry = {
            "path": norm,
            "added": before_text is None and after_text is not None,
            "removed": after_text is None and before_text is not None,
            "parse_partial": parse_partial,
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

    if any_partial:
        notes.append(
            "One or more changed workflows parsed only partially "
            "(parse_partial). An empty security_delta on a partially-parsed "
            "workflow is NOT evidence the change is safe; inspect the raw diff."
        )

    return {
        "git": {"repository": True},
        "changed_files": changed,
        "workflow_changes": workflow_changes,
        "notes": notes,
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
