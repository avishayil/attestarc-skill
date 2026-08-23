#!/usr/bin/env python3
"""Inspect GitHub Actions workflows and emit normalized *facts*.

No PyYAML dependency: this module includes a small, conservative parser for the
block-style YAML subset that GitHub Actions workflows use. It is deliberately
robust rather than complete -- on anything it cannot parse it degrades to
``parse_partial: true`` plus the raw excerpt rather than raising, so it can
never crash the host agent.

It emits facts (triggers, permissions, runners, action references and their
pin state, untrusted-context references, reusable-workflow secret passing and
pin state, cache usage, and fetch-then-execute command excerpts), never security
verdicts. The host agent, guided by references/github-actions.md and
references/threats/ci-cd-threats.md, decides what the facts mean.

Usage::

    inspect_workflows.py [--root .] [PATH ...]

With no PATH, all files under .github/workflows are inspected.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

from _pathsafe import is_within_root, resolve_within_root

# --------------------------------------------------------------------------- #
# Minimal block-YAML parser (workflow subset)
# --------------------------------------------------------------------------- #
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
# A ref that *looks like* a released version: v4, v1.2, v1.2.3, 1.2.3, and an
# optional pre-release/build suffix (v1.2.3-rc.1). This is only a hint used to
# tell a movable *version tag* apart from a movable *branch* (main/master); it
# is NOT a claim of tag-vs-branch certainty, which is undecidable from the
# ``uses:`` string alone (GitHub resolves either against tags then branches).
_VERSION_REF = re.compile(r"^v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.]+)?$")

# Context references that are attacker-influenced in fork/PR/issue events.
_UNTRUSTED_NEEDLES = (
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.commits",
    "github.event.head_commit.message",
    "github.head_ref",
)
# Refs that are attacker-controlled when checked out under a privileged event.
_UNTRUSTED_REF_NEEDLES = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.head_ref",
    "github.event.pull_request.merge_commit_sha",
)

# Fetch-then-execute one-liners: content pulled from the network and run. This
# is a fact (the matched command line), not a verdict -- the host decides
# whether it matters given the job's trigger and privilege.
_FETCH_EXEC_PATTERNS = (
    # curl/wget ... | <interpreter>  (optionally sudo, optional path prefix).
    # Covers shells (sh/bash/zsh) and language interpreters piped straight from
    # the network (e.g. ``curl ... | python3 -``, ``| node``, ``| ruby``).
    re.compile(
        r"\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?\S*"
        r"(?:sh|bash|zsh|python3?|perl|ruby|node|php)\b"
    ),
    # curl/wget ... && chmod +x  (download, make executable, then run)
    re.compile(r"\b(?:curl|wget)\b[^\n]*&&\s*chmod\s+\+x"),
    # PowerShell: Invoke-WebRequest/Invoke-RestMethod ... | iex
    re.compile(
        r"\b(?:iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n]*\|\s*"
        r"(?:iex|invoke-expression)",
        re.IGNORECASE,
    ),
)


class _Line:
    __slots__ = ("indent", "content", "raw")

    def __init__(self, indent, content, raw):
        self.indent = indent
        self.content = content
        self.raw = raw


def _strip_comment(s: str) -> str:
    """Remove a trailing '#' comment that is outside quotes."""
    in_single = in_double = False
    for i, ch in enumerate(s):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if i == 0 or s[i - 1] in " \t":
                return s[:i]
    return s


def _preprocess(text: str):
    """Return (lines, partial). Each line: _Line(indent, content, raw)."""
    partial = False
    records = []
    for raw in text.splitlines():
        expanded = raw
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            partial = True
            expanded = raw.expandtabs(2)
        stripped_full = _strip_comment(expanded)
        if stripped_full.strip() == "":
            records.append(_Line(-1, "", raw))  # blank/comment marker
            continue
        if stripped_full.strip() in ("---", "..."):
            # YAML document start/end markers. A workflow is a single document,
            # so these carry no mapping content; treat them like blank lines so
            # a leading ``---`` is not mistaken for a block-sequence item (which
            # would make the whole file parse as a list and drop every fact).
            records.append(_Line(-1, "", raw))
            continue
        indent = len(stripped_full) - len(stripped_full.lstrip(" "))
        records.append(_Line(indent, stripped_full.strip(), raw))
    return records, partial


def _scalar(token: str):
    token = token.strip()
    if token == "":
        return None
    if (len(token) >= 2 and token[0] == token[-1] and token[0] in "'\""):
        return token[1:-1]
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if inner == "":
            return []
        return [_scalar(t) for t in _split_flow(inner)]
    if token.startswith("{") and token.endswith("}"):
        inner = token[1:-1].strip()
        result = {}
        if inner:
            for pair in _split_flow(inner):
                if ":" in pair:
                    k, v = pair.split(":", 1)
                    result[k.strip()] = _scalar(v)
        return result
    low = token.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    return token


def _split_flow(s: str):
    """Split a flow collection body on top-level commas."""
    parts, depth, buf = [], 0, []
    in_s = in_d = False
    for ch in s:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        if not in_s and not in_d:
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append("".join(buf).strip())
                buf = []
                continue
        buf.append(ch)
    if "".join(buf).strip():
        parts.append("".join(buf).strip())
    return parts


class _Parser:
    def __init__(self, lines):
        self.lines = lines
        self.i = 0
        self.partial = False

    def _next_significant(self):
        j = self.i
        while j < len(self.lines) and self.lines[j].indent < 0:
            j += 1
        return j

    def parse_node(self, indent):
        j = self._next_significant()
        if j >= len(self.lines):
            return None
        self.i = j
        line = self.lines[self.i]
        if line.indent < indent:
            return None
        if line.content.startswith("-"):
            return self._parse_seq(line.indent)
        return self._parse_map(line.indent)

    def _parse_map(self, indent):
        result = {}
        while True:
            j = self._next_significant()
            if j >= len(self.lines):
                break
            line = self.lines[j]
            if line.indent < indent:
                break
            if line.indent > indent:
                # Unexpected extra indentation; skip defensively.
                self.partial = True
                self.i = j + 1
                continue
            if line.content.startswith("-"):
                break  # a sequence at this level; not our mapping
            self.i = j + 1
            key, value = self._parse_map_entry(line, indent)
            result[key] = value
        return result

    def _parse_map_entry(self, line, indent):
        content = line.content
        if ":" not in content:
            self.partial = True
            return content.strip(), None
        key, rest = self._split_key(content)
        rest = rest.strip()
        if rest in ("|", ">", "|-", ">-", "|+", ">+") or re.match(
            r"^[|>][+-]?\d*$", rest
        ):
            return key, self._consume_block_scalar(indent)
        if rest == "":
            # Nested block, or empty value.
            j = self._next_significant()
            if j < len(self.lines):
                nxt = self.lines[j]
                if nxt.indent > indent:
                    return key, self.parse_node(nxt.indent)
                # A block sequence may be indented at the SAME column as the
                # mapping key it belongs to (a common GitHub Actions style,
                # e.g. ``steps:`` and its ``- `` items both at one indent).
                # Only a sequence can share the key's indent; a sibling mapping
                # key would appear as ``key:``, not ``-``.
                if nxt.indent == indent and nxt.content.startswith("-"):
                    return key, self._parse_seq(nxt.indent)
            return key, None
        return key, _scalar(rest)

    @staticmethod
    def _split_key(content):
        # Split on the first ':' that is followed by space or end, outside quotes.
        in_s = in_d = False
        for i, ch in enumerate(content):
            if ch == "'" and not in_d:
                in_s = not in_s
            elif ch == '"' and not in_s:
                in_d = not in_d
            elif ch == ":" and not in_s and not in_d:
                if i + 1 >= len(content) or content[i + 1] in " \t":
                    key = content[:i].strip()
                    if key and key[0] == key[-1] and key[0] in "'\"":
                        key = key[1:-1]
                    return key, content[i + 1:]
        return content.strip(), ""

    def _consume_block_scalar(self, parent_indent):
        collected = []
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.indent < 0:  # blank line, part of the scalar
                collected.append("")
                self.i += 1
                continue
            if line.indent <= parent_indent:
                break
            collected.append(line.raw.strip())
            self.i += 1
        return "\n".join(collected).strip()

    def _parse_seq(self, indent):
        items = []
        while True:
            j = self._next_significant()
            if j >= len(self.lines):
                break
            line = self.lines[j]
            if line.indent < indent or not line.content.startswith("-"):
                break
            if line.indent > indent:
                self.partial = True
                break
            self.i = j
            rest = line.content[1:].lstrip()
            inner_indent = indent + 2
            if rest == "":
                self.i = j + 1
                k = self._next_significant()
                if k < len(self.lines) and self.lines[k].indent > indent:
                    items.append(self.parse_node(self.lines[k].indent))
                else:
                    items.append(None)
            elif self._has_mapping_colon(rest):
                # Mapping item; rewrite as the first line of the item's block.
                self.lines[j] = _Line(inner_indent, rest, line.raw)
                items.append(self.parse_node(inner_indent))
            else:
                # Plain scalar sequence item (e.g. - "v*").
                self.i = j + 1
                items.append(_scalar(rest))
        return items

    @staticmethod
    def _has_mapping_colon(content):
        _, rest = _Parser._split_key(content)
        return rest != "" or re.search(r":\s*$", content) is not None


def parse_yaml(text: str):
    """Parse the workflow-subset YAML. Returns (data, partial)."""
    lines, partial = _preprocess(text)
    parser = _Parser(lines)
    try:
        data = parser.parse_node(0)
    except Exception:  # never crash the host; degrade to partial
        return None, True
    return data, (partial or parser.partial)


# --------------------------------------------------------------------------- #
# Fact extraction
# --------------------------------------------------------------------------- #
def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _triggers(on_value):
    if on_value is None:
        return []
    if isinstance(on_value, str):
        return [on_value]
    if isinstance(on_value, list):
        return [str(t) for t in on_value]
    if isinstance(on_value, dict):
        return list(on_value.keys())
    return [str(on_value)]


# Per-event qualifiers that scope *where* an event fires. These are load-bearing
# for reachability (e.g. a ``push`` restricted to ``tags: [v*]`` is a release
# trigger, not a branch push), so they are surfaced as facts alongside the flat
# ``triggers`` list. The privilege judgment stays with the Host.
_TRIGGER_QUALIFIERS = (
    "branches", "branches-ignore", "tags", "tags-ignore",
    "paths", "paths-ignore", "types",
)


def _event_qualifiers(event, cfg):
    """Structured qualifiers for one ``on:`` event; ``{}`` when it has none."""
    if event == "schedule":
        crons = [str(item["cron"]) for item in _as_list(cfg)
                 if isinstance(item, dict) and "cron" in item]
        return {"cron": crons} if crons else {}
    if not isinstance(cfg, dict):
        return {}
    q = {}
    for key in _TRIGGER_QUALIFIERS:
        if key in cfg:
            q[key] = [str(x) for x in _as_list(cfg[key])]
    return q


def _trigger_details(on_value):
    """Map each trigger event to its qualifiers.

    Back-compat companion to ``_triggers`` (which stays a flat name list). A
    bare event (string, list item, or ``pull_request:`` with no body) maps to an
    empty ``{}`` — present, unqualified. The ``pull_request`` vs
    ``pull_request_target`` distinction is preserved because they are distinct
    event keys.
    """
    if on_value is None:
        return {}
    if isinstance(on_value, str):
        return {on_value: {}}
    if isinstance(on_value, list):
        return {str(e): {} for e in on_value}
    if isinstance(on_value, dict):
        return {str(event): _event_qualifiers(str(event), cfg)
                for event, cfg in on_value.items()}
    return {}


def _norm_permissions(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value  # e.g. "write-all", "read-all"
    if isinstance(value, dict):
        return {str(k): v for k, v in value.items()}
    return str(value)


def _norm_job_secrets(value):
    """Normalize a job-level ``secrets:`` (reusable-workflow call).

    Returns ``"inherit"``, a ``{name: source}`` dict, or ``None``.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value  # typically "inherit"
    if isinstance(value, dict):
        return {str(k): v for k, v in value.items()}
    return str(value)


def _step_uses_cache(action, step):
    """True if the step reads/writes an Actions cache (a presence fact)."""
    name = action["name"].lower()
    if name.endswith("actions/cache") or "/cache" in name:
        return True
    # setup-* actions with a cache input (e.g. actions/setup-node with cache).
    if "/setup-" in name:
        with_ = step.get("with")
        if isinstance(with_, dict) and any(
            str(k) == "cache" or str(k).endswith("-cache") for k in with_
        ):
            return True
    return False


def _run_excerpt(run_text, limit=200):
    """A compact, whitespace-normalized excerpt of a ``run:`` block.

    Workflow source, not runtime data, so there is no secret to redact here;
    the excerpt exists so the host can see what a privileged step executes
    (e.g. ``make release`` vs ``curl ... | sh``) without re-reading the file.
    """
    if not isinstance(run_text, str):
        return None
    collapsed = " ".join(run_text.split())
    if len(collapsed) > limit:
        return collapsed[:limit] + "..."
    return collapsed


def _fetch_execute_facts(run_text):
    """Detect a fetch-then-execute command; return (bool, excerpt|None)."""
    if not isinstance(run_text, str):
        return False, None
    for line in run_text.splitlines():
        for pat in _FETCH_EXEC_PATTERNS:
            if pat.search(line):
                return True, line.strip()[:200]
    return False, None


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _classify_ref(ref):
    """Return ``(ref_kind, looks_like_version)`` for a Git-based action ref.

    ``ref_kind`` is ``"sha"`` for an immutable 40-hex commit SHA, ``"movable"``
    for a tag or branch that can be repointed after review, or ``"none"`` when
    there is no ref. ``looks_like_version`` is a *hint* (True only for movable,
    version-shaped refs); it never asserts tag-vs-branch, which cannot be decided
    from the ``uses:`` string alone.
    """
    if ref is None:
        return "none", False
    if _SHA40.match(ref):
        return "sha", False
    return "movable", bool(_VERSION_REF.match(ref))


def _classify_docker(uses: str):
    """Classify a ``docker://`` action reference and its pin state.

    A container image is immutable only when pinned by digest
    (``image@sha256:<64 hex>``). A ``:tag`` reference — and an implicit
    ``latest`` when no tag is given — is mutable and can be repointed after
    review, so ``pinned`` is ``False`` for both. Registry ports
    (``host:5000/img:tag``) are handled by only treating a ``:`` that follows
    the final ``/`` as the tag separator.
    """
    body = uses[len("docker://"):]
    if "@" in body:
        name, ref = body.split("@", 1)
        pinned = bool(_DIGEST.match(ref))
        return {"name": f"docker://{name}", "ref": ref, "pinned": pinned,
                "ref_kind": "sha" if pinned else "movable",
                "looks_like_version": (
                    False if pinned else bool(_VERSION_REF.match(ref))),
                "kind": "docker", "uses": uses}
    last_slash = body.rfind("/")
    tail = body[last_slash + 1:]
    if ":" in tail:
        tail_name, tag = tail.rsplit(":", 1)
        name = body[:last_slash + 1] + tail_name
        return {"name": f"docker://{name}", "ref": tag, "pinned": False,
                "ref_kind": "movable",
                "looks_like_version": bool(_VERSION_REF.match(tag)),
                "kind": "docker", "uses": uses}
    # No tag at all -> implicit :latest, which is mutable (but not a version).
    return {"name": f"docker://{body}", "ref": None, "pinned": False,
            "ref_kind": "movable", "looks_like_version": False,
            "kind": "docker", "uses": uses}


def _classify_action(uses: str):
    uses = uses.strip()
    if uses.startswith(("./", "../")):
        # A local action is not a trusted leaf: its ``action.yml``/``action.yaml``
        # (and any script or composite steps it declares) is executable code that
        # is part of this pipeline and should itself be inspected. Emit that as a
        # fact — we deliberately do not recurse into it here (no scanner engine).
        return {"name": uses, "ref": None, "pinned": None, "kind": "local",
                "ref_kind": "none", "looks_like_version": False, "uses": uses,
                "local_path": uses, "transitive_code": True}
    if uses.startswith("docker://"):
        return _classify_docker(uses)
    kind = "external"
    name, ref = uses, None
    if "@" in uses:
        name, ref = uses.rsplit("@", 1)
    if re.search(r"\.ya?ml$", name) or "/.github/workflows/" in name:
        kind = "reusable-workflow"
    pinned = None
    if ref is not None:
        pinned = bool(_SHA40.match(ref))
    ref_kind, looks_like_version = _classify_ref(ref)
    return {"name": name, "ref": ref, "pinned": pinned, "ref_kind": ref_kind,
            "looks_like_version": looks_like_version, "kind": kind,
            "uses": uses}


def _expressions(text: str):
    if not isinstance(text, str):
        return [], []
    exprs = [m.group(1) for m in _EXPR.finditer(text)]
    untrusted = sorted({
        needle for e in exprs for needle in _UNTRUSTED_NEEDLES if needle in e
    })
    return exprs, untrusted


def _scan_run_text(step):
    """Collect ${{ }} expressions from run/env/with of a step."""
    texts = []
    if isinstance(step.get("run"), str):
        texts.append(step["run"])
    for container in ("env", "with"):
        c = step.get(container)
        if isinstance(c, dict):
            for v in c.values():
                if isinstance(v, str):
                    texts.append(v)
    all_exprs, all_untrusted = [], set()
    for t in texts:
        e, u = _expressions(t)
        all_exprs.extend(e)
        all_untrusted.update(u)
    return all_exprs, sorted(all_untrusted)


def _checkout_ref_facts(step, action):
    """Detect actions/checkout using an attacker-controlled ref."""
    if not action["name"].endswith("actions/checkout"):
        return None
    with_ = step.get("with")
    if not isinstance(with_, dict):
        return None
    ref = with_.get("ref")
    if not isinstance(ref, str):
        return None
    untrusted = any(n in ref for n in _UNTRUSTED_REF_NEEDLES)
    if "${{" not in ref:
        return None
    return {"ref": ref, "references_untrusted_ref": untrusted}


def _inspect_job(name, job):
    if not isinstance(job, dict):
        return {"name": name, "parse_partial": True}
    runs_on = job.get("runs-on")
    self_hosted = False
    if isinstance(runs_on, str):
        self_hosted = "self-hosted" in runs_on
    elif isinstance(runs_on, list):
        self_hosted = any("self-hosted" in str(x) for x in runs_on)

    actions, run_steps, checkout_refs = [], [], []
    uses_cache = False
    steps = job.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if isinstance(uses, str):
                action = _classify_action(uses)
                actions.append(action)
                co = _checkout_ref_facts(step, action)
                if co:
                    checkout_refs.append(co)
                if _step_uses_cache(action, step):
                    uses_cache = True
            run_text = step.get("run")
            has_run = isinstance(run_text, str)
            exprs, untrusted = _scan_run_text(step)
            fetch_exec, fetch_excerpt = _fetch_execute_facts(run_text)
            # Emit a record for every step that runs a command (``run:``), that
            # references attacker-influenced input, or that fetches-and-executes.
            # A benign ``uses:`` step whose only expressions are trusted (e.g.
            # ``${{ matrix.os }}``) is not command execution and is left to the
            # ``actions`` list, so it no longer masquerades as a run step.
            if has_run or untrusted or fetch_exec:
                run_steps.append({
                    "name": step.get("name"),
                    "has_run": has_run,
                    "run_excerpt": _run_excerpt(run_text) if has_run else None,
                    "expressions": exprs,
                    "references_untrusted_input": untrusted,
                    "fetch_execute": fetch_exec,
                    "fetch_execute_excerpt": fetch_excerpt,
                    # Reachability facts (facts, not verdicts): a step-level ``if:``
                    # can gate whether this step runs; ``continue-on-error`` lets the
                    # job succeed even if it fails. The host decides what they mean.
                    "if": step.get("if") if isinstance(step.get("if"), str) else None,
                    "continue_on_error": step.get("continue-on-error"),
                })

    job_uses = job.get("uses")  # reusable workflow at job level
    uses_pinned = None
    if isinstance(job_uses, str):
        uses_pinned = _classify_action(job_uses)["pinned"]

    # Reachability facts (facts, not verdicts). A job-level ``if:`` and ``needs:``
    # gate whether the job runs at all; a matrix fans it out; ``continue-on-error``
    # lets the workflow pass even when this job fails. The host reasons about
    # whether a privileged job is actually reachable — the parser only reports.
    needs = job.get("needs")
    if isinstance(needs, str):
        needs = [needs]
    elif isinstance(needs, list):
        needs = [str(n) for n in needs]
    else:
        needs = None

    strategy = job.get("strategy")
    strategy_facts = None
    if isinstance(strategy, dict):
        matrix = strategy.get("matrix")
        strategy_facts = {
            "has_matrix": matrix is not None,
            "matrix_keys": sorted(matrix.keys()) if isinstance(matrix, dict) else None,
            "fail_fast": strategy.get("fail-fast"),
        }

    return {
        "name": job.get("name", name),
        "id": name,
        "runner": runs_on,
        "self_hosted": self_hosted,
        "environment": job.get("environment"),
        "permissions": _norm_permissions(job.get("permissions")),
        "uses": job_uses,
        "uses_pinned": uses_pinned,
        "secrets": _norm_job_secrets(job.get("secrets")),
        "uses_cache": uses_cache,
        "if": job.get("if") if isinstance(job.get("if"), str) else None,
        "needs": needs,
        "strategy": strategy_facts,
        "continue_on_error": job.get("continue-on-error"),
        "actions": actions,
        "run_steps": run_steps,
        "checkout_refs": checkout_refs,
    }


def inspect_workflow_text(text: str, path: str) -> dict:
    data, partial = parse_yaml(text)
    if not isinstance(data, dict):
        return {
            "path": path,
            "parse_partial": True,
            "raw_excerpt": text[:400],
            "triggers": [],
            "trigger_details": {},
            "permissions": None,
            "jobs": [],
        }
    jobs_raw = data.get("jobs")
    jobs = []
    if isinstance(jobs_raw, dict):
        for jname, jdef in jobs_raw.items():
            jobs.append(_inspect_job(jname, jdef))
    elif jobs_raw is not None:
        partial = True

    return {
        "path": path,
        "name": data.get("name"),
        "parse_partial": partial,
        "triggers": _triggers(data.get("on")),
        "trigger_details": _trigger_details(data.get("on")),
        "permissions": _norm_permissions(data.get("permissions")),
        "jobs": jobs,
    }


def _iter_workflow_files(root):
    wf_dir = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(wf_dir):
        return []
    # The repository is untrusted: a symlinked .github/workflows escaping the
    # root must not be followed off-root during enumeration.
    if not is_within_root(wf_dir, root):
        return []
    found = []
    for fn in sorted(os.listdir(wf_dir)):
        if fn.endswith((".yml", ".yaml")):
            rel = os.path.join(".github", "workflows", fn)
            # Skip a symlinked entry that resolves outside the root.
            if is_within_root(os.path.join(root, rel), root):
                found.append(rel)
    return found


def inspect_paths(paths, root="."):
    workflows = []
    for p in paths:
        full = p if os.path.isabs(p) else os.path.join(root, p)
        rel = os.path.relpath(full, root).replace(os.sep, "/")
        # The repository is untrusted input. A caller-supplied absolute path, a
        # ``..`` traversal, or a symlinked workflow file must never redirect a
        # read outside the assessed root. Refuse as a fact; never follow it.
        _resolved, _root_real, within = resolve_within_root(full, root)
        if not within:
            workflows.append({
                "path": rel,
                "error": "refused: path resolves outside the repository root "
                         "(untrusted symlink or traversal)",
                "out_of_root": True,
                "parse_partial": True,
            })
            continue
        try:
            with open(full, "r", encoding="utf-8") as fh:
                text = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            workflows.append({"path": rel, "error": str(exc),
                              "parse_partial": True})
            continue
        wf = inspect_workflow_text(text, rel)
        workflows.append(wf)
    return {"workflows": workflows}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="AttestArc GitHub Actions inspector")
    p.add_argument("--root", default=".", help="repository root (default: .)")
    p.add_argument("paths", nargs="*",
                   help="workflow files (default: all under .github/workflows)")
    args = p.parse_args(argv)
    paths = args.paths or _iter_workflow_files(args.root)
    print(json.dumps(inspect_paths(paths, root=args.root),
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
