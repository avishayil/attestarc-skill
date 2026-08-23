#!/usr/bin/env python3
"""Inspect GitHub Actions workflows and emit normalized *facts*.

No PyYAML dependency: this module includes a small, conservative parser for the
block-style YAML subset that GitHub Actions workflows use. It is deliberately
robust rather than complete -- on anything it cannot parse it degrades to
``parse_partial: true`` plus the raw excerpt rather than raising, so it can
never crash the host agent.

It emits facts (triggers, permissions, runners, action references and their
pin state, untrusted-context references), never security verdicts. The host
agent, guided by references/github-actions.md, decides what the facts mean.

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

# --------------------------------------------------------------------------- #
# Minimal block-YAML parser (workflow subset)
# --------------------------------------------------------------------------- #
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")

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
            if j < len(self.lines) and self.lines[j].indent > indent:
                return key, self.parse_node(self.lines[j].indent)
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


def _norm_permissions(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value  # e.g. "write-all", "read-all"
    if isinstance(value, dict):
        return {str(k): v for k, v in value.items()}
    return str(value)


def _classify_action(uses: str):
    uses = uses.strip()
    kind = "external"
    name, ref = uses, None
    if uses.startswith(("./", "../")):
        kind = "local"
        name = uses
    elif uses.startswith("docker://"):
        kind = "docker"
        name = uses
    else:
        if "@" in uses:
            name, ref = uses.rsplit("@", 1)
        if re.search(r"\.ya?ml$", name) or "/.github/workflows/" in name:
            kind = "reusable-workflow"
    pinned = None
    if ref is not None:
        pinned = bool(_SHA40.match(ref))
    return {"name": name, "ref": ref, "pinned": pinned, "kind": kind, "uses": uses}


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
            exprs, untrusted = _scan_run_text(step)
            if exprs:
                run_steps.append({
                    "name": step.get("name"),
                    "has_run": isinstance(step.get("run"), str),
                    "expressions": exprs,
                    "references_untrusted_input": untrusted,
                })

    return {
        "name": job.get("name", name),
        "id": name,
        "runner": runs_on,
        "self_hosted": self_hosted,
        "environment": job.get("environment"),
        "permissions": _norm_permissions(job.get("permissions")),
        "uses": job.get("uses"),  # reusable workflow at job level
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
        "permissions": _norm_permissions(data.get("permissions")),
        "jobs": jobs,
    }


def _iter_workflow_files(root):
    wf_dir = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(wf_dir):
        return []
    found = []
    for fn in sorted(os.listdir(wf_dir)):
        if fn.endswith((".yml", ".yaml")):
            found.append(os.path.join(".github", "workflows", fn))
    return found


def inspect_paths(paths, root="."):
    workflows = []
    for p in paths:
        full = p if os.path.isabs(p) else os.path.join(root, p)
        rel = os.path.relpath(full, root).replace(os.sep, "/")
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
