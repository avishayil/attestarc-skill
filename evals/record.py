#!/usr/bin/env python3
"""Dev-only eval-run recorder for AttestArc — NOT part of the shipped skill.

This is scaffolding under ``evals/``; it is never copied into an installed skill
(the payload is SKILL.md + references/ + scripts/ + assets/ — see SPECIFICATION.md
§3 and install.py). It exists so a human can record, in a repeatable way, the
outcome of running an interactive eval case against a host.

It DELIBERATELY DOES NOT SCORE ANYTHING. There is no eval-runner engine (SPEC
§14/§16, and the north star): building one would drift AttestArc toward a
standalone product. The human runs the case against the host, judges the
transcript against the case's ``expect``/``prohibit`` and the rubric in
``evals/README.md``, and this tool merely persists that judgment — with the
host, model, skill version, and a hash of the case spec — to a JSONL log so runs
can be compared across releases.

Usage::

    python evals/record.py list
    python evals/record.py show <case>
    python evals/record.py record <case> --host claude-code --model opus-4.8 \
        --verdict pass --expect-met 4/4 --prohibit-clean yes --note "…"

Records are appended to ``evals/runs/records.jsonl`` (one JSON object per line).
Stdlib-only; no third-party dependency and no import of the shipped helpers.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
_CASES_DIR = os.path.join(_HERE, "cases")
_RUNS_DIR = os.path.join(_HERE, "runs")
_LOG = os.path.join(_RUNS_DIR, "records.jsonl")

_VALID_VERDICTS = ("pass", "fail", "partial")


def _skill_version(default: str = "unknown") -> str:
    """Best-effort read of metadata.version from the repo-root SKILL.md."""
    path = os.path.join(_REPO, "SKILL.md")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return default
    m = re.search(r'(?m)^\s*version:\s*["\']?([^"\'\n]+)["\']?\s*$', text)
    return m.group(1).strip() if m else default


def _case_path(case: str) -> str:
    """Resolve a case name (with or without .yaml) to a path under cases/."""
    name = case if case.endswith((".yaml", ".yml")) else f"{case}.yaml"
    return os.path.join(_CASES_DIR, os.path.basename(name))


def _read_case(case: str):
    path = _case_path(case)
    if not os.path.isfile(path):
        return None, None
    with open(path, "rb") as fh:
        raw = fh.read()
    return path, raw


def _first_field(text: str, field: str) -> str:
    """Extract a single-line ``field: value`` from a case's YAML (no PyYAML)."""
    m = re.search(rf'(?m)^{re.escape(field)}:\s*(.+?)\s*$', text)
    if not m:
        return ""
    val = m.group(1)
    # Fold a block scalar ('>' / '|') into its first continuation line.
    if val in (">", "|", ">-", "|-"):
        lines = text.splitlines()
        for i, ln in enumerate(lines):
            if ln.startswith(f"{field}:"):
                rest = [l.strip() for l in lines[i + 1:] if l.strip()]
                return rest[0] if rest else ""
    return val


def _iter_cases():
    if not os.path.isdir(_CASES_DIR):
        return
    for fn in sorted(os.listdir(_CASES_DIR)):
        if fn.endswith((".yaml", ".yml")):
            yield fn


def cmd_list(_args) -> int:
    any_case = False
    for fn in _iter_cases():
        any_case = True
        with open(os.path.join(_CASES_DIR, fn), "r", encoding="utf-8") as fh:
            text = fh.read()
        name = _first_field(text, "name") or fn
        desc = _first_field(text, "description")
        print(f"{name:40s} {desc}")
    if not any_case:
        print("(no cases found)", file=sys.stderr)
        return 1
    return 0


def cmd_show(args) -> int:
    path, raw = _read_case(args.case)
    if path is None:
        print(f"error: no such case: {args.case}", file=sys.stderr)
        return 2
    sys.stdout.write(raw.decode("utf-8", errors="replace"))
    return 0


def cmd_record(args) -> int:
    path, raw = _read_case(args.case)
    if path is None:
        print(f"error: no such case: {args.case}", file=sys.stderr)
        return 2
    if args.verdict not in _VALID_VERDICTS:
        print(f"error: --verdict must be one of {_VALID_VERDICTS}",
              file=sys.stderr)
        return 2

    text = raw.decode("utf-8", errors="replace")
    record = {
        # Timezone-aware UTC; recorded at judgment time by a human, not derived.
        "recorded_at": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "case": _first_field(text, "name") or os.path.basename(path)[:-5],
        "case_file": os.path.relpath(path, _REPO),
        # Hash of the exact spec judged, so a later spec edit is detectable.
        "case_sha256": hashlib.sha256(raw).hexdigest(),
        "host": args.host,
        "model": args.model,
        "skill_version": args.version or _skill_version(),
        "verdict": args.verdict,
        "expect_met": args.expect_met,
        "prohibit_clean": args.prohibit_clean,
        "judge": args.judge or os.environ.get("USER", ""),
        "notes": args.note or [],
    }

    os.makedirs(_RUNS_DIR, exist_ok=True)
    with open(_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    print(f"recorded {record['verdict']} for {record['case']} "
          f"(host={record['host']} model={record['model']} "
          f"version={record['skill_version']}) → {os.path.relpath(_LOG, _REPO)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Record (do not score) interactive AttestArc eval runs.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list available cases").set_defaults(
        func=cmd_list)

    ps = sub.add_parser("show", help="print a case spec")
    ps.add_argument("case")
    ps.set_defaults(func=cmd_show)

    pr = sub.add_parser("record", help="append a human judgment to the log")
    pr.add_argument("case")
    pr.add_argument("--host", required=True,
                    help="host that ran the case, e.g. claude-code / cursor")
    pr.add_argument("--model", required=True, help="model identifier")
    pr.add_argument("--version", default=None,
                    help="skill version (default: read from SKILL.md)")
    pr.add_argument("--verdict", required=True,
                    help=f"one of {_VALID_VERDICTS}")
    pr.add_argument("--expect-met", default=None,
                    help='e.g. "4/4" — how many expect bullets were met')
    pr.add_argument("--prohibit-clean", default=None,
                    choices=["yes", "no", "partial"],
                    help="were all prohibit bullets avoided?")
    pr.add_argument("--judge", default=None, help="who judged (default: $USER)")
    pr.add_argument("--note", action="append", help="free-form note (repeatable)")
    pr.set_defaults(func=cmd_record)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
