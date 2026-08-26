#!/usr/bin/env python3
"""Structural attester for AttestArc's OKF *Attested Computation* concepts.

The kernel's fact-emitting helpers — ``discover_repo.py``, ``inspect_workflows.py``,
``inspect_git_diff.py`` — are modeled as OKF *Attested Computation* concepts in
``scripts/computations/*.md``. This module is the **minimal structural receipt
validator** for those concepts (SPECIFICATION.md §12.5).

What it is, and — emphatically — what it is NOT:

* **Structure only, never a verdict.** It answers exactly one question: *"is this
  JSON a structurally well-formed facts receipt for this computation?"* — required
  keys present, of the declared types, and no verdict-shaped key smuggled in. It
  emits facts (a boolean plus the structural violations it observed); it makes no
  security judgment and never decides what any receipt *means*. A component that
  emitted a security verdict here would violate SPECIFICATION.md §2.6/§12/§17 and
  the layer boundary this whole tree exists to keep. The ``forbidden_keys`` check is
  precisely how the boundary is enforced: a receipt that carries a ``verdict`` /
  ``finding`` / ``severity`` key is *structurally* invalid for a fact-emitting
  computation.
* **Never executes the computation.** It validates a receipt the Host already
  produced. It reads concept files and a receipt JSON; it never runs a helper, never
  touches the assessed repository, and never reaches the network.
* **Never crashes the host.** Malformed concepts degrade to ``parse_partial`` (via
  ``okf``) and an unreadable/undecodable receipt is reported as a violation, not an
  exception.

stdlib-only, deterministic (CLAUDE.md; SPECIFICATION.md §12).
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import okf  # noqa: E402  (sibling helper; path set above)

# Declared receipt key types -> the JSON/Python type they must be. ``bool`` is
# checked before ``int`` because ``bool`` is a subclass of ``int`` in Python.
_TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "integer": int,
}

_COMPUTATIONS_DIR = os.path.dirname(os.path.abspath(__file__))

# Reserved, non-concept markdown that ships in this tree (documentation, not an
# Attested Computation). Skipped by the concept sweep, mirroring the knowledge
# bundle's reserved index.md/log.md.
_RESERVED = ("README.md", "index.md", "log.md")


def concept_files(directory: str = _COMPUTATIONS_DIR):
    """The Attested-Computation concept files in ``directory`` (reserved
    documentation files excluded), sorted."""
    return sorted(p for p in glob.glob(os.path.join(directory, "*.md"))
                  if os.path.basename(p) not in _RESERVED)


def _type_ok(value, declared: str) -> bool:
    expected = _TYPE_MAP.get(declared)
    if expected is None:
        return False
    if declared == "integer":  # exclude bool, which is a subclass of int
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, expected)


def load_computation(path: str) -> dict:
    """Read a computation concept. Returns the authoritative fields the attester
    needs plus ``parse_partial``; never raises."""
    concept = okf.read_concept(path)
    fm = concept.get("frontmatter") or {}
    ns = fm.get("attestarc")
    if concept.get("_parse_partial") or not isinstance(ns, dict):
        return {"id": None, "entrypoint": None, "emits": None,
                "receipt": {}, "parse_partial": True, "path": path}
    receipt = ns.get("receipt")
    return {
        "id": ns.get("id"),
        "entrypoint": ns.get("entrypoint"),
        "emits": ns.get("emits"),
        "runtime": ns.get("runtime"),
        "receipt": receipt if isinstance(receipt, dict) else {},
        "parse_partial": False,
        "path": path,
    }


def validate_receipt(computation: dict, receipt) -> dict:
    """Fact operation: is ``receipt`` a structurally valid facts receipt for
    ``computation``? Returns ``{computation_id, structurally_valid, violations,
    checked_keys}``. No verdict, no security judgment."""
    violations: list[dict] = []
    spec = computation.get("receipt") or {}
    required = spec.get("required_keys") or []
    key_types = spec.get("key_types") or {}
    forbidden = spec.get("forbidden_keys") or []

    if computation.get("parse_partial"):
        violations.append({"kind": "concept-parse-partial",
                           "detail": "computation concept did not parse cleanly"})
    if computation.get("emits") != "facts":
        # A computation this attester validates MUST declare it emits facts. This
        # is the layer boundary, restated as data.
        violations.append({"kind": "not-facts-emitter",
                           "detail": f"emits={computation.get('emits')!r}"})

    if not isinstance(receipt, dict):
        violations.append({"kind": "receipt-not-object",
                           "detail": type(receipt).__name__})
        return {
            "computation_id": computation.get("id"),
            "structurally_valid": False,
            "violations": violations,
            "checked_keys": [],
        }

    for key in required:
        if key not in receipt:
            violations.append({"kind": "missing-required-key", "key": key})
            continue
        declared = key_types.get(key)
        if declared is not None and not _type_ok(receipt[key], declared):
            violations.append({"kind": "wrong-type", "key": key,
                               "expected": declared,
                               "got": type(receipt[key]).__name__})

    for key in forbidden:
        if key in receipt:
            # A verdict-shaped key in a facts receipt is a boundary breach.
            violations.append({"kind": "forbidden-key", "key": key})

    return {
        "computation_id": computation.get("id"),
        "structurally_valid": not violations,
        "violations": violations,
        "checked_keys": sorted(required),
    }


def verify_concepts(directory: str = _COMPUTATIONS_DIR) -> dict:
    """Structural self-check over every computation concept in ``directory``:
    each parses cleanly, is in canonical OKF byte form, declares ``emits: facts``
    and a well-formed ``receipt``, and points at an entrypoint that exists. Facts,
    not a verdict; used by tests and the release self-check."""
    results = []
    ok = True
    repo_root = os.path.dirname(_COMPUTATIONS_DIR)  # scripts/ -> repo root's scripts
    repo_root = os.path.dirname(repo_root)
    for path in concept_files(directory):
        rel = os.path.relpath(path, repo_root)
        problems = []
        raw = ""
        try:
            with open(path, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            problems.append(f"unreadable: {exc}")
        if raw and not okf.roundtrip_ok(raw):
            problems.append("non-canonical OKF byte form")
        comp = load_computation(path)
        if comp["parse_partial"]:
            problems.append("parse_partial")
        else:
            if comp["emits"] != "facts":
                problems.append(f"emits != facts (emits={comp['emits']!r})")
            if not comp["id"]:
                problems.append("missing attestarc.id")
            spec = comp["receipt"]
            if not spec.get("required_keys"):
                problems.append("receipt has no required_keys")
            ep = comp.get("entrypoint")
            if not ep:
                problems.append("missing entrypoint")
            elif not os.path.exists(os.path.join(repo_root, ep)):
                problems.append(f"entrypoint not found: {ep}")
        ok = ok and not problems
        results.append({"concept": rel, "ok": not problems,
                        "problems": problems})
    return {"all_ok": ok, "concepts": results}


def _cmd_check(args) -> int:
    computation = load_computation(args.concept)
    if args.receipt == "-":
        raw = sys.stdin.read()
    else:
        try:
            with open(args.receipt, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            print(json.dumps({"computation_id": computation.get("id"),
                              "structurally_valid": False,
                              "violations": [{"kind": "receipt-unreadable",
                                              "detail": str(exc)}],
                              "checked_keys": []}, indent=2, sort_keys=True))
            return 0
    try:
        receipt = json.loads(raw)
    except (ValueError, TypeError) as exc:
        print(json.dumps({"computation_id": computation.get("id"),
                          "structurally_valid": False,
                          "violations": [{"kind": "receipt-not-json",
                                          "detail": str(exc)}],
                          "checked_keys": []}, indent=2, sort_keys=True))
        return 0
    print(json.dumps(validate_receipt(computation, receipt),
                     indent=2, sort_keys=True))
    return 0


def _cmd_verify_concepts(args) -> int:
    result = verify_concepts(args.dir or _COMPUTATIONS_DIR)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Structural attester for AttestArc Attested-Computation "
                    "concepts (facts, never a verdict)")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="validate a receipt against a computation "
                                     "concept")
    c.add_argument("concept", help="path to a computation concept (.md)")
    c.add_argument("receipt", help="path to the receipt JSON, or - for stdin")
    c.set_defaults(func=_cmd_check)

    v = sub.add_parser("verify-concepts",
                       help="structural self-check over all computation concepts")
    v.add_argument("--dir", default=None,
                   help="concepts directory (default: this script's directory)")
    v.set_defaults(func=_cmd_verify_concepts)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
