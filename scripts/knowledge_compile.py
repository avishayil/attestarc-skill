#!/usr/bin/env python3
"""AttestArc Updater — deterministic pieces of the knowledge-refresh pipeline.

The refresh workflow is a **separate principal** from the assessor. It is the
only mode with network access, and even then only through the host's fetch tool
against the fixed allowlist in ``knowledge/sources.yaml``. This helper never
fetches; it provides the *deterministic* steps the host orchestrates around its
LLM slot-extraction:

    host WebFetch (allowlisted)          <- host, not this tool
      -> quarantine        (this tool: store raw doc + content_hash)
      -> host slot-extract to a candidate KnowledgeEntry   <- host LLM
      -> check-source      (this tool: registry authority, never model-chosen)
      -> validate-candidate(this tool: schema + provenance + secret guard)
      -> conflict          (this tool: contradiction vs existing authoritative)
      -> may-promote       (this tool: deterministic promotion-tier decision)

Every step emits **facts**. Promotion itself is never performed here — the tool
only reports the tier the deterministic policy assigns (see
``core/promotion-policy.md``, a root-of-trust file). The model may ``propose``;
it may never ``promote``.

Stdlib-only. No target-repository access; no kernel or knowledge write beyond the
quarantine directory the caller names.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import date
from urllib.parse import urlsplit

import state  # reuse the shared secret guard

_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_KNOWLEDGE_ROOT = os.path.join(_PACKAGE_ROOT, "knowledge")

# Source types that can never auto-promote: they are recorded as candidate only
# (blog/issue/researcher/forum/model). See promotion-policy.md.
_NEVER_AUTO_TYPES = ("research", "issue", "community", "arbitrary-web")
_DIRECTIONS = ("positive", "neutral", "negative")

# KnowledgeEntry required keys + closed enums (hand-rolled; jsonschema is not a
# dependency). Kept in parity with schemas/knowledge.schema.json.
_REQUIRED = ("id", "kind", "platform", "subject", "claim", "valid_from",
             "status", "confidence", "sources")
_ALLOWED_TOP = _REQUIRED + ("applies_to", "expires", "supersedes",
                            "last_verified", "compiler", "extensions")
_KINDS = ("platform-semantics", "api", "standard", "guidance")
_STATUSES = ("active", "superseded", "disputed", "retired", "draft")
_CONFIDENCES = ("authoritative", "corroborated", "candidate")
_SOURCE_REQUIRED = ("publisher", "authority", "type", "url")


class CompileError(Exception):
    pass


# --------------------------------------------------------------------------- #
# sources.yaml — scoped stdlib reader (no YAML dependency)
# --------------------------------------------------------------------------- #
def load_registry(knowledge_root: str) -> dict:
    """Parse the small ``sources.yaml`` subset: a ``tiers`` mapping and an
    ``allowlist`` list of ``{domain, publisher, type}`` records.

    Deliberately not a general YAML parser — it handles exactly this file's shape
    (comments, ``key: value``, and ``- `` list records with indented fields).
    """
    path = os.path.join(knowledge_root, "sources.yaml")
    tiers: dict = {}
    allowlist: list = []
    section = None
    record = None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        raise CompileError(f"cannot read source registry: {exc}")

    for raw in lines:
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0 and stripped.endswith(":"):
            section = stripped[:-1]
            record = None
            continue
        if section == "tiers" and indent >= 2 and ":" in stripped:
            key, _, val = stripped.partition(":")
            try:
                tiers[key.strip()] = int(val.strip())
            except ValueError:
                continue
        elif section == "allowlist":
            body = stripped
            if body.startswith("- "):
                record = {}
                allowlist.append(record)
                body = body[2:].strip()
            if record is not None and ":" in body:
                key, _, val = body.partition(":")
                record[key.strip()] = val.strip()
    return {"tiers": tiers, "allowlist": allowlist}


def _domain_of(url: str) -> str:
    host = urlsplit(url).hostname or ""
    return host.lower()


def classify_source(url: str, registry: dict) -> dict:
    """Deterministically classify a URL against the registry. Facts only."""
    domain = _domain_of(url)
    tiers = registry.get("tiers", {})
    for rec in registry.get("allowlist", []):
        if rec.get("domain", "").lower() == domain and domain:
            stype = rec.get("type", "arbitrary-web")
            return {"url": url, "domain": domain, "allowed": True,
                    "publisher": rec.get("publisher"), "type": stype,
                    "authority": tiers.get(stype, 0)}
    return {"url": url, "domain": domain, "allowed": False,
            "publisher": None, "type": "arbitrary-web",
            "authority": tiers.get("arbitrary-web", 0)}


# --------------------------------------------------------------------------- #
# quarantine
# --------------------------------------------------------------------------- #
def quarantine(raw: str, url: str, out_dir: str, registry: dict) -> dict:
    """Store a fetched document under ``out_dir`` keyed by content hash.

    The raw doc is treated as untrusted input: it is stored, hashed, and
    classified, but never parsed as instructions. Extraction happens later, in
    the host LLM step, over this quarantined copy.
    """
    content_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    os.makedirs(out_dir, exist_ok=True)
    stored = os.path.join(out_dir, f"{content_hash}.raw")
    with open(stored, "w", encoding="utf-8") as fh:
        fh.write(raw)
    fact = classify_source(url, registry)
    fact.update({"content_hash": content_hash, "bytes": len(raw),
                 "stored_path": stored})
    return fact


# --------------------------------------------------------------------------- #
# validate-candidate
# --------------------------------------------------------------------------- #
def validate_candidate(candidate: dict, registry: dict) -> dict:
    """Schema + provenance + secret checks over an extracted candidate entry."""
    errors: list = []
    warnings: list = []
    tiers = registry.get("tiers", {})

    if not isinstance(candidate, dict):
        return {"valid": False, "errors": ["candidate is not an object"],
                "warnings": []}

    for key in _REQUIRED:
        if key not in candidate:
            errors.append(f"missing required field: {key}")
    extra = set(candidate) - set(_ALLOWED_TOP)
    if extra:
        errors.append(f"unknown fields (not in schema): {sorted(extra)}")

    kid = candidate.get("id", "")
    if not (isinstance(kid, str) and kid.startswith("KE-")
            and all(c.islower() or c.isdigit() or c == "-" for c in kid[3:])):
        errors.append(f"id must match ^KE-[a-z0-9-]+$: {kid!r}")
    if candidate.get("kind") not in _KINDS:
        errors.append(f"kind not in {_KINDS}: {candidate.get('kind')!r}")
    if candidate.get("status") not in _STATUSES:
        errors.append(f"status not in {_STATUSES}: {candidate.get('status')!r}")
    if candidate.get("confidence") not in _CONFIDENCES:
        errors.append(
            f"confidence not in {_CONFIDENCES}: {candidate.get('confidence')!r}")

    sources = candidate.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append("sources must be a non-empty array")
        sources = []
    max_authority = 0
    for i, src in enumerate(sources):
        if not isinstance(src, dict):
            errors.append(f"sources[{i}] is not an object")
            continue
        for key in _SOURCE_REQUIRED:
            if key not in src:
                errors.append(f"sources[{i}] missing {key}")
        stype = src.get("type")
        declared = src.get("authority")
        expected = tiers.get(stype)
        # Authority is registry-derived, never model-chosen.
        if expected is None:
            errors.append(f"sources[{i}] type {stype!r} is not a registry tier")
        elif declared != expected:
            errors.append(
                f"sources[{i}] authority {declared} does not match registry "
                f"tier for {stype!r} ({expected}); authority is never model-chosen")
        if isinstance(expected, int):
            max_authority = max(max_authority, expected)

    # Secret guard: no secret value may enter the learning pipeline.
    for path, text in state._iter_string_paths(candidate):
        if state.looks_like_secret(text):
            errors.append(f"{path} appears to contain a secret value; secrets "
                          "must never enter the knowledge pipeline")

    # Confidence vs authority sanity (warning, not fatal — policy decides).
    conf = candidate.get("confidence")
    if conf == "authoritative" and max_authority < 90:
        warnings.append("confidence 'authoritative' but no source authority >= 90")

    return {"valid": not errors, "errors": errors, "warnings": warnings,
            "max_authority": max_authority}


# --------------------------------------------------------------------------- #
# conflict
# --------------------------------------------------------------------------- #
def find_conflicts(candidate: dict, existing: list) -> dict:
    """Report existing *active, authoritative* entries that share the candidate's
    (platform, subject) but assert a different claim — a contradiction to
    adjudicate (the loser becomes ``disputed``)."""
    conflicts = []
    plat, subj, claim = (candidate.get("platform"), candidate.get("subject"),
                         candidate.get("claim"))
    sup = set(candidate.get("supersedes") or [])
    for e in existing:
        if not isinstance(e, dict):
            continue
        if e.get("id") in sup:
            continue  # explicitly superseding it is not a conflict
        if (e.get("platform") == plat and e.get("subject") == subj
                and e.get("status") == "active"
                and e.get("confidence") in ("authoritative", "corroborated")
                and e.get("claim") != claim):
            conflicts.append({"id": e.get("id"), "claim": e.get("claim")})
    return {"has_conflict": bool(conflicts), "conflicts": conflicts}


# --------------------------------------------------------------------------- #
# may-promote — the deterministic tier decision
# --------------------------------------------------------------------------- #
_ROOT_OF_TRUST = (
    "core/agent-safety.md", "core/promotion-policy.md",
    "scripts/knowledge_verify.py", "knowledge/root.json",
    ".github/workflows/release-knowledge.yml",
)


def may_promote(candidate: dict, facts: dict) -> dict:
    """Return the promotion tier per core/promotion-policy.md. Never promotes.

    ``facts`` carries the deterministic inputs the policy reads:
      evals_pass (bool), signature_valid (bool|None), has_conflict (bool),
      direction ('positive'|'neutral'|'negative'), changes_root_of_trust (bool),
      weakens_eval (bool), max_authority (int).
    """
    reasons: list = []
    tier = "auto-promote"

    def demote(to, why):
        nonlocal tier
        order = ["auto-promote", "require-review", "two-party-review", "never-auto"]
        if order.index(to) > order.index(tier):
            tier = to
        reasons.append(why)

    sources = candidate.get("sources") or []
    types = {s.get("type") for s in sources if isinstance(s, dict)}
    max_authority = facts.get("max_authority", 0)

    # Never-auto sources → candidate only.
    if types & set(_NEVER_AUTO_TYPES) or max_authority < 90:
        demote("never-auto",
               "source is blog/issue/researcher/community or authority < 90; "
               "candidate only — may shape questions, never drive a conclusion")

    # Two-party: any root-of-trust target or eval weakening.
    if facts.get("changes_root_of_trust"):
        demote("two-party-review", "changes a root-of-trust file")
    if facts.get("weakens_eval"):
        demote("two-party-review", "weakens or deletes a trusted eval")

    # Require-review: security-negative direction, conflict, reachability/severity.
    direction = facts.get("direction")
    if direction not in _DIRECTIONS:
        demote("require-review", "security-regression direction unknown")
    elif direction == "negative":
        demote("require-review",
               "security-negative direction (previously-flagged -> safe); the "
               "exact shape of a poisoning attempt")
    if facts.get("has_conflict"):
        demote("require-review",
               "conflicts with an existing authoritative entry; adjudicate "
               "(-> disputed until resolved)")
    if facts.get("alters_reachability_or_severity"):
        demote("require-review", "alters reachability or severity semantics")

    # Auto-promote gate: everything must be clean.
    if tier == "auto-promote":
        if not facts.get("evals_pass"):
            demote("require-review", "evals do not pass")
        sig = facts.get("signature_valid")
        if sig is False:
            demote("require-review", "signature invalid for a published pack")

    if tier == "auto-promote":
        reasons.append("authoritative + structured + no conflict + evals pass + "
                       "direction not negative: eligible for auto-promotion")
    return {"tier": tier, "reasons": reasons}


# --------------------------------------------------------------------------- #
# I/O helpers
# --------------------------------------------------------------------------- #
def _read_stdin_json():
    data = sys.stdin.read()
    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        raise CompileError(f"stdin is not valid JSON: {exc}")


def _load_existing(knowledge_root: str) -> list:
    """Load full existing entries from the bundled packs (for conflict checks)."""
    import knowledge  # local import; shares the same scripts/ dir
    entries, _ = knowledge.load_packs(knowledge_root)
    return [{k: v for k, v in e.items() if not k.startswith("_")} for e in entries]


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_check_source(args) -> int:
    registry = load_registry(args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT)
    print(json.dumps(classify_source(args.url, registry), indent=2, sort_keys=True))
    return 0


def cmd_quarantine(args) -> int:
    registry = load_registry(args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT)
    raw = sys.stdin.read()
    fact = quarantine(raw, args.url, args.out, registry)
    print(json.dumps(fact, indent=2, sort_keys=True))
    return 0


def cmd_validate(args) -> int:
    registry = load_registry(args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT)
    result = validate_candidate(_read_stdin_json(), registry)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


def cmd_conflict(args) -> int:
    root = args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT
    result = find_conflicts(_read_stdin_json(), _load_existing(root))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["has_conflict"] else 0


def cmd_may_promote(args) -> int:
    candidate = _read_stdin_json()
    facts = {
        "evals_pass": args.evals_pass,
        "signature_valid": (None if args.signature is None
                            else args.signature == "valid"),
        "has_conflict": args.conflict,
        "direction": args.direction,
        "changes_root_of_trust": args.root_of_trust,
        "weakens_eval": args.weakens_eval,
        "alters_reachability_or_severity": args.alters_severity,
        "max_authority": args.max_authority,
    }
    result = may_promote(candidate, facts)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="AttestArc Updater: deterministic knowledge-refresh steps "
                    "(facts, not verdicts; the model may propose, never promote)")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--knowledge-root", default=None)
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("check-source", parents=[common],
                        help="classify a URL against the source registry")
    sp.add_argument("--url", required=True)
    sp.set_defaults(func=cmd_check_source)

    sp = sub.add_parser("quarantine", parents=[common],
                        help="store a fetched doc (stdin) by content hash")
    sp.add_argument("--url", required=True)
    sp.add_argument("--out", required=True, help="quarantine directory")
    sp.set_defaults(func=cmd_quarantine)

    sp = sub.add_parser("validate-candidate", parents=[common],
                        help="schema + provenance + secret checks (stdin)")
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("conflict", parents=[common],
                        help="contradiction vs existing authoritative (stdin)")
    sp.set_defaults(func=cmd_conflict)

    sp = sub.add_parser("may-promote", parents=[common],
                        help="deterministic promotion-tier decision (stdin)")
    sp.add_argument("--evals-pass", action="store_true")
    sp.add_argument("--signature", choices=["valid", "invalid"], default=None)
    sp.add_argument("--conflict", action="store_true")
    sp.add_argument("--direction", choices=list(_DIRECTIONS), default=None)
    sp.add_argument("--root-of-trust", action="store_true")
    sp.add_argument("--weakens-eval", action="store_true")
    sp.add_argument("--alters-severity", action="store_true")
    sp.add_argument("--max-authority", type=int, default=0)
    sp.set_defaults(func=cmd_may_promote)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CompileError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
