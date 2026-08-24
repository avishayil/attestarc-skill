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

# KnowledgeEntry required keys + closed enums (hand-rolled; jsonschema is not a
# dependency). Kept in parity with schemas/knowledge.schema.json.
_REQUIRED = ("id", "kind", "platform", "subject", "claim", "valid_from",
             "status", "confidence", "sources")
_ALLOWED_TOP = _REQUIRED + ("applies_to", "expires", "supersedes",
                            "last_verified", "compiler", "extensions")
_KINDS = ("platform-semantics", "api", "standard", "guidance")
_STATUSES = ("active", "superseded", "disputed", "retired", "draft")
_CONFIDENCES = ("authoritative", "corroborated", "candidate")
# A source must carry a URL and be bound to a quarantined object: either an
# inline content_hash + retrieved_at, or a receipt_id resolvable to a receipt
# that carries them. publisher/type/authority are DERIVED from the URL via the
# registry, never trusted from the candidate.
_SOURCE_REQUIRED = ("url",)


class CompileError(Exception):
    pass


# --------------------------------------------------------------------------- #
# sources.yaml — scoped stdlib reader (no YAML dependency)
# --------------------------------------------------------------------------- #
def load_registry(knowledge_root: str) -> dict:
    """Parse the small ``sources.yaml`` subset: a ``tiers`` mapping and an
    ``allowlist`` list of ``{origin, publisher, type}`` records, each optionally
    carrying a nested ``path_prefixes:`` list that scopes a repo host to specific
    orgs/repos.

    Deliberately not a general YAML parser — it handles exactly this file's shape
    (comments, ``key: value``, ``- `` list records with indented fields, and a
    single level of nested ``- item`` lists under a record key).
    """
    path = os.path.join(knowledge_root, "sources.yaml")
    tiers: dict = {}
    allowlist: list = []
    section = None
    record = None
    record_indent = None
    listkey = None
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
            record_indent = None
            listkey = None
            continue
        if section == "tiers" and indent >= 2 and ":" in stripped:
            key, _, val = stripped.partition(":")
            try:
                tiers[key.strip()] = int(val.strip())
            except ValueError:
                continue
        elif section == "allowlist":
            # A new record: a ``- `` line at (or above) the record dash indent.
            if stripped.startswith("- ") and (record_indent is None
                                              or indent <= record_indent):
                record = {}
                allowlist.append(record)
                record_indent = indent
                listkey = None
                body = stripped[2:].strip()
                if ":" in body:
                    key, _, val = body.partition(":")
                    record[key.strip()] = val.strip()
                continue
            if record is None:
                continue
            # A nested list item under the current record key.
            if stripped.startswith("- ") and listkey is not None:
                record[listkey].append(stripped[2:].strip())
                continue
            # A record field ``key: value`` (empty value starts a nested list).
            if ":" in stripped:
                key, _, val = stripped.partition(":")
                key, val = key.strip(), val.strip()
                if val == "":
                    record[key] = []
                    listkey = key
                else:
                    record[key] = val
                    listkey = None
    return {"tiers": tiers, "allowlist": allowlist}


def classify_source(url: str, registry: dict) -> dict:
    """Deterministically classify a URL against the registry. Facts only.

    Trust is bound to an exact HTTPS origin (scheme+host) and, for repo hosts,
    to specific ``path_prefixes`` (orgs/repos). A non-HTTPS URL, an unknown
    origin, or a path outside the trusted prefixes is ``arbitrary-web`` (0) —
    never fetched, never promotion-eligible. The declared type/authority a
    candidate carries is ignored here; classification derives from the URL alone.
    """
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower()
    upath = parts.path or "/"
    tiers = registry.get("tiers", {})

    def reject(reason):
        return {"url": url, "host": host, "scheme": scheme, "path": upath,
                "allowed": False, "publisher": None, "type": "arbitrary-web",
                "authority": tiers.get("arbitrary-web", 0), "reason": reason}

    if scheme != "https":
        return reject("non-https source rejected")
    if not host:
        return reject("url has no host")
    for rec in registry.get("allowlist", []):
        o = urlsplit(rec.get("origin", ""))
        if (o.scheme or "").lower() != "https":
            continue
        if (o.hostname or "").lower() != host:
            continue
        prefixes = rec.get("path_prefixes")
        if prefixes and not any(upath.startswith(p) for p in prefixes):
            continue  # host matches but path is outside the trusted org/repo set
        stype = rec.get("type", "arbitrary-web")
        return {"url": url, "host": host, "scheme": scheme, "path": upath,
                "allowed": True, "publisher": rec.get("publisher"),
                "type": stype, "authority": tiers.get(stype, 0)}
    return reject("origin not on allowlist (or path outside trusted prefixes)")


# --------------------------------------------------------------------------- #
# quarantine
# --------------------------------------------------------------------------- #
def _receipt_id(content_hash: str) -> str:
    """Deterministic receipt id derived from the stored content hash."""
    return "QR-" + content_hash[:16]


def quarantine(raw: str, url: str, out_dir: str, registry: dict,
               retrieved_at: str) -> dict:
    """Store a fetched document under ``out_dir`` keyed by content hash and emit a
    signed-in-spirit **provenance receipt**.

    The raw doc is treated as untrusted input: it is stored, hashed, and
    classified, but never parsed as instructions. Extraction happens later, in
    the host LLM step, over this quarantined copy. The receipt — not the model —
    is the authority for ``publisher``/``source_type``/``authority``/
    ``content_hash``/``retrieved_at``; a candidate references it by ``receipt_id``
    and ``validate_candidate`` resolves provenance from it. The LLM never
    populates those fields.

    ``retrieved_at`` is supplied by the caller (the fetch step) rather than read
    from the clock here, keeping this helper deterministic.
    """
    content_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    os.makedirs(out_dir, exist_ok=True)
    stored = os.path.join(out_dir, f"{content_hash}.raw")
    with open(stored, "w", encoding="utf-8") as fh:
        fh.write(raw)
    fact = classify_source(url, registry)
    receipt = {
        "_type": "attestarc-quarantine-receipt",
        "receipt_id": _receipt_id(content_hash),
        "final_url": url,
        "publisher": fact.get("publisher"),
        "source_type": fact.get("type"),
        "authority": fact.get("authority"),
        "allowed": fact.get("allowed", False),
        "content_hash": content_hash,
        "retrieved_at": retrieved_at,
        "bytes": len(raw),
        "stored_path": stored,
    }
    receipt_path = os.path.join(out_dir, f"{content_hash}.receipt.json")
    with open(receipt_path, "w", encoding="utf-8") as fh:
        json.dump(receipt, fh, indent=2, sort_keys=True)
    receipt["receipt_path"] = receipt_path
    return receipt


def resolve_receipt(receipt_id: str, quarantine_dir: str) -> dict | None:
    """Load a quarantine receipt by id from ``quarantine_dir``. Returns None if
    the directory or a matching receipt is absent or unreadable."""
    if not receipt_id or not quarantine_dir:
        return None
    try:
        names = os.listdir(quarantine_dir)
    except OSError:
        return None
    for name in names:
        if not name.endswith(".receipt.json"):
            continue
        try:
            with open(os.path.join(quarantine_dir, name), "r",
                      encoding="utf-8") as fh:
                rec = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(rec, dict) and rec.get("receipt_id") == receipt_id:
            return rec
    return None


# --------------------------------------------------------------------------- #
# validate-candidate
# --------------------------------------------------------------------------- #
def validate_candidate(candidate: dict, registry: dict,
                       quarantine_dir: str = None) -> dict:
    """Schema + provenance + secret checks over an extracted candidate entry.

    Every source URL is **reclassified** through the registry: the derived
    publisher/type/authority are authoritative and any declared value that
    disagrees is an error (the model never chooses authority). Each source must
    also be bound to a quarantined object — an inline ``content_hash`` +
    ``retrieved_at`` or a ``receipt_id`` resolvable in ``quarantine_dir`` — so a
    candidate is structurally tied to something that was actually fetched.
    """
    errors: list = []
    warnings: list = []

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
        url = src.get("url")
        if not isinstance(url, str) or not url:
            errors.append(f"sources[{i}] url must be a non-empty string")
            continue

        # Reclassify the URL — the registry, not the candidate, decides authority.
        derived = classify_source(url, registry)
        if not derived.get("allowed"):
            errors.append(
                f"sources[{i}] url {url!r} classifies as arbitrary-web "
                f"({derived.get('reason')}); it may not drive a promotion")
        for field, key in (("type", "type"), ("authority", "authority"),
                           ("publisher", "publisher")):
            if field in src and src.get(field) != derived.get(key):
                errors.append(
                    f"sources[{i}] declared {field}={src.get(field)!r} disagrees "
                    f"with the registry classification of the URL "
                    f"({derived.get(key)!r}); {field} is never model-chosen")
        max_authority = max(max_authority, derived.get("authority", 0))

        # Provenance binding: content_hash + retrieved_at, or a resolvable receipt.
        receipt = None
        rid = src.get("receipt_id")
        if rid:
            receipt = resolve_receipt(rid, quarantine_dir)
            if receipt is None:
                errors.append(
                    f"sources[{i}] receipt_id {rid!r} does not resolve to a "
                    f"quarantine receipt")
            else:
                if receipt.get("content_hash") != src.get("content_hash") \
                        and src.get("content_hash") is not None:
                    errors.append(
                        f"sources[{i}] content_hash disagrees with receipt {rid!r}")
                if receipt.get("final_url") != url:
                    errors.append(
                        f"sources[{i}] url disagrees with receipt {rid!r} final_url")
                if receipt.get("authority") != derived.get("authority"):
                    errors.append(
                        f"sources[{i}] receipt {rid!r} authority "
                        f"{receipt.get('authority')} disagrees with registry "
                        f"reclassification ({derived.get('authority')})")
        has_hash = bool(src.get("content_hash")) or bool(
            receipt and receipt.get("content_hash"))
        has_time = bool(src.get("retrieved_at")) or bool(
            receipt and receipt.get("retrieved_at"))
        if not has_hash:
            errors.append(
                f"sources[{i}] is not bound to a fetched object: needs "
                f"content_hash or a resolvable receipt_id")
        if not has_time:
            errors.append(
                f"sources[{i}] missing retrieved_at (or a receipt carrying it)")

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
# Files whose modification is a trust event: any change touching one requires
# two-party review. Kept in sync with core/promotion-policy.md and
# THREAT_MODEL.md §6. This tuple is USED by classify_change_paths below.
_ROOT_OF_TRUST = (
    "core/agent-safety.md", "core/promotion-policy.md",
    "scripts/knowledge_verify.py", "scripts/knowledge.py",
    "scripts/knowledge_compile.py", "knowledge/sources.yaml",
    "knowledge/trust-anchor.json",
    "schemas/knowledge.schema.json", "schemas/knowledge-manifest.schema.json",
    "schemas/learning-candidate.schema.json",
    ".github/workflows/release-knowledge.yml",
)


def classify_change_paths(paths) -> dict:
    """Classify a set of repo-relative paths (the actual proposed diff) into the
    trust-relevant facts the promotion policy reads. Mechanical, not a judgment.

      - ``changes_root_of_trust``: any path in ``_ROOT_OF_TRUST``.
      - ``touches_eval``: any path under ``evals/``.
    ``weakens_eval`` (deletion/modification of a *trusted* eval) is derived by the
    caller from the diff shape (removed/modified eval files) — an addition is not
    a weakening — and passed alongside these facts.
    """
    paths = [p for p in (paths or []) if isinstance(p, str)]

    def norm(p):
        return p.lstrip("./")

    normed = [norm(p) for p in paths]
    rot_hits = sorted({p for p in normed if p in _ROOT_OF_TRUST})
    eval_hits = sorted({p for p in normed if p.startswith("evals/")})
    return {
        "changes_root_of_trust": bool(rot_hits),
        "root_of_trust_paths": rot_hits,
        "touches_eval": bool(eval_hits),
        "eval_paths": eval_hits,
    }


def may_promote(candidate: dict, facts: dict, registry: dict = None,
                existing: list = None) -> dict:
    """Return the promotion tier per core/promotion-policy.md. Never promotes.

    Facts are **derived**, not asserted by the caller:
      - ``max_authority`` and source ``types`` come from reclassifying the
        candidate's own source URLs through ``registry`` (falls back to
        ``facts['max_authority']`` only when no registry is supplied).
      - ``has_conflict`` comes from ``find_conflicts`` over ``existing`` when
        given (else ``facts['has_conflict']``).
      - ``changes_root_of_trust`` / ``touches_eval`` come from
        ``classify_change_paths(facts['change_paths'])`` — the actual diff.
      - ``weakens_eval`` is mechanical diff data
        (``facts['removed_or_modified_evals']`` non-empty), not a model judgment.
      - ``evals_pass`` and ``signature_valid`` are results of an actual eval run
        and the attestation check.

    Safer core rule: knowledge that does not supersede or conflict with an active
    claim can auto-promote (given authority/evals/signature); anything that
    changes an existing active security semantic — a supersession, a conflict, an
    eval weakening, or a root-of-trust edit — always routes to human review.
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
    if registry is not None:
        classified = [classify_source(s.get("url", ""), registry)
                      for s in sources if isinstance(s, dict)]
        types = {c.get("type") for c in classified}
        max_authority = max([c.get("authority", 0) for c in classified] or [0])
    else:
        types = {s.get("type") for s in sources if isinstance(s, dict)}
        max_authority = facts.get("max_authority", 0)

    # Conflict is derived from the current verified set when it is provided.
    if existing is not None:
        has_conflict = find_conflicts(candidate, existing)["has_conflict"]
    else:
        has_conflict = bool(facts.get("has_conflict"))

    change = classify_change_paths(facts.get("change_paths"))
    weakens_eval = bool(facts.get("removed_or_modified_evals"))

    # Never-auto sources → candidate only.
    if types & set(_NEVER_AUTO_TYPES) or max_authority < 90:
        demote("never-auto",
               "source is blog/issue/researcher/community or authority < 90; "
               "candidate only — may shape questions, never drive a conclusion")

    # Two-party: any root-of-trust target or eval weakening.
    if change["changes_root_of_trust"]:
        demote("two-party-review",
               f"changes a root-of-trust file: {change['root_of_trust_paths']}")
    if weakens_eval:
        demote("two-party-review", "weakens or deletes a trusted eval")

    # Require-review: alters an existing active semantic (supersede or conflict).
    if candidate.get("supersedes"):
        demote("require-review",
               "supersedes an existing active claim; a change to established "
               "security semantics, not new knowledge")
    if has_conflict:
        demote("require-review",
               "conflicts with an existing authoritative entry; adjudicate "
               "(-> disputed until resolved)")

    # Auto-promote gate: everything must be clean.
    if tier == "auto-promote":
        if not facts.get("evals_pass"):
            demote("require-review", "evals do not pass")
        sig = facts.get("signature_valid")
        if sig is False:
            demote("require-review", "signature invalid for a published pack")

    if tier == "auto-promote":
        reasons.append("authoritative source + new (non-superseding) knowledge + "
                       "no conflict + evals pass + valid signature: eligible for "
                       "auto-promotion")
    return {"tier": tier, "reasons": reasons,
            "derived": {"max_authority": max_authority,
                        "has_conflict": has_conflict,
                        "changes_root_of_trust": change["changes_root_of_trust"],
                        "weakens_eval": weakens_eval,
                        "supersedes": bool(candidate.get("supersedes"))}}


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
    fact = quarantine(raw, args.url, args.out, registry, args.retrieved_at)
    print(json.dumps(fact, indent=2, sort_keys=True))
    return 0


def cmd_validate(args) -> int:
    registry = load_registry(args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT)
    result = validate_candidate(_read_stdin_json(), registry,
                                quarantine_dir=args.quarantine_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


def cmd_conflict(args) -> int:
    root = args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT
    result = find_conflicts(_read_stdin_json(), _load_existing(root))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["has_conflict"] else 0


def cmd_may_promote(args) -> int:
    candidate = _read_stdin_json()
    root = args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT
    registry = load_registry(root)
    existing = _load_existing(root)
    facts = {
        "evals_pass": args.evals_pass,
        "signature_valid": (None if args.signature is None
                            else args.signature == "valid"),
        "change_paths": args.change_path or [],
        "removed_or_modified_evals": (args.removed_eval or [])
                                     + (args.modified_eval or []),
    }
    result = may_promote(candidate, facts, registry=registry, existing=existing)
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
                        help="store a fetched doc (stdin) by content hash + "
                             "emit a provenance receipt")
    sp.add_argument("--url", required=True)
    sp.add_argument("--out", required=True, help="quarantine directory")
    sp.add_argument("--retrieved-at", required=True,
                    help="fetch timestamp (ISO 8601), supplied by the caller")
    sp.set_defaults(func=cmd_quarantine)

    sp = sub.add_parser("validate-candidate", parents=[common],
                        help="schema + provenance + secret checks (stdin)")
    sp.add_argument("--quarantine-dir", default=None,
                    help="directory of quarantine receipts (to resolve receipt_id)")
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("conflict", parents=[common],
                        help="contradiction vs existing authoritative (stdin)")
    sp.set_defaults(func=cmd_conflict)

    sp = sub.add_parser("may-promote", parents=[common],
                        help="deterministic promotion-tier decision (stdin); "
                             "authority/conflict/root-of-trust are derived, not "
                             "asserted")
    sp.add_argument("--evals-pass", action="store_true",
                    help="the eval run over this candidate passed")
    sp.add_argument("--signature", choices=["valid", "invalid"], default=None,
                    help="attestation result for the published pack")
    sp.add_argument("--change-path", action="append", default=[],
                    help="a repo-relative path the proposed diff touches "
                         "(repeatable; the actual diff, from git)")
    sp.add_argument("--removed-eval", action="append", default=[],
                    help="a trusted eval file removed by the diff (repeatable)")
    sp.add_argument("--modified-eval", action="append", default=[],
                    help="a trusted eval file modified by the diff (repeatable)")
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
