#!/usr/bin/env python3
"""AttestArc verified-knowledge lookup (facts, not verdicts; no network).

The assessor resolves *volatile platform facts* — GitHub fork-PR defaults, cache
write scopes, OIDC subject guidance, SLSA tracks — from a signed, temporal,
provenance-backed knowledge plane rather than from frozen prose. This helper is
the read side of that plane. It is deliberately **offline**: refreshing knowledge
is a separate principal (see ``knowledge_compile.py`` / the Updater mode). The
assessor only ever reads the verified snapshot through this tool.

Design rules (see SPECIFICATION.md §23 and THREAT_MODEL.md):

* Stdlib-only, deterministic, facts-not-verdicts.
* Confined to its OWN knowledge root — NEVER the assessed repository root. The
  repository is untrusted input and must not be able to redirect knowledge reads.
* Temporal + status-aware: an entry is in effect only within
  ``[valid_from, expires)``; retired/draft/superseded entries do not drive a
  current conclusion; a ``disputed`` entry is returned flagged and must not close
  a chain.
* Never crashes the host: an unparseable line degrades to ``parse_partial`` and
  is skipped.

Commands::

    knowledge.py status
    knowledge.py lookup --platform github-actions --subject cache-write [--topic X] [--as-of YYYY-MM-DD]
    knowledge.py explain KE-...
    knowledge.py index            # id -> {version, content_hash, status} for state.py reverify

``--knowledge-root`` overrides where packs are read from (default: the ``knowledge``
directory bundled beside this script — the last-known-good snapshot).
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import sys
from datetime import date, datetime

from _pathsafe import PathEscapeError, resolve_within_root

_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_KNOWLEDGE_ROOT = os.path.join(_PACKAGE_ROOT, "knowledge")
_ACTIVE_CONFIDENCES = ("authoritative", "corroborated")
# Statuses that never drive a *current* conclusion.
_NON_CURRENT = ("superseded", "retired", "draft")


class KnowledgeError(Exception):
    pass


def _parse_date(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def content_hash(entry: dict) -> str:
    """Stable sha256 over the entry's canonical JSON (the invalidation key)."""
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_targets(knowledge_root: str) -> dict:
    """Map pack filename -> version from targets.json, if present. Best-effort."""
    path = os.path.join(knowledge_root, "targets.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    out = {}
    for t in data.get("targets", []) if isinstance(data, dict) else []:
        if isinstance(t, dict) and "name" in t:
            out[os.path.basename(t["name"])] = str(t.get("version", "0"))
    return out


def load_packs(knowledge_root: str) -> tuple[list[dict], list[dict]]:
    """Load all knowledge entries under ``knowledge_root`` (confined).

    Returns ``(entries, pack_summaries)``. Each entry is annotated (not persisted)
    with ``_pack`` and ``_content_hash``. Never raises on a malformed line — it is
    skipped and reflected in the pack summary's ``parse_partial``.
    """
    resolved, root_real, within = resolve_within_root(knowledge_root, knowledge_root)
    # (self-resolve just normalizes; the real guard is per-file below)
    entries: list[dict] = []
    summaries: list[dict] = []
    pattern = os.path.join(knowledge_root, "bootstrap", "*.jsonl")
    targets = _load_targets(knowledge_root)
    for path in sorted(glob.glob(pattern)):
        _, _, ok = resolve_within_root(path, root_real)
        if not ok:
            continue  # a symlink escaping the knowledge root: never follow it
        name = os.path.basename(path)
        version = targets.get(name, "bootstrap")
        count = 0
        parse_partial = False
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw_lines = fh.readlines()
        except OSError:
            continue
        for line in raw_lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                parse_partial = True
                continue
            if not isinstance(entry, dict) or "id" not in entry:
                parse_partial = True
                continue
            entry["_pack"] = name
            entry["_version"] = version
            entry["_content_hash"] = content_hash(
                {k: v for k, v in entry.items() if not k.startswith("_")})
            entries.append(entry)
            count += 1
        summaries.append({"pack": name, "version": version, "entries": count,
                          "parse_partial": parse_partial})
    return entries, summaries


def _in_effect(entry: dict, as_of: date) -> bool:
    vf = _parse_date(entry.get("valid_from"))
    if vf is not None and as_of < vf:
        return False
    exp = _parse_date(entry.get("expires"))
    if exp is not None and as_of >= exp:
        return False
    return True


def _public(entry: dict) -> dict:
    """Strip internal annotations for output, keeping provenance."""
    return {k: v for k, v in entry.items() if not k.startswith("_")}


def lookup(entries, *, platform=None, subject=None, topic=None, as_of=None,
           include_noncurrent=False):
    """Return matching entries as of ``as_of`` (default today), status-aware."""
    as_of = _parse_date(as_of) or date.today()
    hits = []
    for e in entries:
        if platform and e.get("platform") != platform:
            continue
        if subject and e.get("subject") != subject:
            continue
        if topic:
            hay = f"{e.get('subject','')} {e.get('claim','')}".lower()
            if topic.lower() not in hay:
                continue
        if not _in_effect(e, as_of):
            continue
        status = e.get("status")
        if status in _NON_CURRENT and not include_noncurrent:
            continue
        out = _public(e)
        out["version"] = e.get("_version")
        out["content_hash"] = e.get("_content_hash")
        # A disputed/candidate entry may inform questions but not drive a
        # conclusion — flag it so the assessor routes to needs_review.
        out["drives_conclusion"] = (
            status == "active"
            and e.get("confidence") in _ACTIVE_CONFIDENCES)
        hits.append(out)
    hits.sort(key=lambda h: h.get("id") or "")
    return hits


def build_index(entries) -> dict:
    """id -> {version, content_hash, status}: the input to state.py reverify."""
    index = {}
    for e in entries:
        index[e["id"]] = {
            "version": e.get("_version"),
            "content_hash": e.get("_content_hash"),
            "status": e.get("status"),
        }
    return index


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def _resolve_root(args) -> str:
    root = args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT
    if not os.path.isdir(root):
        raise KnowledgeError(f"knowledge root not found: {root}")
    return os.path.abspath(root)


def cmd_status(args) -> int:
    root = _resolve_root(args)
    entries, summaries = load_packs(root)
    today = date.today()
    for s in summaries:
        pack_entries = [e for e in entries if e.get("_pack") == s["pack"]]
        oldest = min((e.get("valid_from") for e in pack_entries
                      if e.get("valid_from")), default=None)
        expired = sum(1 for e in pack_entries
                      if (_parse_date(e.get("expires")) or today) < today)
        disputed = sum(1 for e in pack_entries if e.get("status") == "disputed")
        s["oldest_valid_from"] = oldest
        s["expired"] = expired
        s["disputed"] = disputed
    out = {
        "knowledge_root": root,
        "source": "bundled-snapshot",  # offline; refresh is a separate principal
        "total_entries": len(entries),
        "packs": summaries,
    }
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_lookup(args) -> int:
    root = _resolve_root(args)
    entries, _ = load_packs(root)
    hits = lookup(entries, platform=args.platform, subject=args.subject,
                  topic=args.topic, as_of=args.as_of,
                  include_noncurrent=args.include_noncurrent)
    print(json.dumps(hits, indent=2, sort_keys=True))
    return 0


def cmd_explain(args) -> int:
    root = _resolve_root(args)
    entries, _ = load_packs(root)
    for e in entries:
        if e.get("id") == args.id:
            out = _public(e)
            out["version"] = e.get("_version")
            out["content_hash"] = e.get("_content_hash")
            print(json.dumps(out, indent=2, sort_keys=True))
            return 0
    sys.stderr.write(f"no knowledge entry with id {args.id}\n")
    return 1


def cmd_index(args) -> int:
    root = _resolve_root(args)
    entries, _ = load_packs(root)
    print(json.dumps(build_index(entries), indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="AttestArc verified-knowledge lookup")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--knowledge-root", default=None,
                        help="directory holding the knowledge packs (default: "
                             "the bundled snapshot beside this script). NEVER the "
                             "assessed repository root.")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("status", parents=[common],
                        help="per-pack freshness facts")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("lookup", parents=[common],
                        help="find in-effect entries (temporal + status-aware)")
    sp.add_argument("--platform")
    sp.add_argument("--subject")
    sp.add_argument("--topic", help="keyword matched in subject/claim")
    sp.add_argument("--as-of", help="YYYY-MM-DD; temporal query (default today)")
    sp.add_argument("--include-noncurrent", action="store_true",
                    help="also return superseded/retired/draft entries")
    sp.set_defaults(func=cmd_lookup)

    sp = sub.add_parser("explain", parents=[common],
                        help="print a single entry with full provenance")
    sp.add_argument("id")
    sp.set_defaults(func=cmd_explain)

    sp = sub.add_parser("index", parents=[common],
                        help="emit id -> {version, content_hash, status} "
                             "(feed to state.py reverify)")
    sp.set_defaults(func=cmd_index)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PathEscapeError as exc:
        sys.stderr.write(f"refusing to read outside the knowledge root: {exc}\n")
        return 2
    except KnowledgeError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
