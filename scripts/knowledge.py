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

import knowledge_verify
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


def _load_manifest_version(knowledge_root: str) -> str:
    """The release version pins every pack in one atomic manifest, so all packs in
    a snapshot share the manifest version. Best-effort; 'bootstrap' if absent."""
    path = os.path.join(knowledge_root, "manifest.json")
    if not os.path.exists(path):
        return "bootstrap"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return "bootstrap"
    if isinstance(data, dict) and data.get("version") is not None:
        return str(data.get("version"))
    return "bootstrap"


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
    version = _load_manifest_version(knowledge_root)
    for path in sorted(glob.glob(pattern)):
        _, _, ok = resolve_within_root(path, root_real)
        if not ok:
            continue  # a symlink escaping the knowledge root: never follow it
        name = os.path.basename(path)
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


def _applicability(entry: dict, context: dict | None) -> str:
    """Evaluate the entry's ``applies_to`` scope against an explicit assessment
    context. Returns ``applicable`` | ``not-applicable`` | ``unknown``.

    A conclusion-driving fact must be scoped to the situation being assessed; the
    assessor is not trusted to remember to interpret ``applies_to`` by hand. An
    entry with no scope constraints is unconstrained (``applicable``). If a
    constraint is present but the context does not supply that dimension, the
    result is ``unknown`` — the assessor must resolve it, not assume it applies.
    """
    at = entry.get("applies_to") or {}
    context = context or {}
    dims = []  # per-constraint verdicts

    def match(present, supplied, ok):
        if not present:
            return None            # no constraint on this dimension
        if supplied in (None, "", []):
            return "unknown"       # constrained, but context is silent
        return "applicable" if ok else "not-applicable"

    prod = at.get("product")
    dims.append(match(prod is not None, context.get("product"),
                      prod == context.get("product")))

    events = at.get("events") or ([at["event"]] if at.get("event") else None)
    dims.append(match(events, context.get("event"),
                      context.get("event") in (events or [])))

    action = at.get("action")
    cact = context.get("action")
    action_ok = bool(cact) and (cact == action or cact.startswith(f"{action}@")
                                or cact.startswith(f"{action}/"))
    dims.append(match(action is not None, cact, action_ok))

    ver = at.get("version")
    dims.append(match(ver is not None, context.get("version"),
                      str(ver) == str(context.get("version"))))

    dims = [d for d in dims if d is not None]
    if not dims:
        return "applicable"        # unconstrained fact
    if "not-applicable" in dims:
        return "not-applicable"
    if "unknown" in dims:
        return "unknown"
    return "applicable"


def lookup(entries, *, platform=None, subject=None, topic=None, as_of=None,
           context=None, include_noncurrent=False):
    """Return matching entries as of ``as_of`` (default today), status- and
    applicability-aware. ``context`` is ``{product, event, action, version}``."""
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
        applicability = _applicability(e, context)
        out["applicability"] = applicability
        # A conclusion needs: active status, trusted confidence, AND a fact whose
        # scope actually applies to the assessed context. A disputed/candidate
        # entry, or one whose scope does not apply (or cannot be confirmed to),
        # may inform questions but must not close a chain.
        out["drives_conclusion"] = (
            status == "active"
            and e.get("confidence") in _ACTIVE_CONFIDENCES
            and applicability == "applicable")
        hits.append(out)
    hits.sort(key=lambda h: h.get("id") or "")
    return hits


def check_consistency(entries) -> dict:
    """Validate the pack SET as a coherent whole before it is trusted for reasoning.

    A verified snapshot is more than a bag of individually-valid entries: two
    active-authoritative entries must not contradict each other for an overlapping
    scope, a superseded entry must not still be active, and ``supersedes`` targets
    must exist. On any conflict the affected subjects fail closed — the assessor
    routes them to ``needs_review`` rather than letting either claim drive.
    """
    conflicts = []
    by_id = {}
    for e in entries:
        eid = e.get("id")
        if eid in by_id:
            conflicts.append({"kind": "duplicate-id", "id": eid})
        else:
            by_id[eid] = e

    superseded_ids = set()
    for e in entries:
        for sid in e.get("supersedes") or []:
            superseded_ids.add(sid)
            if sid not in by_id:
                conflicts.append({"kind": "dangling-supersedes",
                                  "id": e.get("id"), "target": sid})
    for sid in superseded_ids:
        tgt = by_id.get(sid)
        if tgt is not None and tgt.get("status") == "active":
            conflicts.append({"kind": "superseded-still-active", "id": sid})

    # Contradictory active-authoritative claims occupying the SAME single-valued
    # slot. A slot is declared explicitly via ``claim_key`` (e.g. the
    # pull_request_target fork-token default): two active-authoritative entries
    # with the same claim_key, overlapping scope, but different claims cannot both
    # be true. Complementary facts about one subject do NOT share a claim_key and
    # are never flagged — this avoids false positives while still catching the
    # classic poisoning shape ("X is writable" vs "X is read-only").
    # Any confidence that can drive a conclusion (authoritative OR corroborated)
    # must be checked — two contradictory *corroborated* entries would otherwise
    # both remain conclusion-driving. Keep this in lockstep with the confidence
    # gate in ``lookup`` (``_ACTIVE_CONFIDENCES``).
    active_auth = [e for e in entries
                   if e.get("status") == "active"
                   and e.get("confidence") in _ACTIVE_CONFIDENCES
                   and e.get("claim_key")]
    for i in range(len(active_auth)):
        for j in range(i + 1, len(active_auth)):
            a, b = active_auth[i], active_auth[j]
            if (a.get("claim_key") == b.get("claim_key")
                    and a.get("claim") != b.get("claim")
                    and _scopes_overlap(a, b)
                    and b.get("id") not in (a.get("supersedes") or [])
                    and a.get("id") not in (b.get("supersedes") or [])):
                conflicts.append({"kind": "contradictory-active",
                                  "ids": sorted([a.get("id"), b.get("id")]),
                                  "claim_key": a.get("claim_key")})
    return {"consistent": not conflicts, "conflicts": conflicts}


def _scopes_overlap(a: dict, b: dict) -> bool:
    """Two entries' applies_to scopes overlap if, for every dimension both
    constrain, the constraints intersect. Missing constraint = wildcard."""
    aa, ba = a.get("applies_to") or {}, b.get("applies_to") or {}
    for key in ("product", "action", "version"):
        av, bv = aa.get(key), ba.get(key)
        if av is not None and bv is not None and str(av) != str(bv):
            return False
    ae = set(aa.get("events") or [])
    be = set(ba.get("events") or [])
    if ae and be and not (ae & be):
        return False
    return True


def validate_snapshot(entries, registry) -> dict:
    """Validate that every entry in a verified snapshot satisfies the trust
    contract — not merely that the bytes match the attested pack hash.

    A pack hash proves *these are the released bytes*; it does not prove the
    bytes obey the policy the plane claims to enforce. The shipped bootstrap has
    already drifted here (an entry declaring a higher authority tier than the
    source registry assigns its URL). This is the deterministic gate that catches
    that class of drift: each entry must have its required fields and valid enums,
    each source's declared ``publisher``/``type``/``authority`` must match the
    registry's reclassification of the URL (never the value written in the pack),
    every source URL must be registry-allowed, and no entry may carry a
    secret-looking value. Facts, not verdicts: it returns the violations; the
    caller (``open_verified`` / the installer) decides to withhold trust.

    ``registry`` is the parsed package source registry — the classification root
    of trust — and MUST be loaded from the in-package snapshot, never from a
    refreshed snapshot that an attacker could shape.
    """
    import knowledge_compile as kc  # pure registry/enum helpers; no network
    import state                    # shared secret guard

    violations: list = []
    for e in entries:
        eid = e.get("id")
        pub = _public(e)
        for key in kc._VERIFIED_REQUIRED:
            if key not in pub:
                violations.append({"kind": "missing-field", "id": eid,
                                   "field": key})
        for field, allowed in (("kind", kc._KINDS), ("status", kc._STATUSES),
                               ("confidence", kc._CONFIDENCES),
                               ("effect", kc._EFFECTS)):
            if field in pub and pub.get(field) not in allowed:
                violations.append({"kind": "bad-enum", "id": eid,
                                   "field": field, "value": pub.get(field)})

        sources = pub.get("sources")
        if not isinstance(sources, list) or not sources:
            violations.append({"kind": "no-sources", "id": eid})
            sources = []
        for i, src in enumerate(sources):
            if not isinstance(src, dict):
                violations.append({"kind": "bad-source", "id": eid, "index": i})
                continue
            url = src.get("url")
            if not isinstance(url, str) or not url:
                violations.append({"kind": "source-no-url", "id": eid,
                                   "index": i})
                continue
            derived = kc.classify_source(url, registry)
            if not derived.get("allowed"):
                violations.append({"kind": "source-not-allowed", "id": eid,
                                   "index": i, "url": url,
                                   "reason": derived.get("reason")})
            for field, key in (("type", "type"), ("authority", "authority"),
                               ("publisher", "publisher")):
                if field in src and src.get(field) != derived.get(key):
                    violations.append({
                        "kind": "provenance-mismatch", "id": eid, "index": i,
                        "field": field, "declared": src.get(field),
                        "derived": derived.get(key)})

        for path, text in state._iter_string_paths(pub):
            if state.looks_like_secret(text):
                violations.append({"kind": "secret-in-entry", "id": eid,
                                   "path": path})

    return {"valid": not violations, "violations": violations}


def apply_freshness(hits, fresh) -> None:
    """Downgrade stale down-gate facts in place (the freshness dimension).

    Integrity and freshness are separate: a snapshot can be intact yet stale (past
    its manifest expiry — a freeze). A stale *mitigation* or *neutral* fact must
    not drive a conclusion, because a down-gate that has silently changed upstream
    would wrongly suppress a finding; those are routed to ``needs_review``. A
    *risk-increasing* fact may keep driving even when stale — failing toward more
    scrutiny is safe. Fresh snapshots are untouched. ``effect`` defaults to
    ``neutral`` when absent (conservative)."""
    if fresh is not False:  # fresh, or unknown (do not downgrade on unknown)
        return
    for h in hits:
        if h.get("effect", "neutral") != "risk-increasing" and h.get("drives_conclusion"):
            h["drives_conclusion"] = False
            h["freshness"] = "stale-downgraded"


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


def resolve_active_snapshot() -> str:
    """The knowledge root the assessor should read when none is given explicitly.

    Prefer a refreshed last-known-good snapshot: if persistent client state records
    a ``current`` snapshot that still exists on disk (and state is not corrupt),
    use it — ``verify_installed`` re-checks it against that same client-state
    attestation record before anything drives a conclusion. Otherwise fall back to
    the in-package bootstrap. Never raises; any error degrades to the bootstrap.
    """
    try:
        anchor = knowledge_verify.load_anchor()
        state = knowledge_verify.load_client_state(anchor)
        if knowledge_verify.state_is_corrupt(state):
            return _DEFAULT_KNOWLEDGE_ROOT
        cur = state.get("current") or {}
        path = cur.get("path")
        if (path and os.path.isdir(path)
                and os.path.exists(os.path.join(path, "manifest.json"))):
            return path
    except Exception:  # noqa: BLE001 — bootstrap is always a safe fallback
        pass
    return _DEFAULT_KNOWLEDGE_ROOT


def open_verified(knowledge_root=None, now=None):
    """The assessor-facing read path. Verify the snapshot BEFORE any entry can be
    returned as conclusion-driving, and validate the set is consistent.

    Returns ``(entries, verification, consistency)``. If verification fails, the
    returned entries carry ``drives_conclusion=false`` and a ``verification``
    marker so a poisoned/unverified snapshot cannot close a chain. If the set is
    inconsistent, conclusion-driving is likewise withheld (route to needs_review).
    This is the only path the assessor should use; ``load_packs`` is raw and is
    reserved for tests and the compiler.
    """
    auto = knowledge_root is None
    root = knowledge_root or resolve_active_snapshot()
    entries, verification, consistency, trusted = _open_at(root, now)
    # Resilient bundled fallback: when the caller did not pin a root and the
    # dynamically-resolved snapshot (a refreshed LKG) fails to verify, fall back to
    # the verified in-package bootstrap rather than returning an untrusted set. This
    # matches the documented behavior — a refreshed snapshot that goes bad degrades
    # to the last-known-good floor that shipped with the package.
    if auto and not trusted and os.path.abspath(root) != os.path.abspath(
            _DEFAULT_KNOWLEDGE_ROOT):
        b_entries, b_verification, b_consistency, b_trusted = _open_at(
            _DEFAULT_KNOWLEDGE_ROOT, now)
        if b_trusted:
            b_verification = dict(b_verification)
            b_verification.setdefault("warnings", [])
            b_verification["warnings"] = list(b_verification["warnings"]) + [
                f"active snapshot {root} failed verification; fell back to the "
                "in-package bootstrap"]
            b_verification["fell_back_to_bootstrap"] = True
            return b_entries, b_verification, b_consistency
    return entries, verification, consistency


def _open_at(root, now=None):
    """Verify + load a specific snapshot root. Returns
    ``(entries, verification, consistency, trusted)``. Never raises."""
    verification = knowledge_verify.verify_installed(knowledge_root=root, now=now)
    entries, summaries = load_packs(os.path.abspath(root))
    consistency = check_consistency(entries)
    # A pack that only partially parsed is a partially-consumed verified set: the
    # attested bytes did not fully load, so we cannot claim the snapshot is intact.
    # Treat it as inconsistent (fail closed) rather than silently reasoning over the
    # lines that happened to parse.
    partial = [s["pack"] for s in summaries if s.get("parse_partial")]
    if partial:
        consistency = dict(consistency)
        consistency["consistent"] = False
        consistency["conflicts"] = list(consistency.get("conflicts") or []) + [
            {"kind": "parse-partial", "pack": p} for p in partial]
    # Snapshot self-validation: the entries must obey the trust contract (schema,
    # registry-derived provenance, secret policy), not merely hash-match the
    # attested packs. The classification registry is the PACKAGE registry (the
    # root of trust), never one from a refreshed snapshot. If it cannot be loaded,
    # fail closed — an unvalidatable snapshot is not trustworthy.
    try:
        import knowledge_compile as kc
        registry = kc.load_registry(_DEFAULT_KNOWLEDGE_ROOT)
        snapshot = validate_snapshot(entries, registry)
    except Exception as exc:  # noqa: BLE001 — degrade to untrusted, never crash
        snapshot = {"valid": False,
                    "violations": [{"kind": "validate-error", "error": str(exc)}]}
    if not snapshot.get("valid"):
        consistency = dict(consistency)
        consistency["consistent"] = False
        consistency["conflicts"] = list(consistency.get("conflicts") or []) + [
            {"kind": "snapshot-invalid", "violations": snapshot["violations"]}]
    trusted = bool(verification.get("trusted")) and consistency.get("consistent")
    if not trusted:
        for e in entries:
            e["_untrusted"] = True
    return entries, verification, consistency, trusted


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def _resolve_root(args) -> str:
    root = args.knowledge_root or resolve_active_snapshot()
    if not os.path.isdir(root):
        raise KnowledgeError(f"knowledge root not found: {root}")
    return os.path.abspath(root)


def _context_from_args(args) -> dict:
    return {"product": getattr(args, "product", None),
            "event": getattr(args, "event", None),
            "action": getattr(args, "action", None),
            "version": getattr(args, "context_version", None)}


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
    if args.allow_unverified:
        entries, _ = load_packs(root)
        verification = {"trusted": None, "source": "unverified (--allow-unverified)"}
        consistency = check_consistency(entries)
    else:
        entries, verification, consistency = open_verified(
            knowledge_root=root, now=args.as_of)
    hits = lookup(entries, platform=args.platform, subject=args.subject,
                  topic=args.topic, as_of=args.as_of,
                  context=_context_from_args(args),
                  include_noncurrent=args.include_noncurrent)
    # Only an explicit, positive verification result may leave conclusions standing.
    # ``--allow-unverified`` sets ``trusted:None`` (verification skipped) — that path
    # surfaces facts for investigation but MUST NOT drive a conclusion, so ``None``
    # fails the gate exactly like ``False``.
    trusted = (verification.get("trusted") is True) and consistency.get("consistent")
    if not trusted:
        # Verification failed/skipped or the set is inconsistent: no entry may drive
        # a conclusion. Fail secure — surface the facts and withhold conclusion.
        for h in hits:
            h["drives_conclusion"] = False
    else:
        # Trusted but possibly stale: withhold conclusion from stale down-gate facts.
        apply_freshness(hits, verification.get("fresh"))
    out = {"verification": verification, "consistency": consistency, "hits": hits}
    print(json.dumps(out, indent=2, sort_keys=True))
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
                        help="find in-effect entries (temporal + status- + "
                             "applicability-aware; verified before use)")
    sp.add_argument("--platform")
    sp.add_argument("--subject")
    sp.add_argument("--topic", help="keyword matched in subject/claim")
    sp.add_argument("--as-of", help="YYYY-MM-DD; temporal query (default today)")
    # Assessment context — a fact drives a conclusion only if its applies_to scope
    # matches the situation being assessed.
    sp.add_argument("--product", help="e.g. github.com / GHES")
    sp.add_argument("--event", help="e.g. pull_request_target")
    sp.add_argument("--action", help="e.g. actions/checkout")
    sp.add_argument("--context-version", dest="context_version",
                    help="platform/action version of the assessed context")
    sp.add_argument("--include-noncurrent", action="store_true",
                    help="also return superseded/retired/draft entries")
    sp.add_argument("--allow-unverified", action="store_true",
                    help="skip the verification gate (tests/tooling ONLY; never "
                         "for assessment)")
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
