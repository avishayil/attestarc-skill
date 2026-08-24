#!/usr/bin/env python3
"""AttestArc Updater — deterministic pieces of the knowledge-refresh pipeline.

The refresh workflow is a **separate principal** from the assessor. It is the
only mode with network access, and even then only through the host's fetch tool
against the fixed allowlist in ``knowledge/sources.yaml``. This helper never
fetches; it provides the *deterministic* steps the host orchestrates around its
LLM slot-extraction:

    host WebFetch (allowlisted)          <- host, not this tool
      -> quarantine        (this tool: store raw doc + self-verifying receipt)
      -> host slot-extract to a *candidate* entry          <- host LLM
      -> check-source      (this tool: registry authority, never model-chosen)
      -> validate-candidate(this tool: candidate schema + provenance + secrets)
      -> conflict          (this tool: contradiction vs an IMMUTABLE baseline)
      -> may-promote       (this tool: deterministic promotion-tier decision)
      -> promote           (this tool: assigns status/confidence — policy, not LLM)

The model produces a **candidate** (``schemas/knowledge-candidate.schema.json``):
it never declares the trusted ``status``/``confidence`` fields, and it never
declares a source's ``publisher``/``type``/``authority`` — those are DERIVED from
the source registry. Only the deterministic policy here, in ``promote_to_verified``
gated by ``may_promote``, emits a trusted ``VerifiedKnowledgeEntry``
(``schemas/knowledge.schema.json``). The model may ``propose``; it may never
``promote``.

Every step emits **facts**. Promotion-tier decisions follow
``core/promotion-policy.md`` (a root-of-trust file). Conflict and semantic-diff are
always computed against an **immutable baseline** — the last verified released
snapshot, never the working tree that carries the proposal — so a proposal cannot
launder itself by editing the file it is compared against.

Stdlib-only. No target-repository access; no kernel or knowledge write beyond the
quarantine directory the caller names.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import posixpath
import subprocess
import sys
from urllib.parse import urlsplit

import state  # reuse the shared secret guard

_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_KNOWLEDGE_ROOT = os.path.join(_PACKAGE_ROOT, "knowledge")

# Source types that can never auto-promote: they are recorded as candidate only
# (blog/issue/researcher/forum/model). See promotion-policy.md.
_NEVER_AUTO_TYPES = ("research", "issue", "community", "arbitrary-web")

# A *candidate* entry (what the model produces) — kept in parity with
# schemas/knowledge-candidate.schema.json. It deliberately OMITS the trusted
# ``status``/``confidence`` fields; those are ASSIGNED by promote_to_verified,
# never declared by the model (a candidate carrying them is a structural error).
_CANDIDATE_REQUIRED = ("id", "kind", "platform", "subject", "claim",
                       "valid_from", "sources")
_CANDIDATE_ALLOWED_TOP = _CANDIDATE_REQUIRED + (
    "claim_key", "applies_to", "expires", "supersedes", "effect",
    "compiler", "extensions")
# Trusted fields the model may never declare on a candidate.
_PROMOTION_ASSIGNED = ("status", "confidence")
# A *verified* entry (what promotion emits / what a released snapshot contains) —
# in parity with schemas/knowledge.schema.json. It DOES carry the trusted
# status/confidence fields. Used by knowledge.validate_snapshot to check the
# installed snapshot on the assessor read path.
_VERIFIED_REQUIRED = _CANDIDATE_REQUIRED + ("status", "confidence")
_KINDS = ("platform-semantics", "api", "standard", "guidance")
_STATUSES = ("active", "superseded", "disputed", "retired", "draft")
_CONFIDENCES = ("authoritative", "corroborated", "candidate")
_EFFECTS = ("mitigation", "risk-increasing", "neutral")
# A promotion-eligible source must carry a URL and be bound to a quarantined
# object by a RESOLVABLE, self-verifying ``receipt_id``. publisher/type/authority
# are DERIVED from the URL via the registry, never trusted from the candidate.
_SOURCE_REQUIRED = ("url",)


class CompileError(Exception):
    pass


# --------------------------------------------------------------------------- #
# canonical digests — bind a decision/eval-result to the EXACT bytes it covers
# --------------------------------------------------------------------------- #
def canonical_entry_digest(entry: dict) -> str:
    """Stable sha256 of a knowledge entry, independent of key order/whitespace.

    Runtime-only ``_``-prefixed fields are excluded so an entry's identity is its
    shipped content. Used to bind a promotion decision / eval-result to the exact
    entry it was made over — an edit to the entry changes the digest, so a stale
    decision no longer covers it (verify-promotions fails closed)."""
    clean = {k: v for k, v in (entry or {}).items() if not k.startswith("_")}
    blob = json.dumps(clean, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def eval_corpus_digest(corpus_root: str) -> str:
    """Digest of the trusted eval corpus (``evals/cases/*.yaml``), order-independent.

    Binds an eval-result to the exact corpus it was judged under: a result produced
    against a weakened/edited corpus does not match a later, restored corpus (and
    vice-versa). Each file contributes ``<relpath>\\n<bytes>`` so a rename is also a
    change. Missing corpus → empty-string digest sentinel (still deterministic)."""
    cases_dir = os.path.join(corpus_root, "cases")
    files = sorted(glob.glob(os.path.join(cases_dir, "*.yaml")))
    h = hashlib.sha256()
    for path in files:
        rel = os.path.relpath(path, corpus_root)
        h.update(rel.encode("utf-8"))
        h.update(b"\n")
        try:
            with open(path, "rb") as fh:
                h.update(fh.read())
        except OSError as exc:
            raise CompileError(f"cannot read eval corpus file {rel}: {exc}")
        h.update(b"\n")
    return h.hexdigest()


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
    # Collapse dot-segments BEFORE prefix matching so a traversal like
    # ``/actions/../evil`` becomes ``/evil`` and fails the trusted-prefix test —
    # a candidate cannot smuggle a trusted org/repo prefix past classification.
    raw_path = parts.path or "/"
    upath = posixpath.normpath(raw_path)
    if raw_path.endswith("/") and not upath.endswith("/"):
        upath += "/"
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
    """Deterministic receipt id derived from the FULL stored content hash.

    The full sha256 is used (not a truncated prefix) so a receipt id is not
    forgeable by finding a shorter collision, and so ``resolve_receipt`` can
    locate the backing ``.raw`` object directly from the id's hash.
    """
    return "QR-" + content_hash


def _origin(url: str) -> tuple:
    """(scheme, host) of a URL, lower-cased — the origin trust is bound to."""
    parts = urlsplit(url or "")
    return ((parts.scheme or "").lower(), (parts.hostname or "").lower())


def quarantine(raw: str, url: str, out_dir: str, registry: dict,
               retrieved_at: str, requested_url: str = None,
               redirect_chain: list = None) -> dict:
    """Store a fetched document under ``out_dir`` keyed by content hash and emit a
    self-verifying **provenance receipt**.

    The raw doc is treated as untrusted input: it is stored, hashed, and
    classified, but never parsed as instructions. Extraction happens later, in
    the host LLM step, over this quarantined copy. The receipt — not the model —
    is the authority for ``publisher``/``source_type``/``authority``/
    ``content_hash``/``retrieved_at``; a candidate references it by ``receipt_id``
    and ``validate_candidate`` resolves provenance from it. The LLM never
    populates those fields.

    Redirect provenance is supplied by the host fetch adapter: ``url`` is the
    **final** URL the bytes were served from (what we classify), ``requested_url``
    is what the fetch started at (defaults to ``url``), and ``redirect_chain`` is
    the ordered list of hop URLs (defaults to ``[]``). A redirect that crosses
    **origin** (scheme+host) off the final origin is not trusted: the receipt is
    stored but marked ``allowed=False`` with a reason, so it can never back a
    promotion. Trust follows the final origin, not the requested one.

    ``retrieved_at`` is supplied by the caller (the fetch step) rather than read
    from the clock here, keeping this helper deterministic.
    """
    content_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    os.makedirs(out_dir, exist_ok=True)
    stored = os.path.join(out_dir, f"{content_hash}.raw")
    with open(stored, "w", encoding="utf-8") as fh:
        fh.write(raw)
    fact = classify_source(url, registry)
    allowed = bool(fact.get("allowed", False))
    reason = fact.get("reason")

    requested_url = requested_url or url
    redirect_chain = list(redirect_chain or [])
    # Any hop whose origin differs from the final origin is a cross-origin
    # redirect: an allowlisted URL that bounces off-origin cannot be trusted.
    final_origin = _origin(url)
    cross = sorted({hop for hop in redirect_chain + [requested_url]
                    if _origin(hop) != final_origin})
    if allowed and cross:
        allowed = False
        reason = (f"cross-origin redirect off the final origin: {cross}; "
                  f"a redirect that changes scheme/host is not trusted")

    receipt = {
        "_type": "attestarc-quarantine-receipt",
        "receipt_id": _receipt_id(content_hash),
        "requested_url": requested_url,
        "final_url": url,
        "redirect_chain": redirect_chain,
        "publisher": fact.get("publisher"),
        "source_type": fact.get("type"),
        "authority": fact.get("authority") if allowed else 0,
        "allowed": allowed,
        "content_hash": content_hash,
        "retrieved_at": retrieved_at,
        "bytes": len(raw),
        "stored_path": stored,
    }
    if reason:
        receipt["reason"] = reason
    receipt_path = os.path.join(out_dir, f"{content_hash}.receipt.json")
    with open(receipt_path, "w", encoding="utf-8") as fh:
        json.dump(receipt, fh, indent=2, sort_keys=True)
    receipt["receipt_path"] = receipt_path
    return receipt


def resolve_receipt(receipt_id: str, quarantine_dir: str,
                    registry: dict = None) -> dict | None:
    """Load a quarantine receipt by id and **self-verify** it. Returns None if the
    directory/receipt is absent or the receipt fails verification.

    Verification (fail-closed — any failure returns None, never a partial):
      - the backing ``<content_hash>.raw`` exists and **rehashes** to the
        receipt's ``content_hash`` (a fabricated receipt whose ``.raw`` does not
        rehash — or is missing — does not resolve); and
      - when a ``registry`` is supplied, the receipt's stored
        ``authority``/``source_type`` still match a fresh classification of its
        ``final_url`` (a receipt cannot claim an authority the registry would not
        grant today), and it is ``allowed``.
    """
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
        if not (isinstance(rec, dict) and rec.get("receipt_id") == receipt_id):
            continue

        # Self-verify: the receipt's content_hash must match the actual bytes.
        content_hash = rec.get("content_hash")
        if not isinstance(content_hash, str) or not content_hash:
            return None
        raw_path = os.path.join(quarantine_dir, f"{content_hash}.raw")
        try:
            with open(raw_path, "rb") as fh:
                actual = hashlib.sha256(fh.read()).hexdigest()
        except OSError:
            return None
        if actual != content_hash:
            return None  # tampered/fabricated: bytes do not rehash to the id

        # Re-derive classification of the final URL when a registry is given.
        if registry is not None:
            derived = classify_source(rec.get("final_url", ""), registry)
            if not derived.get("allowed"):
                return None
            if (rec.get("authority") != derived.get("authority")
                    or rec.get("source_type") != derived.get("type")):
                return None
        return rec
    return None


# --------------------------------------------------------------------------- #
# validate-candidate
# --------------------------------------------------------------------------- #
def validate_candidate(candidate: dict, registry: dict,
                       quarantine_dir: str = None) -> dict:
    """Candidate-schema + provenance + secret checks over an extracted entry.

    Validates against the **candidate** contract
    (``schemas/knowledge-candidate.schema.json``), NOT the verified one:

      - The trusted ``status``/``confidence`` fields are **assigned by promotion**,
        never declared by the model — a candidate carrying either is a structural
        error (``_PROMOTION_ASSIGNED``).
      - Every source URL is **reclassified** through the registry: the derived
        publisher/type/authority are authoritative and any declared value that
        disagrees is an error (the model never chooses authority).
      - Every **promotion-eligible** source (allowlisted origin) must be bound to
        a quarantined object by a ``receipt_id`` that **resolves and self-verifies**
        in ``quarantine_dir`` (its ``.raw`` rehashes to the receipt hash). An
        inline ``content_hash`` alone is NOT sufficient for a promotion-eligible
        source — the fetched bytes must actually exist and match.

    The returned ``max_authority`` and per-source ``receipts`` feed
    ``promote_to_verified`` so promotion copies provenance from the verified
    receipt, not from the model's declarations.
    """
    errors: list = []
    warnings: list = []

    if not isinstance(candidate, dict):
        return {"valid": False, "errors": ["candidate is not an object"],
                "warnings": [], "max_authority": 0, "receipts": {}}

    # Trusted fields are promotion-assigned, never model-declared.
    for key in _PROMOTION_ASSIGNED:
        if key in candidate:
            errors.append(
                f"candidate declares {key!r}; {key} is assigned by promotion, "
                f"never by the model (see knowledge-candidate.schema.json)")

    for key in _CANDIDATE_REQUIRED:
        if key not in candidate:
            errors.append(f"missing required field: {key}")
    extra = set(candidate) - set(_CANDIDATE_ALLOWED_TOP)
    if extra:
        errors.append(f"unknown fields (not in candidate schema): {sorted(extra)}")

    kid = candidate.get("id", "")
    if not (isinstance(kid, str) and kid.startswith("KE-")
            and all(c.islower() or c.isdigit() or c == "-" for c in kid[3:])):
        errors.append(f"id must match ^KE-[a-z0-9-]+$: {kid!r}")
    if candidate.get("kind") not in _KINDS:
        errors.append(f"kind not in {_KINDS}: {candidate.get('kind')!r}")
    if "effect" in candidate and candidate.get("effect") not in _EFFECTS:
        errors.append(f"effect not in {_EFFECTS}: {candidate.get('effect')!r}")

    sources = candidate.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append("sources must be a non-empty array")
        sources = []
    max_authority = 0
    receipts: dict = {}
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
        promotion_eligible = bool(derived.get("allowed"))
        if not promotion_eligible:
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

        # Provenance binding: a promotion-eligible source MUST carry a resolvable,
        # self-verifying receipt_id. Inline content_hash alone does not suffice.
        rid = src.get("receipt_id")
        receipt = resolve_receipt(rid, quarantine_dir, registry) if rid else None
        if rid and receipt is None:
            errors.append(
                f"sources[{i}] receipt_id {rid!r} does not resolve to a "
                f"self-verifying quarantine receipt (missing, tampered, or "
                f"its stored bytes do not rehash to the receipt hash)")
        if receipt is not None:
            if src.get("content_hash") is not None \
                    and receipt.get("content_hash") != src.get("content_hash"):
                errors.append(
                    f"sources[{i}] content_hash disagrees with receipt {rid!r}")
            if receipt.get("final_url") != url:
                errors.append(
                    f"sources[{i}] url disagrees with receipt {rid!r} final_url")
            receipts[str(i)] = receipt
            max_authority = max(max_authority, receipt.get("authority", 0))
        elif promotion_eligible:
            errors.append(
                f"sources[{i}] is promotion-eligible but is not bound to a "
                f"resolvable receipt_id; a fetched, self-verified quarantine "
                f"object is required (inline content_hash is not sufficient)")

    # Secret guard: no secret value may enter the learning pipeline.
    for path, text in state._iter_string_paths(candidate):
        if state.looks_like_secret(text):
            errors.append(f"{path} appears to contain a secret value; secrets "
                          "must never enter the knowledge pipeline")

    return {"valid": not errors, "errors": errors, "warnings": warnings,
            "max_authority": max_authority, "receipts": receipts}


# --------------------------------------------------------------------------- #
# conflict
# --------------------------------------------------------------------------- #
def find_conflicts(candidate: dict, existing: list) -> dict:
    """Report existing *active, authoritative* entries that share the candidate's
    (platform, subject) but assert a different claim — a contradiction to
    adjudicate (the loser becomes ``disputed``).

    ``existing`` is the **immutable baseline** — the last verified released
    snapshot — never the working tree that carries the proposal."""
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
# semantic diff + derived security direction (never model-declared)
# --------------------------------------------------------------------------- #
# The comparable semantic fields of an entry. ``status``/``confidence`` are NOT
# compared — a candidate does not carry them (they are promotion-assigned).
_SEMANTIC_FIELDS = ("claim", "claim_key", "applies_to", "effect")


def semantic_diff(candidate: dict, baseline_entries: list) -> dict:
    """Classify a candidate against the immutable baseline as ``added`` /
    ``modified`` / ``unchanged``, and flag whether it touches an **active security
    semantic**.

    A candidate is a single proposed entry, so it can ``add`` a new id or
    ``modify`` an existing one; it never itself ``removes`` (removal is expressed
    by superseding). The key gap this closes: an *additive edit* of an existing
    active entry — same id, changed claim, but WITHOUT writing ``supersedes`` —
    is still a modification of established security semantics and must route to
    review. Superseding an active baseline entry counts too.
    """
    baseline = {e.get("id"): e for e in (baseline_entries or [])
                if isinstance(e, dict)}
    cid = candidate.get("id")
    prior = baseline.get(cid)
    changed_fields = []
    change = "added"
    if prior is not None:
        for f in _SEMANTIC_FIELDS:
            if candidate.get(f) != prior.get(f):
                changed_fields.append(f)
        change = "modified" if changed_fields else "unchanged"
    superseded_active = sorted(
        sid for sid in (candidate.get("supersedes") or [])
        if isinstance(baseline.get(sid), dict)
        and baseline[sid].get("status") == "active")
    modifies_active_security = bool(
        (change == "modified" and (prior or {}).get("status") == "active")
        or superseded_active)
    return {"change": change, "changed_fields": sorted(changed_fields),
            "prior": prior, "superseded_active": superseded_active,
            "modifies_active_security": modifies_active_security}


def derive_direction(candidate: dict, diff: dict) -> dict:
    """Derive a conservative security-regression **direction** deterministically —
    NEVER trusting a candidate's self-declared direction. Returns
    ``{"direction": negative|neutral|positive|uncertain, "security_negative": bool}``.

    Rules (fail toward scrutiny):
      - A new ``mitigation`` claim is a new down-gate that could suppress a
        finding → ``negative``.
      - Modifying an existing active entry AWAY from ``risk-increasing`` toward
        ``mitigation``/``neutral`` lowers scrutiny → ``negative``.
      - Any *other* modification of an existing active security semantic is
        ``uncertain`` (we cannot prove it is safe) → treated as security-negative.
      - A new ``risk-increasing`` claim raises scrutiny → ``positive``.
      - Otherwise ``neutral``.

    ``security_negative`` is true for ``negative`` and ``uncertain``; the promotion
    policy routes both to review.
    """
    effect = candidate.get("effect")
    prior = diff.get("prior") or {}
    change = diff.get("change")

    if change == "modified" and (prior or {}).get("status") == "active":
        if prior.get("effect") == "risk-increasing" and effect in (
                "mitigation", "neutral", None):
            direction = "negative"
        else:
            direction = "uncertain"
    elif effect == "mitigation":
        direction = "negative"
    elif effect == "risk-increasing":
        direction = "positive"
    else:
        direction = "neutral"

    return {"direction": direction,
            "security_negative": direction in ("negative", "uncertain")}


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
    "schemas/knowledge.schema.json",
    "schemas/knowledge-candidate.schema.json",
    "schemas/knowledge-manifest.schema.json",
    "schemas/learning-candidate.schema.json",
    "schemas/eval-result.schema.json",
    ".github/workflows/release-knowledge.yml",
)

# Directory prefixes whose contents are all root-of-trust: editing a committed
# promotion decision (or the bootstrap approval) changes what a release will ship
# as trusted, so it is a two-party-review event just like the files above.
_ROOT_OF_TRUST_PREFIXES = ("knowledge/promotions/",)


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
    rot_hits = sorted({p for p in normed
                       if p in _ROOT_OF_TRUST
                       or any(p.startswith(pre) for pre in _ROOT_OF_TRUST_PREFIXES)})
    eval_hits = sorted({p for p in normed if p.startswith("evals/")})
    return {
        "changes_root_of_trust": bool(rot_hits),
        "root_of_trust_paths": rot_hits,
        "touches_eval": bool(eval_hits),
        "eval_paths": eval_hits,
    }


def may_promote(candidate: dict, facts: dict, registry: dict = None,
                baseline_entries: list = None, validation: dict = None) -> dict:
    """Return the promotion tier per core/promotion-policy.md. Never promotes.

    Everything is **derived**, never asserted by the caller as a bare flag:
      - ``validation`` is the result of ``validate_candidate``. A candidate that
        has NOT passed validation is not promotable at all — this returns
        ``never-auto`` and refuses to reason further (fail closed). Pass it in;
        omitting it is allowed only for legacy callers that pre-validated.
      - ``max_authority`` / source ``types`` come from reclassifying the
        candidate's source URLs through ``registry``.
      - ``has_conflict`` and the semantic diff come from the **immutable
        baseline** (``baseline_entries`` — the last verified released snapshot),
        never the working tree.
      - The security **direction** is derived (``derive_direction``), never taken
        from the candidate.
      - ``changes_root_of_trust`` / ``weakens_eval`` come from the actual diff
        (``facts['change_paths']`` / ``facts['removed_or_modified_evals']``).
      - ``eval_result`` is the eval-run artifact; ``signature_valid`` is the
        attestation result for a *published* pack.

    Core rule: knowledge that adds a new, non-superseding claim from an
    authoritative source, with passing evals, can auto-promote. Anything that
    changes an existing active security semantic — a supersession, a conflict, an
    additive edit of an active entry, a security-negative/uncertain direction, an
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

    # A candidate must have passed validation before it can be promoted at all.
    if validation is not None and not validation.get("valid"):
        return {"tier": "never-auto",
                "reasons": ["candidate did not pass validate_candidate; it is "
                            "not promotable (fail closed)"],
                "derived": {"validated": False}}

    sources = candidate.get("sources") or []
    if registry is not None:
        classified = [classify_source(s.get("url", ""), registry)
                      for s in sources if isinstance(s, dict)]
        types = {c.get("type") for c in classified}
        max_authority = max([c.get("authority", 0) for c in classified] or [0])
    else:
        types = {s.get("type") for s in sources if isinstance(s, dict)}
        max_authority = facts.get("max_authority", 0)

    # Conflict + semantic diff are derived from the IMMUTABLE baseline.
    if baseline_entries is not None:
        has_conflict = find_conflicts(candidate, baseline_entries)["has_conflict"]
    else:
        has_conflict = bool(facts.get("has_conflict"))
    diff = semantic_diff(candidate, baseline_entries or [])
    direction = derive_direction(candidate, diff)

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

    # Require-review: alters an existing active semantic.
    if candidate.get("supersedes"):
        demote("require-review",
               "supersedes an existing active claim; a change to established "
               "security semantics, not new knowledge")
    if has_conflict:
        demote("require-review",
               "conflicts with an existing authoritative entry; adjudicate "
               "(-> disputed until resolved)")
    if diff["modifies_active_security"]:
        demote("require-review",
               f"modifies an existing active security semantic "
               f"(change={diff['change']}, fields={diff['changed_fields']}, "
               f"superseded_active={diff['superseded_active']}); an additive edit "
               f"of an active entry routes to review even without 'supersedes'")
    if direction["security_negative"]:
        demote("require-review",
               f"derived security direction is {direction['direction']!r} "
               f"(security-negative/uncertain lowers scrutiny; fail toward review)")

    # Auto-promote gate: content eligibility (NOT distribution trust).
    if tier == "auto-promote":
        ev = facts.get("eval_result")
        # The eval-result must be BOUND to this candidate + baseline + corpus
        # (``_bound`` is set only by _load_eval_result_verified after it recomputes
        # and matches all three digests). A bare {"passed": true}, or a passing
        # result recycled from another change, carries no ``_bound`` and fails
        # closed — passing alone is necessary but not sufficient.
        if not (isinstance(ev, dict) and ev.get("passed") is True
                and ev.get("_bound") is True):
            demote("require-review",
                   "eval-result artifact is missing, not passing, or not bound to "
                   "this candidate/baseline/corpus (fail closed)")
        # signature_valid: content-promotion eligibility is separate from
        # distribution trust. A None signature means "not attested yet" (the
        # attestation is applied at release and verified at runtime) and MUST NOT
        # read as valid; only a genuine FAILED attestation over a published pack
        # blocks here.
        if facts.get("signature_valid") is False:
            demote("require-review",
                   "attestation over the published pack failed")

    if tier == "auto-promote":
        reasons.append("authoritative source + new (non-superseding) knowledge + "
                       "no conflict + non-negative direction + evals pass: "
                       "eligible for auto-promotion")
    return {"tier": tier, "reasons": reasons,
            "derived": {"validated": None if validation is None else True,
                        "max_authority": max_authority,
                        "has_conflict": has_conflict,
                        "change": diff["change"],
                        "modifies_active_security": diff["modifies_active_security"],
                        "direction": direction["direction"],
                        "changes_root_of_trust": change["changes_root_of_trust"],
                        "weakens_eval": weakens_eval,
                        "supersedes": bool(candidate.get("supersedes"))}}


# --------------------------------------------------------------------------- #
# promote — deterministic assignment of trusted status/confidence (policy)
# --------------------------------------------------------------------------- #
def promote_to_verified(candidate: dict, validation: dict,
                        registry: dict) -> dict:
    """Emit a trusted ``VerifiedKnowledgeEntry`` from a validated candidate.

    Pure and deterministic. The caller must only invoke this on an ``auto-promote``
    tier (``may_promote``); it assigns the trusted fields the model may never
    declare:
      - ``status = "active"``.
      - ``confidence`` derived from source authority: ``corroborated`` when two or
        more *independent origins* at authority >= 90 agree, else ``authoritative``
        (a single authoritative source). Authority below 90 never reaches here.
      - each ``source`` is rewritten with the registry-/receipt-derived
        ``publisher``/``type``/``authority``/``content_hash``/``retrieved_at`` —
        provenance comes from the self-verified receipt, never the model.
    """
    receipts = (validation or {}).get("receipts", {})
    verified = {k: v for k, v in candidate.items()
                if k not in _PROMOTION_ASSIGNED}

    high_origins = set()
    new_sources = []
    for i, src in enumerate(candidate.get("sources") or []):
        if not isinstance(src, dict):
            continue
        derived = classify_source(src.get("url", ""), registry)
        receipt = receipts.get(str(i)) or {}
        authority = receipt.get("authority", derived.get("authority", 0))
        if authority >= 90:
            high_origins.add(_origin(src.get("url", "")))
        new_sources.append({
            "url": src.get("url"),
            "publisher": derived.get("publisher"),
            "type": derived.get("type"),
            "authority": authority,
            "content_hash": receipt.get("content_hash"),
            "retrieved_at": receipt.get("retrieved_at"),
        })
    verified["sources"] = new_sources
    verified["status"] = "active"
    verified["confidence"] = ("corroborated" if len(high_origins) >= 2
                              else "authoritative")
    return verified


# --------------------------------------------------------------------------- #
# evaluate — the single, unskippable orchestrator
# --------------------------------------------------------------------------- #
def evaluate_candidate(candidate: dict, registry: dict, quarantine_dir: str,
                       baseline_entries: list, eval_result: dict,
                       change_facts: dict = None) -> dict:
    """Run the full deterministic pipeline in order and return one structured
    result: validate -> conflict -> semantic diff -> direction -> may-promote.

    ``may_promote`` is fed the ``validation`` object, so an unvalidated candidate
    cannot skip the gate. This is the single entry point the host should call;
    the individual steps remain exposed for the CLI and for testing.
    """
    validation = validate_candidate(candidate, registry,
                                    quarantine_dir=quarantine_dir)
    conflicts = find_conflicts(candidate, baseline_entries or [])
    diff = semantic_diff(candidate, baseline_entries or [])
    direction = derive_direction(candidate, diff)
    change_facts = dict(change_facts or {})
    change_facts["eval_result"] = eval_result
    promotion = may_promote(candidate, change_facts, registry=registry,
                            baseline_entries=baseline_entries,
                            validation=validation)
    return {"validation": validation, "conflicts": conflicts,
            "semantic_diff": diff, "direction": direction,
            "promotion": promotion}


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


_EVAL_RESULT_REQUIRED = ("_type", "candidate_sha256", "baseline_manifest_sha256",
                         "eval_corpus_sha256", "cases", "passed", "failures",
                         "runner", "evaluated_at")


def bind_eval_result(result: dict, candidate: dict, baseline_manifest_sha256: str,
                     corpus_root: str) -> dict:
    """Verify an eval-result is BOUND to the exact inputs it claims, in code.

    Recomputes the candidate and eval-corpus digests and compares the baseline
    manifest digest; the result is trusted (``_bound: True``) ONLY when all three
    match, the shape is complete (``schemas/eval-result.schema.json``), and
    ``passed`` is a real pass (``passed is True`` with no ``failures``). Any
    mismatch sets ``_bound: False`` and records ``_bind_errors`` — ``may_promote``
    then fails the eval gate closed. This is what stops a bare ``{"passed": true}``
    or a passing result recycled from another candidate/baseline/corpus.

    Not an eval-runner: it never executes cases. It binds a supplied judgement to a
    supplied change."""
    errors: list = []
    if not isinstance(result, dict):
        return {"_bound": False, "_bind_errors": ["eval-result is not an object"],
                "passed": False}
    out = dict(result)
    for key in _EVAL_RESULT_REQUIRED:
        if key not in result:
            errors.append(f"eval-result missing required field: {key}")
    if result.get("_type") not in (None, "attestarc-eval-result"):
        errors.append("eval-result _type is not 'attestarc-eval-result'")

    want_candidate = canonical_entry_digest(candidate)
    if result.get("candidate_sha256") != want_candidate:
        errors.append(
            f"candidate_sha256 does not bind this candidate "
            f"(result={result.get('candidate_sha256')!r} expected={want_candidate!r})")
    if result.get("baseline_manifest_sha256") != baseline_manifest_sha256:
        errors.append(
            f"baseline_manifest_sha256 does not bind the baseline used "
            f"(result={result.get('baseline_manifest_sha256')!r} "
            f"expected={baseline_manifest_sha256!r})")
    want_corpus = eval_corpus_digest(corpus_root)
    if result.get("eval_corpus_sha256") != want_corpus:
        errors.append(
            f"eval_corpus_sha256 does not bind the trusted corpus "
            f"(result={result.get('eval_corpus_sha256')!r} expected={want_corpus!r})")

    passed = result.get("passed") is True and not (result.get("failures") or [])
    out["passed"] = passed
    if not passed:
        errors.append("eval-result is not a clean pass (passed!=true or failures)")
    out["_bound"] = not errors
    out["_bind_errors"] = errors
    return out


def _load_eval_result_verified(path, candidate, baseline_manifest_sha256,
                               corpus_root):
    """Load the eval-result artifact and bind it to (candidate, baseline, corpus).

    Returns None when no path is given so ``may_promote`` fails closed. When a path
    is given the JSON is loaded and passed through ``bind_eval_result``; the returned
    dict carries ``_bound``/``_bind_errors`` so an unbound artifact never satisfies
    the auto-promote gate."""
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise CompileError(f"cannot read eval-result artifact: {exc}")
    return bind_eval_result(raw, candidate, baseline_manifest_sha256, corpus_root)


def _git_diff_name_status(baseline_commit: str) -> list:
    """Return ``git diff --name-status <baseline_commit> HEAD`` rows, or raise."""
    try:
        out = subprocess.run(
            ["git", "diff", "--name-status", "--no-renames",
             f"{baseline_commit}", "HEAD"],
            capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise CompileError(f"git diff against {baseline_commit!r} failed: {exc}")
    rows = []
    for line in out.splitlines():
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            rows.append((parts[0].strip(), parts[-1].strip()))
    return rows


def derive_change_facts(baseline_commit: str) -> dict:
    """Derive the diff facts the promotion policy reads FROM GIT, not caller flags.

    ``--no-renames`` is used so a rename surfaces as a delete + add — a deleted eval
    is a weakening regardless of where it moved. ``change_paths`` is every touched
    path; ``removed_or_modified_evals`` is every ``evals/`` path deleted (``D``) or
    modified (``M``) — an *added* eval is not a weakening. Deriving this in code
    closes the hole where a caller could simply omit ``--change-path`` for the file
    that carries the poisoning edit."""
    rows = _git_diff_name_status(baseline_commit)

    def norm(p):
        return p.lstrip("./")

    change_paths = sorted({norm(p) for _, p in rows})
    removed_or_modified_evals = sorted({
        norm(p) for status, p in rows
        if norm(p).startswith("evals/") and status[:1] in ("D", "M")})
    return {"change_paths": change_paths,
            "removed_or_modified_evals": removed_or_modified_evals}


def _baseline_manifest_sha256(baseline_root: str) -> str:
    """sha256 of a baseline knowledge root's manifest.json — the digest an
    eval-result binds to and a decision records."""
    path = os.path.join(baseline_root, "manifest.json")
    try:
        with open(path, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError as exc:
        raise CompileError(f"cannot read baseline manifest {path}: {exc}")


def resolve_verified_baseline(package_root=None):
    """Resolve the installed **verified** snapshot as the promotion baseline.

    Returns ``(entries, manifest_sha256, knowledge_root)``. Fails closed if no
    snapshot is trusted — a promotion is never judged against an unverified (or
    working-tree) baseline. Uses ``knowledge_verify.verify_installed`` so the
    baseline is exactly what the assessor would trust."""
    import knowledge_verify  # local import; shares scripts/
    res = knowledge_verify.verify_installed(package_root=package_root)
    if not res.get("trusted"):
        raise CompileError(
            f"no trusted verified snapshot to use as a baseline "
            f"(source={res.get('source')!r}); refusing to promote against an "
            f"unverified baseline")
    root = res.get("knowledge_root")
    return (_load_existing(root), res.get("manifest_sha256"), root)


def _corpus_root(args) -> str:
    return getattr(args, "corpus_root", None) or os.path.join(_PACKAGE_ROOT, "evals")


def _resolve_baseline(args):
    """Resolve the immutable baseline. ``--baseline-verified`` resolves the
    installed verified snapshot; otherwise ``--baseline <root>`` is REQUIRED — the
    working tree is never an implicit baseline. Returns (entries, manifest_sha256)."""
    if getattr(args, "baseline_verified", False):
        entries, digest, _ = resolve_verified_baseline()
        return entries, digest
    if not args.baseline:
        raise CompileError(
            "a baseline is required: pass --baseline <knowledge-root> (the "
            "immutable last-released snapshot) or --baseline-verified (resolve the "
            "installed verified snapshot). The working tree is never the baseline.")
    return _load_existing(args.baseline), _baseline_manifest_sha256(args.baseline)


def _resolve_change_facts(args) -> dict:
    """Diff facts derived FROM GIT by default (``--baseline-commit``). The caller
    flags are honored only behind ``--trust-caller-diff`` — explicitly untrusted,
    for unit tests — because a caller could otherwise omit the path carrying a
    poisoning edit."""
    if getattr(args, "trust_caller_diff", False):
        return {"change_paths": args.change_path or [],
                "removed_or_modified_evals": (args.removed_eval or [])
                                             + (args.modified_eval or [])}
    if not getattr(args, "baseline_commit", None):
        raise CompileError(
            "pass --baseline-commit <rev> so the diff is derived from git, or "
            "--trust-caller-diff (untrusted; tests only) with explicit "
            "--change-path/--removed-eval/--modified-eval flags")
    return derive_change_facts(args.baseline_commit)


def _build_facts(args, candidate, baseline_manifest_sha256) -> dict:
    facts = _resolve_change_facts(args)
    facts["signature_valid"] = (None if args.signature is None
                                else args.signature == "valid")
    facts["eval_result"] = _load_eval_result_verified(
        getattr(args, "eval_result", None), candidate,
        baseline_manifest_sha256, _corpus_root(args))
    return facts


# --------------------------------------------------------------------------- #
# verify-promotions — release-time gate: promotion is the ONLY path to a
# shipped active entry
# --------------------------------------------------------------------------- #
def _load_promotions(promotions_dir: str) -> tuple:
    """Return ``(approval, decisions)``: the bootstrap approval (or None) and a
    ``{entry_id: decision}`` map from ``<id>.decision.json`` files."""
    approval = None
    decisions: dict = {}
    try:
        names = sorted(os.listdir(promotions_dir))
    except OSError:
        return None, {}
    for name in names:
        path = os.path.join(promotions_dir, name)
        if name == "bootstrap.approval.json":
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    approval = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                raise CompileError(f"cannot read {name}: {exc}")
        elif name.endswith(".decision.json"):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    dec = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                raise CompileError(f"cannot read {name}: {exc}")
            if isinstance(dec, dict) and dec.get("entry_id"):
                decisions[dec["entry_id"]] = dec
    return approval, decisions


def verify_promotions(knowledge_root: str, promotions_dir: str,
                      baseline_entries: list, baseline_manifest_sha256: str,
                      registry: dict, corpus_root: str,
                      change_facts: dict) -> dict:
    """Recompute, at release time, that EVERY active shipped entry is accounted for
    by a committed, digest-bound promotion decision — so ``promote_to_verified`` is
    the ONLY path to a trusted active entry, not merely *a* path.

    Each active entry is accounted for iff exactly one of:
      - it is pinned in ``bootstrap.approval.json`` with a matching canonical digest
        and a recorded ``approved_by`` (hand-authored knowledge that rode in on the
        signed skill release; two-party approval recorded once); or
      - it has an ``<id>.decision.json`` whose ``entry_sha256`` matches the shipped
        entry and whose ``baseline_manifest_sha256`` matches the baseline in force,
        AND
          * tier ``auto-promote``: the recorded eval-result **re-binds** to this
            entry/baseline/corpus and the deterministic decision, **recomputed** from
            the pinned baseline + git-derived diff + bound eval-result, is STILL
            ``auto-promote``; or
          * a review tier: a human ``review.approved_by`` is recorded.

    Any active entry that is unaccounted, whose digest does not match its
    decision/approval (a later edit), or whose auto-promote decision no longer
    recomputes, is a **failure** — the release must not ship it. This never re-runs
    quarantine/fetch (provenance is a promotion-time property recorded in the
    decision); it recomputes the parts reproducible from shipped material."""
    import knowledge  # local import; shares scripts/
    entries, _ = knowledge.load_packs(knowledge_root)
    active = [{k: v for k, v in e.items() if not k.startswith("_")}
              for e in entries if e.get("status") == "active"]

    approval, decisions = _load_promotions(promotions_dir)
    approved_entries = {}
    if isinstance(approval, dict):
        approver = approval.get("approved_by")
        if approver:
            approved_entries = approval.get("entries") or {}

    failures: list = []
    accounted: list = []
    seen_ids = set()

    for entry in active:
        eid = entry.get("id")
        seen_ids.add(eid)
        digest = canonical_entry_digest(entry)

        # (1) bootstrap approval
        if eid in approved_entries:
            if approved_entries[eid] != digest:
                failures.append({"id": eid, "reason": (
                    "bootstrap approval digest does not match the shipped entry "
                    "(the entry was edited after approval; re-approve or re-promote)")})
            else:
                accounted.append({"id": eid, "via": "bootstrap-approval"})
            continue

        # (2) per-entry decision
        dec = decisions.get(eid)
        if dec is None:
            failures.append({"id": eid, "reason": (
                "no promotion decision or bootstrap approval accounts for this "
                "active entry (promote_to_verified is the only path to a shipped "
                "active entry)")})
            continue
        if dec.get("entry_sha256") != digest:
            failures.append({"id": eid, "reason": (
                "decision entry_sha256 does not match the shipped entry (edited "
                "after the decision was recorded)")})
            continue
        if dec.get("baseline_manifest_sha256") != baseline_manifest_sha256:
            failures.append({"id": eid, "reason": (
                "decision baseline_manifest_sha256 does not match the baseline in "
                "force; the decision was made against a different baseline")})
            continue

        tier = dec.get("tier")
        if tier == "auto-promote":
            candidate = {k: v for k, v in entry.items()
                         if k not in _PROMOTION_ASSIGNED}
            bound = bind_eval_result(dec.get("eval_result") or {}, candidate,
                                     baseline_manifest_sha256, corpus_root)
            facts = dict(change_facts or {})
            facts["eval_result"] = bound
            facts["signature_valid"] = None
            recomputed = may_promote(candidate, facts, registry=registry,
                                     baseline_entries=baseline_entries,
                                     validation=None)
            if recomputed["tier"] != "auto-promote":
                failures.append({"id": eid, "reason": (
                    f"auto-promote decision no longer recomputes to auto-promote "
                    f"(now {recomputed['tier']}: {recomputed['reasons']})")})
            else:
                accounted.append({"id": eid, "via": "auto-promote-recomputed"})
        elif tier in ("require-review", "two-party-review"):
            if (dec.get("review") or {}).get("approved_by"):
                accounted.append({"id": eid, "via": f"{tier}:approved"})
            else:
                failures.append({"id": eid, "reason": (
                    f"{tier} decision has no recorded review.approved_by")})
        else:
            failures.append({"id": eid, "reason": (
                f"decision tier {tier!r} is not a recognized promotion tier")})

    # Orphans are informational, not fatal: a decision/approval for an id that is no
    # longer an active shipped entry.
    orphans = sorted(
        (set(decisions) | set(approved_entries)) - seen_ids)

    return {"ok": not failures, "active": len(active),
            "accounted": sorted(a["id"] for a in accounted),
            "failures": failures, "orphans": orphans}


def cmd_verify_promotions(args) -> int:
    knowledge_root = args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT
    promotions_dir = (args.promotions_dir
                      or os.path.join(knowledge_root, "promotions"))
    registry = load_registry(knowledge_root)
    baseline_entries, baseline_digest = _resolve_baseline(args)
    change_facts = _resolve_change_facts(args)
    result = verify_promotions(
        knowledge_root, promotions_dir, baseline_entries, baseline_digest,
        registry, _corpus_root(args), change_facts)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


def cmd_conflict(args) -> int:
    # Conflict is always computed against the IMMUTABLE baseline snapshot.
    baseline_entries, _ = _resolve_baseline(args)
    result = find_conflicts(_read_stdin_json(), baseline_entries)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["has_conflict"] else 0


def cmd_may_promote(args) -> int:
    candidate = _read_stdin_json()
    registry = load_registry(args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT)
    baseline, baseline_digest = _resolve_baseline(args)
    facts = _build_facts(args, candidate, baseline_digest)
    # Validate first so the gate cannot be skipped on an unvalidated candidate.
    validation = validate_candidate(candidate, registry,
                                    quarantine_dir=args.quarantine_dir)
    result = may_promote(candidate, facts, registry=registry,
                         baseline_entries=baseline, validation=validation)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_evaluate(args) -> int:
    candidate = _read_stdin_json()
    registry = load_registry(args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT)
    baseline, baseline_digest = _resolve_baseline(args)
    facts = _build_facts(args, candidate, baseline_digest)
    result = evaluate_candidate(
        candidate, registry, args.quarantine_dir, baseline,
        facts["eval_result"], change_facts=facts)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["promotion"]["tier"] == "auto-promote" else 1


def cmd_promote(args) -> int:
    """Emit the trusted verified entry — ONLY when the deterministic pipeline
    assigns an auto-promote tier. Refuses otherwise (the model may propose; only
    this policy step promotes)."""
    candidate = _read_stdin_json()
    registry = load_registry(args.knowledge_root or _DEFAULT_KNOWLEDGE_ROOT)
    baseline, baseline_digest = _resolve_baseline(args)
    facts = _build_facts(args, candidate, baseline_digest)
    result = evaluate_candidate(
        candidate, registry, args.quarantine_dir, baseline,
        facts["eval_result"], change_facts=facts)
    if result["promotion"]["tier"] != "auto-promote":
        sys.stderr.write(
            "error: candidate is not auto-promote; refusing to promote "
            f"(tier={result['promotion']['tier']}; "
            f"reasons={result['promotion']['reasons']})\n")
        return 1
    verified = promote_to_verified(candidate, result["validation"], registry)
    print(json.dumps(verified, indent=2, sort_keys=True))
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

    # Shared promotion-decision flags (conflict/diff use the baseline; the tier
    # decision also reads the eval-result artifact and diff facts).
    promo = argparse.ArgumentParser(add_help=False)
    promo.add_argument("--baseline", default=None,
                       help="knowledge root of the IMMUTABLE baseline (last "
                            "verified released snapshot) for conflict + semantic "
                            "diff. REQUIRED unless --baseline-verified; the working "
                            "tree is never an implicit baseline")
    promo.add_argument("--baseline-verified", action="store_true",
                       help="resolve the baseline from the installed VERIFIED "
                            "snapshot (knowledge_verify.verify_installed); fails "
                            "closed if none is trusted")
    promo.add_argument("--corpus-root", default=None,
                       help="root of the trusted eval corpus (defaults to the "
                            "in-package evals/); binds the eval-result")
    promo.add_argument("--quarantine-dir", default=None,
                       help="directory of quarantine receipts (to resolve+verify "
                            "receipt_id)")
    promo.add_argument("--eval-result", default=None,
                       help="path to the eval-result artifact JSON; it must BIND to "
                            "this candidate/baseline/corpus (schemas/eval-result."
                            "schema.json) or it fails closed. Absent also fails "
                            "closed")
    promo.add_argument("--signature", choices=["valid", "invalid"], default=None,
                       help="attestation result for a PUBLISHED pack; a genuine "
                            "failure blocks. Absent means 'not attested yet' and "
                            "never reads as valid")
    # Diff facts are derived FROM GIT by default (--baseline-commit). The caller
    # flags are honored only behind --trust-caller-diff (explicitly untrusted).
    promo.add_argument("--baseline-commit", default=None,
                       help="git rev of the baseline; the diff is derived in code "
                            "via 'git diff --name-status <rev> HEAD' (preferred)")
    promo.add_argument("--trust-caller-diff", action="store_true",
                       help="UNTRUSTED (tests only): trust the --change-path/"
                            "--removed-eval/--modified-eval flags instead of "
                            "deriving the diff from git")
    promo.add_argument("--change-path", action="append", default=[],
                       help="[--trust-caller-diff only] a repo-relative path the "
                            "diff touches (repeatable)")
    promo.add_argument("--removed-eval", action="append", default=[],
                       help="[--trust-caller-diff only] a trusted eval file removed "
                            "by the diff (repeatable)")
    promo.add_argument("--modified-eval", action="append", default=[],
                       help="[--trust-caller-diff only] a trusted eval file modified "
                            "by the diff (repeatable)")

    sp = sub.add_parser("conflict", parents=[common, promo],
                        help="contradiction vs the immutable baseline (stdin)")
    sp.set_defaults(func=cmd_conflict)

    sp = sub.add_parser("may-promote", parents=[common, promo],
                        help="deterministic promotion-tier decision (stdin); "
                             "authority/conflict/direction/root-of-trust are "
                             "derived, not asserted")
    sp.set_defaults(func=cmd_may_promote)

    sp = sub.add_parser("evaluate", parents=[common, promo],
                        help="unskippable pipeline (stdin): validate -> conflict "
                             "-> diff -> direction -> may-promote; exits 0 only "
                             "on auto-promote")
    sp.set_defaults(func=cmd_evaluate)

    sp = sub.add_parser("promote", parents=[common, promo],
                        help="emit the trusted verified entry (stdin) ONLY on an "
                             "auto-promote tier; assigns status/confidence + "
                             "receipt-derived provenance")
    sp.set_defaults(func=cmd_promote)

    sp = sub.add_parser("verify-promotions", parents=[common, promo],
                        help="release-time gate: recompute that EVERY active shipped "
                             "entry is accounted for by a committed, digest-bound "
                             "promotion decision or bootstrap approval; exits 1 on "
                             "any unaccounted/stale/non-recomputing entry")
    sp.add_argument("--promotions-dir", default=None,
                    help="directory of decision artifacts + bootstrap.approval.json "
                         "(defaults to <knowledge-root>/promotions)")
    sp.set_defaults(func=cmd_verify_promotions)
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
