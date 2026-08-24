#!/usr/bin/env python3
"""AttestArc findings state manager.

This is AttestArc's persistent memory. It maintains ``.attestarc/findings.json``
so the host agent can remember findings across sessions, avoid duplicates, know
what was already remediated, and verify previous fixes.

Design rules (see SPECIFICATION.md, sections 6 and 12.1):

* Deterministic: stable finding IDs, sorted keys, atomic writes.
* Stdlib-only: no third-party dependencies.
* Facts, not verdicts: this script stores what the host agent decided; it does
  not itself judge security.
* Secrets never persisted: upsert refuses findings that appear to embed a raw
  secret value.

Commands::

    state.py init
    state.py list [--status STATUS] [--domain DOMAIN]
    state.py get AA-GHA-81F21C
    state.py upsert finding.json          # or '-' to read from stdin
    state.py set-status AA-GHA-81F21C remediating [--reason ...] [--by ...]
    state.py resolve AA-GHA-81F21C [--observed ... --method ...]
    state.py reverify [--knowledge index.json]   # or '-' for stdin
    state.py validate

All commands accept ``--file`` (default ``.attestarc/findings.json``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from _pathsafe import PathEscapeError, resolve_within_root, safe_read_text

# Bumped to 4 in v0.5.0: optional finding.knowledge_dependencies array
# ({id, content_hash [, version]}, content_hash required) recording which
# verified knowledge entries a
# conclusion rests on; requires_reverification is a read-time computed view
# (never a stored field). Version 3 (v0.4.0) added finding.type taxonomy, the
# risk_acceptance nested object with expires_at, typed related_findings, and
# assessor_safety_events. Version 2 (v0.3.0) widened finding ids to 8 hex chars
# and made the fingerprint hash a canonical ``subject``.
SCHEMA_VERSION = 4

# AttestArc version stamped onto findings as provenance (assessment_version).
# Bump in lockstep with pyproject/SKILL.md at each release.
ASSESSMENT_VERSION = "0.5.0"

# Persisted string leaves are capped so a hostile tool result cannot turn
# durable state into a multi-megabyte prompt-injection payload.
_MAX_STRING_LEN = 4000
_TRUNCATION_MARKER = "…[truncated by AttestArc]"

SEVERITIES = ("critical", "high", "medium", "low")
CONFIDENCES = ("high", "medium", "low")
STATUSES = (
    "open",
    "remediating",
    "resolved",
    "accepted_risk",
    "false_positive",
    "needs_review",
)
DOMAINS = (
    "repository",
    "ci",
    "dependencies",
    "identity-secrets",
    "supply-chain",
    "changes",
)

# Statuses set deliberately by a human. Upsert must not silently reopen them.
HUMAN_DECIDED = ("accepted_risk", "false_positive", "resolved")

_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_CONFIDENCE_RANK = {c: i for i, c in enumerate(CONFIDENCES)}

_DOMAIN_PREFIX = {
    "repository": "REP",
    "ci": "CI",
    "dependencies": "DEP",
    "identity-secrets": "IDS",
    "supply-chain": "SC",
    "changes": "CHG",
}

DEFAULT_FILE = os.path.join(".attestarc", "findings.json")


class StateError(Exception):
    """Raised for user-facing state errors (bad input, missing finding, ...)."""


# --------------------------------------------------------------------------- #
# Time
# --------------------------------------------------------------------------- #
def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


# --------------------------------------------------------------------------- #
# Stable identifiers
# --------------------------------------------------------------------------- #
def _canonicalize(part: str) -> str:
    """Normalize a fingerprint component so cosmetic differences don't drift ids.

    Lower-cases, converts backslashes to forward slashes, collapses repeated
    slashes, and strips surrounding whitespace. This keeps ``.github\\Workflows``
    and ``.github/workflows`` (and re-worded casing) mapping to one finding.
    """
    if not part:
        return ""
    s = str(part).strip().lower().replace("\\", "/")
    return re.sub(r"/{2,}", "/", s)


def compute_fingerprint(domain: str, category: str, resource: str,
                        subject: str = "") -> str:
    """Stable sha256 fingerprint of the risky condition.

    Hashes ``domain | category | canonical(resource) | canonical(subject)``.
    The free-text ``condition`` is deliberately NOT part of the fingerprint:
    re-wording the human explanation of the same issue must not mint a new id.
    ``subject`` is an optional stable machine key (e.g. an action ref or job
    name) used to disambiguate two distinct issues on the same resource.

    Independent of run order, so a finding survives across sessions.
    """
    normalized = "|".join(
        _canonicalize(part) for part in (domain, category, resource, subject)
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def id_prefix(domain: str, category: str = "", resource: str = "") -> str:
    """Display prefix for a finding id (e.g. GHA for GitHub Actions)."""
    hay = f"{category} {resource}".lower()
    if domain == "ci":
        if (
            "github" in hay
            or ".github/workflows" in resource.lower()
            or "action" in hay
            or "workflow" in hay
        ):
            return "GHA"
        return "CI"
    return _DOMAIN_PREFIX.get(domain, "AA")


def display_id(fingerprint: str, domain: str, category: str = "",
               resource: str = "", prefix: str | None = None) -> str:
    pfx = prefix or id_prefix(domain, category, resource)
    return f"AA-{pfx}-{fingerprint[:8].upper()}"


# --------------------------------------------------------------------------- #
# Secret guard
# --------------------------------------------------------------------------- #
# High-confidence markers of a real secret value. Kept conservative so genuine
# findings (which reference secret *names*, not values) are not rejected.
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                       # AWS access key id
    re.compile(r"ghp_[0-9A-Za-z]{30,}"),                   # GitHub PAT
    re.compile(r"github_pat_[0-9A-Za-z_]{50,}"),           # GitHub fine-grained
    re.compile(r"gh[opsu]_[0-9A-Za-z]{30,}"),              # other GitHub tokens
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),           # Slack
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),                 # Google API key
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    re.compile(
        r"(?i)(?:secret|token|password|passwd|api[_-]?key|access[_-]?key)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-]{16,}"
    ),
]


def looks_like_secret(text: str) -> bool:
    if not text:
        return False
    return any(p.search(text) for p in _SECRET_PATTERNS)


def _iter_strings(value):
    """Yield every string leaf in a nested dict/list structure."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _iter_strings(v)


def _iter_string_paths(value, prefix: str = ""):
    """Yield (path, string) for every string leaf, for precise error messages."""
    if isinstance(value, str):
        yield prefix or "<root>", value
    elif isinstance(value, dict):
        for k, v in value.items():
            child = f"{prefix}.{k}" if prefix else str(k)
            yield from _iter_string_paths(v, child)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            child = f"{prefix}[{i}]"
            yield from _iter_string_paths(v, child)


def _assert_no_secrets(finding: dict) -> None:
    """Reject a finding if a raw secret value appears in ANY string leaf.

    The secret guard used to cover only ``evidence.{observed,value,key}`` and
    ``threat``; a value leaked into ``title``, ``impact``, ``remediation``,
    ``verification``, ``reason``, or an ``extensions`` field would have been
    persisted. The whole finding is now walked.
    """
    for path, text in _iter_string_paths(finding):
        if looks_like_secret(text):
            raise StateError(
                f"refusing to persist finding: {path} appears to contain a raw "
                "secret value. Store only metadata (secret name/source), never "
                "the value itself."
            )


def _cap_strings(value):
    """Return a copy of ``value`` with over-long string leaves truncated.

    Bounds the durable size of any single field so a hostile tool result cannot
    inflate ``findings.json`` into a giant, re-loaded prompt-injection payload.
    """
    if isinstance(value, str):
        if len(value) > _MAX_STRING_LEN:
            keep = _MAX_STRING_LEN - len(_TRUNCATION_MARKER)
            return value[:keep] + _TRUNCATION_MARKER
        return value
    if isinstance(value, dict):
        return {k: _cap_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_cap_strings(v) for v in value]
    return value


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #
def _empty_state(root: str = ".") -> dict:
    ts = _now()
    return {
        "schema_version": SCHEMA_VERSION,
        "repository": {"root": root, "scm": None, "remote": None},
        "created_at": ts,
        "updated_at": ts,
        "findings": [],
    }


def _dump(state: dict) -> str:
    return json.dumps(state, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def _assert_within_root(path: str, root: str) -> None:
    """Refuse to touch ``path`` unless it resolves to inside ``root``.

    Containment is computed by :func:`_pathsafe.resolve_within_root` (shared with
    the read helpers): it resolves the deepest existing ancestor with ``realpath``
    so a symlink at ``.attestarc`` (or any parent) that escapes the repository —
    e.g. pointing at ``~/.ssh`` or a sibling checkout — is detected even before
    the file is created. Assessment is read-only and state is repo-local; a write
    that lands outside the repository root is always a trap, never legitimate.
    """
    resolved, root_real, within = resolve_within_root(path, root)
    if not within:
        raise StateError(
            f"refusing to write outside the repository root: {path} resolves to "
            f"{resolved}, which is not under {root_real}. This happens when "
            ".attestarc (or a parent) is a symlink escaping the repository; the "
            "repository is untrusted input and cannot redirect AttestArc's writes."
        )


def _atomic_write(path: str, text: str, root: str | None = None) -> None:
    if root is not None:
        _assert_within_root(path, root)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".findings-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save_state(state: dict, path: str, root: str | None = None) -> None:
    state["updated_at"] = _now()
    _atomic_write(path, _dump(state), root=root)


def _backup_corrupt(path: str) -> str:
    n = 0
    while True:
        candidate = f"{path}.corrupt-{n}"
        if not os.path.exists(candidate):
            break
        n += 1
    os.replace(path, candidate)
    return candidate


def _migrate_state(state: dict) -> dict:
    """Migrate an older on-disk state to the current schema, in memory.

    Applied on load so a v1/v2 ``findings.json`` keeps working; the migrated
    shape is persisted only on the next mutating save, so a read-only command
    stays read-only. Idempotent — ids and fingerprints are never changed.

    v2 -> v3:

    * flat ``accepted_by`` / ``reason`` / ``accepted_at`` on an accepted finding
      fold into a nested ``risk_acceptance`` object;
    * untyped ``related_findings: [str]`` become
      ``[{id, relationship: "contributes_to"}]``.

    v3 -> v4: additive only. ``knowledge_dependencies`` is a new optional field;
    existing findings simply do not carry it, so the sole change is the
    ``schema_version`` bump (persisted on the next mutating save).
    """
    version = state.get("schema_version")
    if not isinstance(version, int) or version >= SCHEMA_VERSION:
        return state

    for f in state.get("findings", []):
        if not isinstance(f, dict):
            continue
        # Flat acceptance fields -> nested risk_acceptance object.
        if not isinstance(f.get("risk_acceptance"), dict):
            flat: dict = {}
            for k in ("accepted_by", "accepted_at"):
                if k in f:
                    flat[k] = f.pop(k)
            # ``reason`` belongs to the acceptance only when this WAS one.
            if (flat or f.get("status") == "accepted_risk") and "reason" in f:
                flat["reason"] = f.pop("reason")
            if flat:
                f["risk_acceptance"] = flat
        # Untyped related_findings (list of id strings) -> typed links.
        rel = f.get("related_findings")
        if isinstance(rel, list) and any(isinstance(x, str) for x in rel):
            f["related_findings"] = [
                {"id": x, "relationship": "contributes_to"}
                if isinstance(x, str) else x
                for x in rel
            ]
        # Mark the version that last touched the (migrated) finding.
        f.setdefault("assessment_version", ASSESSMENT_VERSION)

    state["schema_version"] = SCHEMA_VERSION
    return state


def load_state(path: str, *, recover: bool = True, root: str | None = None) -> dict:
    """Load state. On corrupt JSON, back it up and reinitialize (if recover).

    When ``root`` is supplied the read is confined to it (the repository under
    assessment is untrusted input: a symlinked/absolute/``..`` ``findings.json``
    must never let AttestArc read outside the assessed root). Older schema
    versions are migrated in memory via :func:`_migrate_state`.
    """
    if not os.path.exists(path):
        raise StateError(
            f"{path} does not exist. Run 'state.py init' first."
        )
    try:
        if root is not None:
            raw = safe_read_text(path, root)
        else:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read()
        data = json.loads(raw)
    except PathEscapeError as exc:
        raise StateError(
            f"refusing to read outside the repository root: {exc}. This happens "
            "when findings.json (or a parent) is a symlink escaping the "
            "repository; the repository is untrusted input and cannot redirect "
            "AttestArc's reads."
        ) from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        if not recover:
            raise StateError(f"{path} is not valid JSON: {exc}") from exc
        backup = _backup_corrupt(path)
        state = _empty_state()
        save_state(state, path, root=root)
        sys.stderr.write(
            f"warning: {path} was corrupt ({exc}); backed up to {backup} and "
            f"reinitialized.\n"
        )
        return state
    if not isinstance(data, dict):
        raise StateError(f"{path} does not contain a JSON object.")
    return _migrate_state(data)


# --------------------------------------------------------------------------- #
# Validation (hand-rolled; no jsonschema dependency)
# --------------------------------------------------------------------------- #
# Closed vocabularies and key sets mirroring schemas/findings.schema.json. Kept
# here (not read from the schema) so validation stays stdlib-only and cannot be
# steered by a tampered schema file. A parity test asserts they match the schema.
FINDING_TYPES = ("exposure", "attack-path", "hardening")
RELATIONSHIPS = ("contributes_to", "superseded_by", "duplicate_of")
REACHABILITY = ("direct", "conditional", "trusted-only", "unknown")
EVIDENCE_TYPES = (
    "repository-file", "git-diff", "remote-config", "tool-output", "inference",
)

_TOPLEVEL_KEYS = frozenset({
    "schema_version", "repository", "created_at", "updated_at", "findings",
    "assessor_safety_events", "extensions",
})
_FINDING_KEYS = frozenset({
    "id", "fingerprint", "domain", "category", "type", "resource", "subject",
    "condition", "title", "severity", "confidence", "status", "first_seen",
    "last_seen", "observed_at", "source_revision", "last_verified_at",
    "assessment_version", "evidence", "impact", "threat", "trust_boundary",
    "related_findings", "knowledge_dependencies", "remediation", "verification",
    "risk_acceptance", "extensions",
})
_RELATED_KEYS = frozenset({"id", "relationship"})
_KNOWLEDGE_DEP_KEYS = frozenset({"id", "version", "content_hash"})
_RISK_ACCEPTANCE_KEYS = frozenset({
    "accepted_by", "reason", "accepted_at", "expires_at", "extensions",
})
_SAFETY_EVENT_KEYS = frozenset({
    "source", "detected_at", "location", "excerpt", "content_hash",
    "action_taken", "extensions",
})
_ID_RE = re.compile(r"AA-[A-Z]{2,4}-[0-9A-F]{8}")


def validate_state(state: dict) -> list[str]:
    """Return a list of human-readable validation errors ([] if valid).

    findings.json is untrusted input on reload, so the closed v3 structures are
    enforced here (unknown keys, enums, typed links). Graceful: never raises on
    malformed input — every problem becomes an error string.
    """
    errors: list[str] = []

    def err(msg: str) -> None:
        errors.append(msg)

    if state.get("schema_version") != SCHEMA_VERSION:
        err(f"schema_version must be {SCHEMA_VERSION}")
    for key in ("repository", "created_at", "updated_at", "findings"):
        if key not in state:
            err(f"missing top-level key: {key}")
    for key in state:
        if key not in _TOPLEVEL_KEYS:
            err(f"unknown top-level key: {key}")

    repo = state.get("repository")
    if not isinstance(repo, dict) or "root" not in repo:
        err("repository must be an object containing 'root'")

    _validate_safety_events(state.get("assessor_safety_events"), err)

    findings = state.get("findings")
    if not isinstance(findings, list):
        err("findings must be an array")
        return errors

    seen_ids: set[str] = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            err(f"{where} must be an object")
            continue
        for key in ("id", "fingerprint", "domain", "category", "title",
                    "severity", "confidence", "status", "first_seen",
                    "last_seen", "evidence"):
            if key not in f:
                err(f"{where} missing required field: {key}")
        for key in f:
            if key not in _FINDING_KEYS:
                err(f"{where} has unknown field: {key}")
        fid = f.get("id")
        if isinstance(fid, str):
            if not _ID_RE.fullmatch(fid):
                err(f"{where}.id has invalid format: {fid!r}")
            if fid in seen_ids:
                err(f"{where}.id is duplicated: {fid}")
            seen_ids.add(fid)
        fp = f.get("fingerprint")
        if isinstance(fp, str) and not re.fullmatch(r"[0-9a-f]{64}", fp):
            err(f"{where}.fingerprint must be a sha256 hex digest")
        if f.get("domain") not in DOMAINS:
            err(f"{where}.domain invalid: {f.get('domain')!r}")
        if f.get("severity") not in SEVERITIES:
            err(f"{where}.severity invalid: {f.get('severity')!r}")
        if f.get("confidence") not in CONFIDENCES:
            err(f"{where}.confidence invalid: {f.get('confidence')!r}")
        if f.get("status") not in STATUSES:
            err(f"{where}.status invalid: {f.get('status')!r}")
        if "type" in f and f.get("type") not in FINDING_TYPES:
            err(f"{where}.type invalid: {f.get('type')!r}")
        if not isinstance(f.get("evidence"), list):
            err(f"{where}.evidence must be an array")
        else:
            for j, ev in enumerate(f["evidence"]):
                if not isinstance(ev, dict):
                    err(f"{where}.evidence[{j}] must be an object")
                elif ev.get("type") not in EVIDENCE_TYPES:
                    err(f"{where}.evidence[{j}].type invalid: {ev.get('type')!r}")
            try:
                _assert_no_secrets(f)
            except StateError as exc:
                err(f"{where}: {exc}")
        _validate_related_findings(f.get("related_findings"), where, err)
        _validate_knowledge_dependencies(f.get("knowledge_dependencies"), where, err)
        _validate_risk_acceptance(f.get("risk_acceptance"), where, err)
        _validate_threat(f.get("threat"), where, err)
    return errors


def _validate_related_findings(rel, where: str, err) -> None:
    if rel is None:
        return
    if not isinstance(rel, list):
        err(f"{where}.related_findings must be an array")
        return
    for j, item in enumerate(rel):
        at = f"{where}.related_findings[{j}]"
        if not isinstance(item, dict):
            err(f"{at} must be an object {{id, relationship}}")
            continue
        for key in item:
            if key not in _RELATED_KEYS:
                err(f"{at} has unknown field: {key}")
        rid = item.get("id")
        if not isinstance(rid, str) or not _ID_RE.fullmatch(rid):
            err(f"{at}.id has invalid format: {rid!r}")
        if item.get("relationship") not in RELATIONSHIPS:
            err(f"{at}.relationship invalid: {item.get('relationship')!r}")


def _validate_knowledge_dependencies(deps, where: str, err) -> None:
    if deps is None:
        return
    if not isinstance(deps, list):
        err(f"{where}.knowledge_dependencies must be an array")
        return
    for j, item in enumerate(deps):
        at = f"{where}.knowledge_dependencies[{j}]"
        if not isinstance(item, dict):
            err(f"{at} must be an object {{id, content_hash}}")
            continue
        for key in item:
            if key not in _KNOWLEDGE_DEP_KEYS:
                err(f"{at} has unknown field: {key}")
        kid = item.get("id")
        if not isinstance(kid, str) or not kid:
            err(f"{at}.id must be a non-empty string")
        ch = item.get("content_hash")
        if not isinstance(ch, str) or not ch:
            err(f"{at}.content_hash is required (an id alone cannot reliably "
                f"invalidate a finding)")


def _validate_risk_acceptance(ra, where: str, err) -> None:
    if ra is None:
        return
    if not isinstance(ra, dict):
        err(f"{where}.risk_acceptance must be an object")
        return
    for key in ra:
        if key not in _RISK_ACCEPTANCE_KEYS:
            err(f"{where}.risk_acceptance has unknown field: {key}")


def _validate_threat(threat, where: str, err) -> None:
    if threat is None:
        return
    if not isinstance(threat, dict):
        err(f"{where}.threat must be an object")
        return
    reach = threat.get("reachability")
    if reach is not None and reach not in REACHABILITY:
        err(f"{where}.threat.reachability invalid: {reach!r}")


def _validate_safety_events(events, err) -> None:
    if events is None:
        return
    if not isinstance(events, list):
        err("assessor_safety_events must be an array")
        return
    for i, ev in enumerate(events):
        at = f"assessor_safety_events[{i}]"
        if not isinstance(ev, dict):
            err(f"{at} must be an object")
            continue
        for key in ev:
            if key not in _SAFETY_EVENT_KEYS:
                err(f"{at} has unknown field: {key}")
        if ev.get("source") not in _SAFETY_SOURCES:
            err(f"{at}.source invalid: {ev.get('source')!r}")
        if "detected_at" not in ev:
            err(f"{at} missing required field: detected_at")
        try:
            _assert_no_secrets(ev)
        except StateError as exc:
            err(f"{at}: {exc}")


# --------------------------------------------------------------------------- #
# Finding normalization / upsert
# --------------------------------------------------------------------------- #
def _sort_key(f: dict):
    return (
        _SEVERITY_RANK.get(f.get("severity"), len(SEVERITIES)),
        _CONFIDENCE_RANK.get(f.get("confidence"), len(CONFIDENCES)),
        f.get("id", ""),
    )


def normalize_finding(finding: dict) -> dict:
    """Fill fingerprint/id from provided fields and validate a single finding.

    A finding may supply an explicit ``fingerprint``/``id``. Otherwise, provide
    ``resource`` (and optionally ``condition``) so a stable fingerprint can be
    derived. ``resource``/``condition`` are preserved for traceability.
    """
    f = dict(finding)  # shallow copy; do not mutate caller's dict

    domain = f.get("domain")
    category = f.get("category", "")
    if domain not in DOMAINS:
        raise StateError(f"finding.domain invalid or missing: {domain!r}")
    if not category:
        raise StateError("finding.category is required")

    resource = f.get("resource", "")
    # ``subject`` is a stable machine key for disambiguation and feeds the
    # fingerprint; ``condition`` stays a human field and does NOT.
    subject = f.get("subject", "")

    fp = f.get("fingerprint")
    if not fp:
        if not resource:
            raise StateError(
                "finding requires either 'fingerprint' or 'resource' "
                "(plus optional 'subject') to derive a stable id"
            )
        fp = compute_fingerprint(domain, category, resource, subject)
        f["fingerprint"] = fp
    elif not re.fullmatch(r"[0-9a-f]{64}", fp):
        raise StateError("finding.fingerprint must be a sha256 hex digest")

    if not f.get("id"):
        f["id"] = display_id(
            fp, domain, category, resource, prefix=f.get("id_prefix")
        )
    # id_prefix is an input-only hint; do not persist it as a finding field.
    f.pop("id_prefix", None)

    f.setdefault("severity", "medium")
    f.setdefault("confidence", "medium")
    f.setdefault("status", "open")
    if f["severity"] not in SEVERITIES:
        raise StateError(f"finding.severity invalid: {f['severity']!r}")
    if f["confidence"] not in CONFIDENCES:
        raise StateError(f"finding.confidence invalid: {f['confidence']!r}")
    if f["status"] not in STATUSES:
        raise StateError(f"finding.status invalid: {f['status']!r}")
    if "title" not in f or not f["title"]:
        raise StateError("finding.title is required")
    f.setdefault("evidence", [])
    if not isinstance(f["evidence"], list):
        raise StateError("finding.evidence must be an array")

    _assert_no_secrets(f)
    # Secret scan runs on the original text; cap only afterwards so truncation
    # can never split a secret across the boundary and evade detection.
    f = _cap_strings(f)
    return f


def _merge_evidence(existing: list, incoming: list) -> list:
    merged = list(existing)
    seen = {json.dumps(e, sort_keys=True) for e in existing}
    for e in incoming:
        key = json.dumps(e, sort_keys=True)
        if key not in seen:
            merged.append(e)
            seen.add(key)
    return merged


def upsert_finding(state: dict, finding: dict) -> tuple[dict, bool]:
    """Insert or update a finding, matched by fingerprint.

    Returns (stored_finding, created). Preserves human-decided status and
    unknown fields; refreshes last_seen; sets first_seen only on creation.
    """
    incoming = normalize_finding(finding)
    now = _now()
    findings = state.setdefault("findings", [])

    for i, existing in enumerate(findings):
        if existing.get("fingerprint") == incoming["fingerprint"]:
            merged = dict(existing)  # keep unknown/human fields
            # Refresh the observable, agent-supplied fields.
            for key in ("title", "severity", "confidence", "impact",
                        "remediation", "verification", "category", "domain",
                        "resource", "subject", "condition", "threat",
                        "trust_boundary", "related_findings",
                        "knowledge_dependencies", "type"):
                if key in incoming:
                    merged[key] = incoming[key]
            merged["evidence"] = _merge_evidence(
                existing.get("evidence", []), incoming.get("evidence", [])
            )
            merged["last_seen"] = now
            # Provenance: the condition was (re)observed now, by this version.
            merged["observed_at"] = now
            merged["assessment_version"] = ASSESSMENT_VERSION
            if incoming.get("source_revision"):
                merged["source_revision"] = incoming["source_revision"]
            merged.setdefault("first_seen", existing.get("first_seen", now))
            merged["id"] = existing.get("id", incoming["id"])
            # Do not silently reopen a finding a human closed.
            if existing.get("status") in HUMAN_DECIDED:
                merged["status"] = existing["status"]
            else:
                merged["status"] = incoming.get("status", existing.get("status"))
            findings[i] = merged
            return merged, False

    incoming.setdefault("first_seen", now)
    incoming["last_seen"] = now
    incoming.setdefault("observed_at", now)
    incoming.setdefault("assessment_version", ASSESSMENT_VERSION)
    findings.append(incoming)
    return incoming, True


def find_by_id(state: dict, fid: str) -> dict | None:
    for f in state.get("findings", []):
        if f.get("id") == fid:
            return f
    return None


def _parse_iso(ts) -> datetime | None:
    """Best-effort parse of an ISO-8601 timestamp (tolerates a trailing ``Z``)."""
    if not isinstance(ts, str) or not ts.strip():
        return None
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def effective_status(finding: dict, now: str | None = None) -> str:
    """Effective status view: an ``accepted_risk`` past its expiry reverts to open.

    The stored ``status`` is left untouched — this only changes how ``list`` /
    ``get`` present a finding, so a lapsed risk acceptance resurfaces for
    re-review without silently rewriting durable state. An unparseable or absent
    expiry is treated as "no expiry".
    """
    status = finding.get("status")
    if status != "accepted_risk":
        return status
    ra = finding.get("risk_acceptance")
    expires = ra.get("expires_at") if isinstance(ra, dict) else None
    expires_dt = _parse_iso(expires)
    if expires_dt is None:
        return status
    now_dt = _parse_iso(now) or datetime.now(timezone.utc)
    return "open" if expires_dt <= now_dt else status


def _with_effective_status(finding: dict, now: str) -> dict:
    """Return a display copy annotated with ``effective_status`` when it differs.

    Never mutates the stored finding; the annotation is a read-time view only.
    """
    eff = effective_status(finding, now)
    if eff == finding.get("status"):
        return finding
    view = dict(finding)
    view["effective_status"] = eff
    return view


def knowledge_reverification_reasons(finding: dict, index: dict) -> list[str]:
    """Why a finding needs re-verification given the current knowledge ``index``.

    ``index`` maps knowledge-entry id -> {version?, content_hash?, status?} as
    reported by ``knowledge.py``. A finding needs re-verification when a knowledge
    entry its conclusion depended on has since been removed, changed version or
    content, or is no longer ``active`` (superseded/disputed/retired/draft).

    Pure and read-only: like ``effective_status`` this is a computed VIEW — it
    never mutates stored status, so a knowledge change never auto-resolves or
    auto-confirms a finding. state.py deliberately does not read the knowledge
    plane itself (it is confined to the assessed repo); the caller supplies the
    index so knowledge lives behind its own root.
    """
    reasons: list[str] = []
    deps = finding.get("knowledge_dependencies")
    if not isinstance(deps, list):
        return reasons
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        kid = dep.get("id")
        if not isinstance(kid, str) or not kid:
            continue
        cur = index.get(kid)
        if not isinstance(cur, dict):
            reasons.append(f"{kid}: no longer present in verified knowledge")
            continue
        status = cur.get("status")
        if status and status != "active":
            reasons.append(f"{kid}: status is now {status}")
        rv, cv = dep.get("version"), cur.get("version")
        if rv is not None and cv is not None and rv != cv:
            reasons.append(f"{kid}: version {rv} -> {cv}")
        rh, ch = dep.get("content_hash"), cur.get("content_hash")
        if rh is not None and ch is not None and rh != ch:
            reasons.append(f"{kid}: content changed")
    return reasons


def requires_reverification(finding: dict, index: dict) -> bool:
    """True when the finding's knowledge dependencies changed vs ``index``."""
    return bool(knowledge_reverification_reasons(finding, index))


# --------------------------------------------------------------------------- #
# git exclude helper
# --------------------------------------------------------------------------- #
def ensure_git_exclude(root: str = ".") -> str | None:
    """Add '.attestarc/' to .git/info/exclude (never the tracked .gitignore).

    Returns the exclude path if updated/verified, None if not a git repo.
    """
    git_dir = os.path.join(root, ".git")
    if not os.path.isdir(git_dir):
        return None
    info_dir = os.path.join(git_dir, "info")
    exclude = os.path.join(info_dir, "exclude")
    # A symlinked .git escaping the repository is untrusted; never follow it.
    _assert_within_root(exclude, root)
    entry = ".attestarc/"
    existing = ""
    if os.path.exists(exclude):
        with open(exclude, "r", encoding="utf-8") as fh:
            existing = fh.read()
    lines = {ln.strip() for ln in existing.splitlines()}
    if entry in lines or ".attestarc" in lines:
        return exclude
    os.makedirs(info_dir, exist_ok=True)
    prefix = "" if existing == "" or existing.endswith("\n") else "\n"
    with open(exclude, "a", encoding="utf-8") as fh:
        fh.write(f"{prefix}{entry}\n")
    return exclude


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_init(args) -> int:
    path = args.file
    if os.path.exists(path) and not args.force:
        state = load_state(path, root=args.root)
        errors = validate_state(state)
        if errors:
            sys.stderr.write(
                "existing findings file has validation errors:\n  "
                + "\n  ".join(errors) + "\n"
            )
            return 1
        result = {"status": "exists", "file": path,
                  "findings": len(state.get("findings", []))}
    else:
        state = _empty_state(root=args.root)
        save_state(state, path, root=args.root)
        result = {"status": "created", "file": path, "findings": 0}

    excluded = ensure_git_exclude(args.root)
    result["git_exclude"] = excluded
    print(json.dumps(result, indent=2))
    return 0


def cmd_list(args) -> int:
    state = load_state(args.file, root=args.root)
    now = _now()
    findings = list(state.get("findings", []))
    # Filter by EFFECTIVE status so a lapsed accepted_risk resurfaces under
    # 'open' (and no longer appears under 'accepted_risk').
    if args.status:
        findings = [f for f in findings
                    if effective_status(f, now) == args.status]
    if args.domain:
        findings = [f for f in findings if f.get("domain") == args.domain]
    findings.sort(key=_sort_key)
    findings = [_with_effective_status(f, now) for f in findings]
    print(json.dumps(findings, indent=2, sort_keys=True))
    return 0


def cmd_get(args) -> int:
    state = load_state(args.file, root=args.root)
    f = find_by_id(state, args.id)
    if f is None:
        sys.stderr.write(f"no finding with id {args.id}\n")
        return 1
    print(json.dumps(_with_effective_status(f, _now()), indent=2, sort_keys=True))
    return 0


def _read_finding_input(source: str, root: str | None = None) -> dict:
    if source == "-":
        raw = sys.stdin.read()
    elif root is not None:
        # A finding file supplied on the command line is caller-controlled; a
        # symlinked/absolute/``..`` source must not read outside the repo root.
        try:
            raw = safe_read_text(source, root)
        except PathEscapeError as exc:
            raise StateError(
                f"refusing to read finding input outside the repository root: "
                f"{exc}."
            ) from exc
    else:
        with open(source, "r", encoding="utf-8") as fh:
            raw = fh.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StateError(f"input is not valid JSON: {exc}") from exc
    if isinstance(data, list):
        raise StateError(
            "upsert expects a single finding object; got a list. "
            "Upsert findings one at a time."
        )
    if not isinstance(data, dict):
        raise StateError("upsert expects a JSON object")
    return data


def _git_head_revision(root: str) -> str | None:
    """Read-only best-effort: the current HEAD commit, or None.

    Used only to stamp ``source_revision`` provenance; never mutates the repo and
    never raises (git absent / not a repo / detached is all fine → None).
    """
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
            text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    rev = out.stdout.strip()
    return rev if out.returncode == 0 and re.fullmatch(r"[0-9a-f]{7,40}", rev) else None


def cmd_upsert(args) -> int:
    state = load_state(args.file, root=args.root)
    finding = _read_finding_input(args.source, root=args.root)
    # Stamp source_revision provenance from git HEAD unless the host supplied it.
    if not finding.get("source_revision"):
        rev = _git_head_revision(args.root)
        if rev:
            finding["source_revision"] = rev
    stored, created = upsert_finding(state, finding)
    save_state(state, args.file, root=args.root)
    print(json.dumps(
        {"action": "created" if created else "updated", "id": stored["id"],
         "fingerprint": stored["fingerprint"], "status": stored["status"]},
        indent=2,
    ))
    return 0


def cmd_set_status(args) -> int:
    state = load_state(args.file, root=args.root)
    f = find_by_id(state, args.id)
    if f is None:
        sys.stderr.write(f"no finding with id {args.id}\n")
        return 1
    if args.status not in STATUSES:
        sys.stderr.write(
            f"invalid status {args.status!r}; choose from {', '.join(STATUSES)}\n"
        )
        return 1
    now = _now()
    f["status"] = args.status
    f["last_seen"] = now
    if args.status == "accepted_risk":
        acceptance = dict(f.get("risk_acceptance", {}))
        acceptance["accepted_by"] = args.by or "user"
        acceptance["accepted_at"] = now
        if args.reason:
            acceptance["reason"] = args.reason
        if getattr(args, "expires", None):
            acceptance["expires_at"] = args.expires
        f["risk_acceptance"] = acceptance
    elif args.reason:
        # A reason for a non-acceptance status has no closed field; keep it in
        # the open extensions namespace rather than dropping it.
        ext = dict(f.get("extensions", {}))
        ext["status_reason"] = args.reason
        f["extensions"] = ext
    save_state(state, args.file, root=args.root)
    print(json.dumps({"id": f["id"], "status": f["status"]}, indent=2))
    return 0


def cmd_resolve(args) -> int:
    """Mark a finding resolved after verification.

    Verification is the host agent's responsibility (re-observe the condition);
    this records the verified outcome supplied on the command line.
    """
    state = load_state(args.file, root=args.root)
    f = find_by_id(state, args.id)
    if f is None:
        sys.stderr.write(f"no finding with id {args.id}\n")
        return 1
    now = _now()
    f["status"] = "resolved"
    f["last_seen"] = now
    f["last_verified_at"] = now
    verification = dict(f.get("verification", {}))
    verification["status"] = "verified"
    verification["checked_at"] = now
    if args.method:
        verification["method"] = args.method
    if args.observed:
        if looks_like_secret(args.observed):
            sys.stderr.write(
                "refusing to store verification.observed: appears to contain a "
                "secret value.\n"
            )
            return 1
        verification["observed"] = args.observed
    f["verification"] = verification
    save_state(state, args.file, root=args.root)
    print(json.dumps({"id": f["id"], "status": "resolved",
                      "verification": verification["status"]}, indent=2))
    return 0


_SAFETY_SOURCES = ("repository-content", "tool-output", "findings-json")


def _safety_event_from_stdin() -> dict:
    """Read a safety-event payload as JSON from stdin.

    Reading the payload from stdin (``record-safety-event -``) keeps untrusted
    repository text off the shell command line, where it could be
    mis-interpreted as arguments or logged verbatim.
    """
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise StateError(
            f"record-safety-event - expects a JSON object on stdin: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise StateError("record-safety-event - expects a JSON object on stdin")
    return data


def cmd_record_safety_event(args) -> int:
    """Record an attempt to manipulate AttestArc itself.

    This is an *assessor-safety event*, structurally separate from findings: it
    is never a security finding about the assessed repository. By default only
    metadata plus a ``content_hash`` (sha256 of the injected text) is stored, so
    the attempt is fingerprinted without persisting the raw payload. A raw
    ``excerpt`` is kept only when explicitly supplied as already-sanitized
    (secret-scanned, capped) and MUST NOT be acted on.

    Two input styles:

    * ``record-safety-event <source> [--location ...] [--excerpt ...]`` — flags.
    * ``record-safety-event - < payload.json`` — a JSON object on stdin with
      ``{source, location?, action_taken?, content?, excerpt?}``. ``content`` is
      the raw injected text: it is hashed but never persisted.
    """
    if args.source == "-":
        payload = _safety_event_from_stdin()
        source = payload.get("source")
        location = payload.get("location")
        action = payload.get("action_taken") or payload.get("action")
        content = payload.get("content")
        excerpt = payload.get("excerpt")
    else:
        source = args.source
        location = args.location
        action = args.action
        content = None
        excerpt = args.excerpt

    if source not in _SAFETY_SOURCES:
        sys.stderr.write(
            f"invalid source {source!r}; choose from "
            f"{', '.join(_SAFETY_SOURCES)}\n"
        )
        return 1

    state = load_state(args.file, root=args.root)
    event = {"source": source, "detected_at": _now()}
    if location:
        event["location"] = str(location)

    # Fingerprint the injected text (raw ``content`` preferred, else the
    # sanitized ``excerpt``) so the attempt is recorded even when we do not
    # persist the raw payload. Hashing is one-way, so hashing a secret is safe.
    hash_input = content if content is not None else excerpt
    if hash_input is not None and str(hash_input):
        event["content_hash"] = hashlib.sha256(
            str(hash_input).encode("utf-8")
        ).hexdigest()

    # Persist a raw excerpt ONLY when explicitly supplied as already-sanitized.
    if excerpt:
        if not isinstance(excerpt, str):
            sys.stderr.write("excerpt must be a string.\n")
            return 1
        if looks_like_secret(excerpt):
            sys.stderr.write(
                "refusing to store excerpt: appears to contain a secret value.\n"
            )
            return 1
        event["excerpt"] = excerpt

    event["action_taken"] = action or "refused; recorded as data, not followed"
    event = _cap_strings(event)
    state.setdefault("assessor_safety_events", []).append(event)
    save_state(state, args.file, root=args.root)
    print(json.dumps({"recorded": "assessor_safety_event",
                      "source": event["source"]}, indent=2))
    return 0


def cmd_reverify(args) -> int:
    """List findings whose knowledge dependencies changed (read-time view).

    Reads the current knowledge index (id -> {version?, content_hash?, status?})
    produced by ``knowledge.py`` from ``--knowledge FILE`` or stdin ('-'), and
    reports which findings must be re-observed. Never mutates state: a knowledge
    change resurfaces a finding for re-verification, it does not resolve it.
    """
    state = load_state(args.file, root=args.root)
    src = args.knowledge
    try:
        if src == "-":
            raw = sys.stdin.read()
        else:
            with open(src, "r", encoding="utf-8") as fh:
                raw = fh.read()
        index = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"could not read knowledge index from {src!r}: {exc}\n")
        return 1
    if not isinstance(index, dict):
        sys.stderr.write("knowledge index must be a JSON object "
                         "(id -> {version?, content_hash?, status?})\n")
        return 1

    stale = []
    for f in state.get("findings", []):
        if not isinstance(f, dict):
            continue
        reasons = knowledge_reverification_reasons(f, index)
        if reasons:
            stale.append({
                "id": f.get("id"),
                "title": f.get("title"),
                "status": f.get("status"),
                "requires_reverification": True,
                "reasons": reasons,
            })
    stale.sort(key=lambda r: r.get("id") or "")
    print(json.dumps(stale, indent=2, sort_keys=True))
    return 0


def cmd_validate(args) -> int:
    try:
        state = load_state(args.file, recover=False, root=args.root)
    except StateError as exc:
        sys.stderr.write(f"invalid: {exc}\n")
        return 1
    errors = validate_state(state)
    if errors:
        sys.stderr.write("invalid:\n  " + "\n  ".join(errors) + "\n")
        return 1
    print(json.dumps({"status": "valid",
                      "findings": len(state.get("findings", []))}, indent=2))
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="AttestArc findings state manager")
    p.add_argument("--file", default=DEFAULT_FILE,
                   help="path to findings.json (default: <root>/.attestarc/findings.json)")
    sub = p.add_subparsers(dest="command", required=True)

    # --root is accepted on every subcommand: it confines all writes to the
    # assessed repository and is the base for a relative --file, so the skill
    # can invoke this helper from its own package directory.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=None,
                        help="assessed repository root; confines all writes and "
                             "is the base for a relative --file. When omitted, "
                             "it is inferred from --file (the directory that "
                             "contains .attestarc).")

    sp = sub.add_parser("init", parents=[common], help="initialize findings state")
    sp.add_argument("--force", action="store_true",
                    help="reinitialize even if the file exists")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("list", parents=[common], help="list findings (facts)")
    sp.add_argument("--status", choices=STATUSES)
    sp.add_argument("--domain", choices=DOMAINS)
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("get", parents=[common], help="get a finding by id")
    sp.add_argument("id")
    sp.set_defaults(func=cmd_get)

    sp = sub.add_parser("upsert", parents=[common],
                        help="insert or update a finding from JSON")
    sp.add_argument("source", help="path to a finding JSON file, or '-' for stdin")
    sp.set_defaults(func=cmd_upsert)

    sp = sub.add_parser("set-status", parents=[common],
                        help="change a finding's status")
    sp.add_argument("id")
    sp.add_argument("status", choices=STATUSES)
    sp.add_argument("--reason")
    sp.add_argument("--by")
    sp.add_argument("--expires",
                    help="ISO-8601 expiry for an accepted_risk acceptance "
                         "(risk_acceptance.expires_at); past it the acceptance "
                         "has lapsed and the finding should be re-reviewed")
    sp.set_defaults(func=cmd_set_status)

    sp = sub.add_parser("resolve", parents=[common],
                        help="mark a finding resolved (after verify)")
    sp.add_argument("id")
    sp.add_argument("--method")
    sp.add_argument("--observed")
    sp.set_defaults(func=cmd_resolve)

    sp = sub.add_parser("record-safety-event", parents=[common],
                        help="record a prompt-injection/manipulation attempt "
                             "aimed at AttestArc (never a target finding)")
    sp.add_argument("source", choices=_SAFETY_SOURCES + ("-",),
                    help="where the manipulation attempt appeared, or '-' to "
                         "read a JSON payload {source, location?, action_taken?, "
                         "content?, excerpt?} from stdin (keeps untrusted text "
                         "off the command line)")
    sp.add_argument("--location", help="e.g. a file path or tool name")
    sp.add_argument("--excerpt",
                    help="short already-sanitized excerpt to persist as inert "
                         "evidence; a content_hash is always recorded")
    sp.add_argument("--action", help="what the assessor did")
    sp.set_defaults(func=cmd_record_safety_event)

    sp = sub.add_parser("reverify", parents=[common],
                        help="list findings whose verified-knowledge "
                             "dependencies changed (read-only view)")
    sp.add_argument("--knowledge", default="-",
                    help="path to the current knowledge index JSON "
                         "(id -> {version?, content_hash?, status?}) from "
                         "knowledge.py, or '-' for stdin (default)")
    sp.set_defaults(func=cmd_reverify)

    sp = sub.add_parser("validate", parents=[common],
                        help="validate the findings file")
    sp.set_defaults(func=cmd_validate)

    return p


# Commands that write state. They require an explicit --root so the write
# confinement (and now the read confinement) is code-enforced, not inferred from
# a caller-supplied --file — the boundary must not be steerable by prompt.
_MUTATING_COMMANDS = (
    "init", "upsert", "set-status", "resolve", "record-safety-event",
)


def _resolve_root_and_file(args) -> None:
    """Resolve the findings ``--file`` path and the confinement ``--root``.

    Two invocation styles:

    * With an explicit ``--root`` (how the skill invokes this from its own
      package directory): a relative ``--file`` is taken under that root and
      every read/write is confined to it. **Required for mutating commands.**
    * Without ``--root`` (read-only commands only): the (possibly absolute)
      ``--file`` location is trusted as-is, and the confinement root is
      *inferred* from it — the directory that contains ``.attestarc`` if the file
      lives there, else the file's own directory. A symlink that escapes that
      inferred root is still refused by the containment checks.

    Defaulting ``--root`` to ``.`` used to break the common case of pointing an
    absolute ``--file`` at another repository: the write was wrongly refused as
    "outside the repository root" because the root was still the skill's CWD.
    """
    explicit_root = getattr(args, "root", None)
    command = getattr(args, "command", None)
    if explicit_root is None and command in _MUTATING_COMMANDS:
        raise StateError(
            f"{command} requires an explicit --root (the assessed repository "
            "root). It confines every read and write to that repository; the "
            "boundary is code-enforced, not inferred from --file."
        )
    if not os.path.isabs(args.file):
        args.file = os.path.join(explicit_root or ".", args.file)
    if explicit_root is not None:
        args.root = explicit_root
        return
    parent = os.path.dirname(os.path.abspath(args.file))
    args.root = (os.path.dirname(parent)
                 if os.path.basename(parent) == ".attestarc" else parent)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        _resolve_root_and_file(args)
        return args.func(args)
    except StateError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
