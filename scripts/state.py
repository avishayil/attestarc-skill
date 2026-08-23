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
    state.py validate

All commands accept ``--file`` (default ``.attestarc/findings.json``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone

from _pathsafe import resolve_within_root

# Bumped to 2 in v0.3.0: finding ids widened to 8 hex chars and the fingerprint
# no longer hashes the free-text ``condition`` (it hashes a canonical
# ``subject`` instead), so ids from schema_version 1 are not comparable.
SCHEMA_VERSION = 2

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


def load_state(path: str, *, recover: bool = True) -> dict:
    """Load state. On corrupt JSON, back it up and reinitialize (if recover)."""
    if not os.path.exists(path):
        raise StateError(
            f"{path} does not exist. Run 'state.py init' first."
        )
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        if not recover:
            raise StateError(f"{path} is not valid JSON: {exc}") from exc
        backup = _backup_corrupt(path)
        state = _empty_state()
        save_state(state, path)
        sys.stderr.write(
            f"warning: {path} was corrupt ({exc}); backed up to {backup} and "
            f"reinitialized.\n"
        )
        return state
    if not isinstance(data, dict):
        raise StateError(f"{path} does not contain a JSON object.")
    return data


# --------------------------------------------------------------------------- #
# Validation (hand-rolled; no jsonschema dependency)
# --------------------------------------------------------------------------- #
def validate_state(state: dict) -> list[str]:
    """Return a list of human-readable validation errors ([] if valid)."""
    errors: list[str] = []

    def err(msg: str) -> None:
        errors.append(msg)

    if state.get("schema_version") != SCHEMA_VERSION:
        err(f"schema_version must be {SCHEMA_VERSION}")
    for key in ("repository", "created_at", "updated_at", "findings"):
        if key not in state:
            err(f"missing top-level key: {key}")

    repo = state.get("repository")
    if not isinstance(repo, dict) or "root" not in repo:
        err("repository must be an object containing 'root'")

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
        fid = f.get("id")
        if isinstance(fid, str):
            if not re.fullmatch(r"AA-[A-Z]{2,4}-[0-9A-F]{8}", fid):
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
        if not isinstance(f.get("evidence"), list):
            err(f"{where}.evidence must be an array")
        else:
            try:
                _assert_no_secrets(f)
            except StateError as exc:
                err(f"{where}: {exc}")
    return errors


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
                        "trust_boundary", "related_findings"):
                if key in incoming:
                    merged[key] = incoming[key]
            merged["evidence"] = _merge_evidence(
                existing.get("evidence", []), incoming.get("evidence", [])
            )
            merged["last_seen"] = now
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
    findings.append(incoming)
    return incoming, True


def find_by_id(state: dict, fid: str) -> dict | None:
    for f in state.get("findings", []):
        if f.get("id") == fid:
            return f
    return None


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
        state = load_state(path)
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
    state = load_state(args.file)
    findings = list(state.get("findings", []))
    if args.status:
        findings = [f for f in findings if f.get("status") == args.status]
    if args.domain:
        findings = [f for f in findings if f.get("domain") == args.domain]
    findings.sort(key=_sort_key)
    print(json.dumps(findings, indent=2, sort_keys=True))
    return 0


def cmd_get(args) -> int:
    state = load_state(args.file)
    f = find_by_id(state, args.id)
    if f is None:
        sys.stderr.write(f"no finding with id {args.id}\n")
        return 1
    print(json.dumps(f, indent=2, sort_keys=True))
    return 0


def _read_finding_input(source: str) -> dict:
    if source == "-":
        raw = sys.stdin.read()
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


def cmd_upsert(args) -> int:
    state = load_state(args.file)
    finding = _read_finding_input(args.source)
    stored, created = upsert_finding(state, finding)
    save_state(state, args.file, root=args.root)
    print(json.dumps(
        {"action": "created" if created else "updated", "id": stored["id"],
         "fingerprint": stored["fingerprint"], "status": stored["status"]},
        indent=2,
    ))
    return 0


def cmd_set_status(args) -> int:
    state = load_state(args.file)
    f = find_by_id(state, args.id)
    if f is None:
        sys.stderr.write(f"no finding with id {args.id}\n")
        return 1
    if args.status not in STATUSES:
        sys.stderr.write(
            f"invalid status {args.status!r}; choose from {', '.join(STATUSES)}\n"
        )
        return 1
    f["status"] = args.status
    f["last_seen"] = _now()
    if args.status == "accepted_risk":
        f["accepted_by"] = args.by or "user"
        f["accepted_at"] = _now()
        if args.reason:
            f["reason"] = args.reason
    elif args.reason:
        f["reason"] = args.reason
    save_state(state, args.file, root=args.root)
    print(json.dumps({"id": f["id"], "status": f["status"]}, indent=2))
    return 0


def cmd_resolve(args) -> int:
    """Mark a finding resolved after verification.

    Verification is the host agent's responsibility (re-observe the condition);
    this records the verified outcome supplied on the command line.
    """
    state = load_state(args.file)
    f = find_by_id(state, args.id)
    if f is None:
        sys.stderr.write(f"no finding with id {args.id}\n")
        return 1
    now = _now()
    f["status"] = "resolved"
    f["last_seen"] = now
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


def cmd_validate(args) -> int:
    try:
        state = load_state(args.file, recover=False)
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
    sp.set_defaults(func=cmd_set_status)

    sp = sub.add_parser("resolve", parents=[common],
                        help="mark a finding resolved (after verify)")
    sp.add_argument("id")
    sp.add_argument("--method")
    sp.add_argument("--observed")
    sp.set_defaults(func=cmd_resolve)

    sp = sub.add_parser("validate", parents=[common],
                        help="validate the findings file")
    sp.set_defaults(func=cmd_validate)

    return p


def _resolve_root_and_file(args) -> None:
    """Resolve the findings ``--file`` path and the write-confinement ``--root``.

    Two invocation styles, both safe:

    * With an explicit ``--root`` (how the skill invokes this from its own
      package directory): a relative ``--file`` is taken under that root and
      every write is confined to it.
    * Without ``--root``: the (possibly absolute) ``--file`` location is
      trusted as-is, and the confinement root is *inferred* from it — the
      directory that contains ``.attestarc`` if the file lives there, else the
      file's own directory. A symlinked ``.attestarc`` that escapes that
      inferred root is still refused by ``_assert_within_root``.

    Defaulting ``--root`` to ``.`` used to break the common case of pointing an
    absolute ``--file`` at another repository: the write was wrongly refused as
    "outside the repository root" because the root was still the skill's CWD.
    """
    explicit_root = getattr(args, "root", None)
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
    _resolve_root_and_file(args)
    try:
        return args.func(args)
    except StateError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
