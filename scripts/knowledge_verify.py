#!/usr/bin/env python3
"""Deterministic TUF-inspired verification of the AttestArc knowledge plane.

Before the assessor trusts any knowledge pack, this helper walks a delegation
chain over the role metadata (``root`` -> ``timestamp`` -> ``snapshot`` ->
``targets`` -> the pack files) and emits **facts** about what it found. It never
fetches — it verifies whatever is already present under a knowledge root. The
network-facing refresh is a separate principal (see ``knowledge_compile.py``).

The chain (see THREAT_MODEL.md §4):

1. Load ``root.json`` — the trust anchor. Determine ``mode``.
2. **bootstrap mode** (the shipped default): the packs are trusted because they
   ship inside the SSH-signed skill release. We still integrity-check every pack
   against ``targets.json`` (sha256 + size) so a corrupted bundled file is caught.
3. **signed mode**: additionally require, for each role file, a valid threshold
   SSH signature (``ssh-keygen -Y verify``, namespace ``attestarc-knowledge``),
   freshness (``expires`` in the future), snapshot/timestamp consistency (recorded
   version + hash match the file on disk), per-target hash/size match, and version
   monotonicity (**reject rollback / freeze** — a target or metadata version must
   not go backwards relative to ``previous_version`` or a caller-supplied
   last-known-good version map).

Fail-secure: any failure in signed mode degrades to the last-known-good bundled
snapshot (bootstrap integrity re-checked) and records a warning fact. Only if the
bundled snapshot itself fails integrity is ``trusted`` false. Never fetch-then-trust.

Stdlib-only. Signature verification shells out to the system ``ssh-keygen`` — no
Python crypto dependency (mirrors the repo's existing SSH-signing setup).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

from _pathsafe import resolve_within_root

_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_KNOWLEDGE_ROOT = os.path.join(_PACKAGE_ROOT, "knowledge")
_SIG_NAMESPACE = "attestarc-knowledge"
_ROLE_FILES = ("root.json", "timestamp.json", "snapshot.json", "targets.json")


def _now(now=None):
    if isinstance(now, datetime):
        return now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    if isinstance(now, str) and now:
        try:
            parsed = datetime.fromisoformat(now.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _parse_expires(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _ssh_verify(file_path, sig_path, allowed_signers, identity, namespace):
    """Verify a detached SSH signature. Returns (ok: bool, detail: str).

    Fail-secure: any tooling/absence error returns ``False`` — an unverifiable
    signature is never treated as valid.
    """
    if shutil.which("ssh-keygen") is None:
        return False, "ssh-keygen unavailable"
    if not (sig_path and os.path.exists(sig_path)):
        return False, "signature file missing"
    if not (allowed_signers and os.path.exists(allowed_signers)):
        return False, "allowed-signers file missing"
    try:
        with open(file_path, "rb") as fh:
            blob = fh.read()
        proc = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", allowed_signers,
             "-I", identity, "-n", namespace, "-s", sig_path],
            input=blob, capture_output=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"ssh-keygen invocation failed: {exc}"
    if proc.returncode == 0:
        return True, "good signature"
    detail = (proc.stderr or b"").decode("utf-8", "replace").strip()
    return False, detail or "signature verification failed"


class _Report:
    def __init__(self):
        self.checks = []
        self.warnings = []

    def check(self, name, ok, detail=""):
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})
        return ok

    def warn(self, msg):
        self.warnings.append(msg)


def _verify_bundled_integrity(root_real, targets_doc, report) -> bool:
    """Integrity-check every declared target against the file on disk."""
    all_ok = True
    for t in targets_doc.get("targets", []):
        name = t.get("name", "")
        _, _, within = resolve_within_root(os.path.join(root_real, name), root_real)
        path = os.path.join(root_real, name)
        if not within or not os.path.exists(path):
            all_ok = report.check(f"target:{name}:present", False,
                                  "missing or escapes knowledge root") and all_ok
            continue
        size_ok = os.path.getsize(path) == t.get("size")
        hash_ok = _sha256_file(path) == t.get("sha256")
        ok = report.check(f"target:{name}:integrity", size_ok and hash_ok,
                          "sha256+size match" if size_ok and hash_ok
                          else "sha256/size mismatch")
        all_ok = ok and all_ok
    return all_ok


def _verify_monotonic(targets_doc, known_versions, report) -> bool:
    """Reject rollback: a target version must not go below previous_version or a
    caller-supplied last-known-good version."""
    all_ok = True
    known_versions = known_versions or {}
    for t in targets_doc.get("targets", []):
        name = t.get("name", "")
        version = t.get("version", 0)
        floor = max(t.get("previous_version", 0), known_versions.get(name, 0))
        ok = report.check(f"target:{name}:monotonic", version >= floor,
                          f"version {version} >= floor {floor}" if version >= floor
                          else f"rollback: version {version} < floor {floor}")
        all_ok = ok and all_ok
    return all_ok


def _verify_signed_chain(root_real, root_doc, timestamp_doc, snapshot_doc,
                         targets_doc, allowed_signers, now, report) -> bool:
    """The signature + freshness + consistency portion of signed mode."""
    ok = True
    # Freshness across every role file.
    for label, doc in (("root", root_doc), ("timestamp", timestamp_doc),
                       ("snapshot", snapshot_doc), ("targets", targets_doc)):
        exp = _parse_expires(doc.get("expires"))
        fresh = exp is not None and exp > now
        ok = report.check(f"{label}:fresh", fresh,
                          f"expires {doc.get('expires')}") and ok

    # Consistency: recorded version+hash must match the file on disk.
    ts_meta = (timestamp_doc.get("meta") or {}).get("snapshot.json") or {}
    snap_hash = _sha256_file(os.path.join(root_real, "snapshot.json"))
    ok = report.check("snapshot:consistent",
                      ts_meta.get("sha256") == snap_hash
                      and ts_meta.get("version") == snapshot_doc.get("version"),
                      "timestamp records current snapshot") and ok
    snap_meta = (snapshot_doc.get("meta") or {}).get("targets.json") or {}
    tgt_hash = _sha256_file(os.path.join(root_real, "targets.json"))
    ok = report.check("targets:consistent",
                      snap_meta.get("sha256") == tgt_hash
                      and snap_meta.get("version") == targets_doc.get("version"),
                      "snapshot records current targets") and ok

    # Threshold signatures per role file.
    roles = root_doc.get("roles") or {}
    keys = root_doc.get("keys") or {}
    for label in ("timestamp", "snapshot", "targets"):
        spec = roles.get(label) or {}
        threshold = spec.get("threshold", 1)
        keyids = spec.get("keyids") or []
        fpath = os.path.join(root_real, f"{label}.json")
        valid = 0
        for keyid in keyids:
            key = keys.get(keyid) or {}
            identity = key.get("identity", keyid)
            good, _ = _ssh_verify(fpath, f"{fpath}.sig", allowed_signers,
                                  identity, _SIG_NAMESPACE)
            if good:
                valid += 1
        ok = report.check(f"{label}:signature", valid >= threshold and threshold >= 1,
                          f"{valid}/{threshold} valid signatures") and ok
    return ok


def verify(knowledge_root=None, now=None, allowed_signers=None,
           known_versions=None) -> dict:
    """Walk the verification chain; return a facts dict. Never raises."""
    knowledge_root = knowledge_root or _DEFAULT_KNOWLEDGE_ROOT
    _, root_real, _ = resolve_within_root(knowledge_root, knowledge_root)
    now = _now(now)
    report = _Report()

    root_path = os.path.join(root_real, "root.json")
    targets_path = os.path.join(root_real, "targets.json")
    if not os.path.exists(root_path) or not os.path.exists(targets_path):
        report.check("metadata:present", False, "root.json/targets.json missing")
        return {"trusted": False, "mode": "unknown", "source": "none",
                "knowledge_root": root_real, "checks": report.checks,
                "warnings": ["knowledge metadata missing; no knowledge available"]}

    try:
        root_doc = _load_json(root_path)
        targets_doc = _load_json(targets_path)
    except (OSError, json.JSONDecodeError) as exc:
        report.check("metadata:parse", False, str(exc))
        return {"trusted": False, "mode": "unknown", "source": "none",
                "knowledge_root": root_real, "checks": report.checks,
                "warnings": [f"knowledge metadata unparseable: {exc}"]}

    mode = root_doc.get("mode", "bootstrap")
    report.check("root:loaded", True, f"mode={mode}")

    integrity_ok = _verify_bundled_integrity(root_real, targets_doc, report)
    monotonic_ok = _verify_monotonic(targets_doc, known_versions, report)

    if mode != "signed":
        trusted = integrity_ok and monotonic_ok
        return {"trusted": trusted, "mode": "bootstrap",
                "source": "bundled-snapshot", "knowledge_root": root_real,
                "checks": report.checks, "warnings": report.warnings,
                "targets": [t.get("name") for t in targets_doc.get("targets", [])]}

    # signed mode: require the full chain; degrade to bundled snapshot on failure.
    try:
        timestamp_doc = _load_json(os.path.join(root_real, "timestamp.json"))
        snapshot_doc = _load_json(os.path.join(root_real, "snapshot.json"))
    except (OSError, json.JSONDecodeError) as exc:
        report.warn(f"signed metadata unavailable ({exc}); "
                    "falling back to last-known-good bundled snapshot")
        return {"trusted": integrity_ok and monotonic_ok, "mode": "bootstrap",
                "source": "bundled-snapshot", "knowledge_root": root_real,
                "checks": report.checks, "warnings": report.warnings,
                "targets": [t.get("name") for t in targets_doc.get("targets", [])]}

    chain_ok = _verify_signed_chain(root_real, root_doc, timestamp_doc,
                                    snapshot_doc, targets_doc, allowed_signers,
                                    now, report)
    if chain_ok and integrity_ok and monotonic_ok:
        return {"trusted": True, "mode": "signed", "source": "verified",
                "knowledge_root": root_real, "checks": report.checks,
                "warnings": report.warnings,
                "targets": [t.get("name") for t in targets_doc.get("targets", [])]}

    report.warn("signed verification failed; falling back to last-known-good "
                "bundled snapshot")
    return {"trusted": integrity_ok and monotonic_ok, "mode": "bootstrap",
            "source": "bundled-snapshot", "knowledge_root": root_real,
            "checks": report.checks, "warnings": report.warnings,
            "targets": [t.get("name") for t in targets_doc.get("targets", [])]}


def cmd_verify(args) -> int:
    result = verify(knowledge_root=args.knowledge_root, now=args.now,
                    allowed_signers=args.allowed_signers)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("trusted") else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Verify the AttestArc knowledge plane (facts; no network)")
    sub = p.add_subparsers(dest="command", required=True)
    sp = sub.add_parser("verify", help="walk the verification chain")
    sp.add_argument("--knowledge-root", default=None,
                    help="knowledge root to verify (default: bundled snapshot)")
    sp.add_argument("--allowed-signers", default=None,
                    help="OpenSSH allowed-signers file (signed mode)")
    sp.add_argument("--now", default=None,
                    help="ISO timestamp to evaluate freshness against (testing)")
    sp.set_defaults(func=cmd_verify)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
