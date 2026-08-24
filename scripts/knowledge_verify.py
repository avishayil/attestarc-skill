#!/usr/bin/env python3
"""Deterministic verification of the AttestArc knowledge plane (facts; no verdicts).

Trust model (see THREAT_MODEL.md §4). The root of trust is an **external anchor**
that ships inside the SSH-signed skill release — ``knowledge/trust-anchor.json`` —
and lives OUTSIDE any downloaded bundle. It pins the Sigstore build-provenance
identity (repo + signer workflow + OIDC issuer) that an official knowledge bundle
must have been produced under. A bundle can therefore never declare its own trust;
the homemade ``root/timestamp/snapshot/targets`` role-file protocol is gone.

Two verification entry points:

* ``verify_installed`` — the ASSESSOR-facing path. Verifies an already-installed
  snapshot with **no network and no external tooling**. The immutable in-package
  snapshot is trusted because it rode in on the signed release (``bootstrap``). A
  refreshed snapshot under ``~/.attestarc/knowledge`` is trusted only if the
  persistent client state records that this exact version+digest was previously
  attestation-verified. Anything else is untrusted.

* ``verify_download`` — the UPDATER-facing path. Verifies a freshly-downloaded
  bundle by shelling out to ``gh attestation verify`` with the anchor's identity
  constraints, then checks manifest integrity, freshness (freeze protection),
  monotonic version + prev_digest chain (rollback protection), and revocation.
  **Any failure discards the download** — no metadata from a failed bundle ever
  participates in a fallback; the installed last-known-good is retained.

Fail-secure everywhere: a downloaded bundle claiming ``mode: bootstrap`` is
rejected; a missing/absent ``gh`` makes attestation verification fail (never
pass); rollback/freeze/revoked bundles are discarded. Never fetch-then-trust.

Stdlib-only. Attestation verification shells out to the system ``gh`` CLI (no
Python crypto dependency — mirrors the ``ssh-keygen`` shell-out convention).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

from _pathsafe import resolve_within_root

_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_KNOWLEDGE_ROOT = os.path.join(_PACKAGE_ROOT, "knowledge")
_ANCHOR_FILE = "trust-anchor.json"
_MANIFEST_FILE = "manifest.json"
_STATE_FILE = "trusted-state.json"


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# Hash + IO helpers
# --------------------------------------------------------------------------- #
def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


class _Report:
    def __init__(self):
        self.checks = []
        self.warnings = []

    def check(self, name, ok, detail=""):
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    def warn(self, msg):
        self.warnings.append(msg)


# --------------------------------------------------------------------------- #
# Trust anchor + persistent client state
# --------------------------------------------------------------------------- #
def load_anchor(package_root=None) -> dict:
    """Load the external trust anchor from the in-package knowledge dir.

    The anchor is NEVER read from a caller-supplied or downloaded root — it is the
    one root of trust and must come from the signed skill package.
    """
    root = os.path.join(package_root or _PACKAGE_ROOT, "knowledge")
    path = os.path.join(root, _ANCHOR_FILE)
    return _load_json(path)


def _expand_state_dir(anchor: dict) -> str:
    raw = (anchor or {}).get("client_state_dir") or "~/.attestarc/knowledge"
    return os.path.abspath(os.path.expanduser(raw))


def client_state_path(anchor: dict) -> str:
    return os.path.join(_expand_state_dir(anchor), _STATE_FILE)


def load_client_state(anchor: dict) -> dict:
    """Persistent last-known-good state, OUTSIDE any repo or bundle.

    The attacker cannot supply this; it is the client's own memory of the highest
    version it has trusted and the digests it installed. Missing/unparseable state
    degrades to a conservative empty floor (highest_version 0).
    """
    path = client_state_path(anchor)
    empty = {"highest_version": 0, "current": None,
             "revoked_versions": [], "history": []}
    if not os.path.exists(path):
        return empty
    try:
        data = _load_json(path)
    except (OSError, json.JSONDecodeError):
        return empty
    if not isinstance(data, dict):
        return empty
    data.setdefault("highest_version", 0)
    data.setdefault("current", None)
    data.setdefault("revoked_versions", [])
    data.setdefault("history", [])
    return data


def save_client_state(anchor: dict, state: dict) -> str:
    """Atomically write client state, confined to the state dir."""
    state_dir = _expand_state_dir(anchor)
    os.makedirs(state_dir, exist_ok=True)
    path = os.path.join(state_dir, _STATE_FILE)
    _, root_real, within = resolve_within_root(path, state_dir)
    if not within:
        raise ValueError("refusing to write client state outside the state dir")
    fd, tmp = tempfile.mkstemp(dir=state_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return path


# --------------------------------------------------------------------------- #
# Manifest integrity
# --------------------------------------------------------------------------- #
def _load_manifest(root_real: str, report: _Report):
    mpath = os.path.join(root_real, _MANIFEST_FILE)
    if not os.path.exists(mpath):
        report.check("manifest:present", False, "manifest.json missing")
        return None, None
    try:
        manifest = _load_json(mpath)
    except (OSError, json.JSONDecodeError) as exc:
        report.check("manifest:parse", False, str(exc))
        return None, None
    report.check("manifest:present", True, f"version={manifest.get('version')}")
    return manifest, _sha256_file(mpath)


def _verify_pack_integrity(root_real: str, manifest: dict, report: _Report) -> bool:
    """Every declared pack must match its sha256+size on disk, and no undeclared
    pack may sit in the tree (a smuggled extra pack is a poisoning vector)."""
    all_ok = True
    declared = set()
    for p in manifest.get("packs", []):
        name = p.get("name", "")
        declared.add(name)
        _, _, within = resolve_within_root(os.path.join(root_real, name), root_real)
        path = os.path.join(root_real, name)
        if not within or not os.path.exists(path):
            all_ok = report.check(f"pack:{name}:present", False,
                                  "missing or escapes knowledge root") and all_ok
            continue
        size_ok = os.path.getsize(path) == p.get("size")
        hash_ok = _sha256_file(path) == p.get("sha256")
        all_ok = report.check(f"pack:{name}:integrity", size_ok and hash_ok,
                              "sha256+size match" if size_ok and hash_ok
                              else "sha256/size mismatch") and all_ok
    # Undeclared packs in the pack dir are rejected.
    for present in _list_pack_files(root_real):
        if present not in declared:
            all_ok = report.check(f"pack:{present}:declared", False,
                                  "pack present on disk but not in manifest") and all_ok
    return all_ok


def _list_pack_files(root_real: str):
    out = []
    boot = os.path.join(root_real, "bootstrap")
    if os.path.isdir(boot):
        for fn in sorted(os.listdir(boot)):
            if fn.endswith(".jsonl"):
                out.append(f"bootstrap/{fn}")
    return out


# --------------------------------------------------------------------------- #
# Attestation (gh) — network/tooling boundary; Updater only
# --------------------------------------------------------------------------- #
def _gh_attest_verify(artifact_path, anchor, offline_bundle=None):
    """Verify a Sigstore build-provenance attestation over ``artifact_path`` with
    the anchor's identity constraints. Returns (ok, detail).

    Fail-secure: a missing ``gh`` or any non-zero exit is a verification FAILURE,
    never a pass.
    """
    if shutil.which("gh") is None:
        return False, "gh unavailable (cannot verify attestation)"
    repo = (anchor or {}).get("repo")
    if not repo:
        return False, "anchor missing repo"
    cmd = ["gh", "attestation", "verify", artifact_path, "--repo", repo]
    # gh treats [signer-workflow, cert-identity, cert-identity-regex, signer-repo]
    # as a mutually-exclusive group. Prefer the higher-level signer-workflow
    # constraint; fall back to the SAN identity regexp only if no workflow is
    # pinned. --cert-oidc-issuer is orthogonal and always applied.
    signer_workflow = (anchor or {}).get("signer_workflow")
    ident_re = (anchor or {}).get("cert_identity_regexp")
    if signer_workflow:
        cmd += ["--signer-workflow", f"{repo}/{signer_workflow.lstrip('/')}"]
    elif ident_re:
        cmd += ["--cert-identity-regex", ident_re]
    issuer = (anchor or {}).get("cert_oidc_issuer")
    if issuer:
        cmd += ["--cert-oidc-issuer", issuer]
    if offline_bundle:
        cmd += ["--bundle", offline_bundle]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"gh invocation failed: {exc}"
    if proc.returncode == 0:
        return True, "attestation verified"
    detail = (proc.stderr or b"").decode("utf-8", "replace").strip()
    return False, detail or "attestation verification failed"


# --------------------------------------------------------------------------- #
# verify_installed — assessor-facing (no network, no gh)
# --------------------------------------------------------------------------- #
def verify_installed(knowledge_root=None, anchor=None, client_state=None,
                     now=None, package_root=None) -> dict:
    """Verify an already-installed snapshot for assessor reads. Never raises."""
    package_knowledge = os.path.join(package_root or _PACKAGE_ROOT, "knowledge")
    knowledge_root = knowledge_root or _DEFAULT_KNOWLEDGE_ROOT
    _, root_real, _ = resolve_within_root(knowledge_root, knowledge_root)
    _, pkg_real, _ = resolve_within_root(package_knowledge, package_knowledge)
    is_package = root_real == pkg_real
    now = _now(now)
    report = _Report()
    if anchor is None:
        try:
            anchor = load_anchor(package_root)
        except (OSError, json.JSONDecodeError):
            anchor = {}
    if client_state is None:
        client_state = load_client_state(anchor)

    manifest, manifest_digest = _load_manifest(root_real, report)
    if manifest is None:
        return _untrusted(report, root_real, source="none")

    # A downloaded/installed snapshot may never confer bootstrap trust on itself.
    if manifest.get("mode") == "bootstrap" and not is_package:
        report.check("bootstrap:in-package", False,
                     "non-package snapshot declares bootstrap; rejected")
        return _untrusted(report, root_real, source="rejected")

    version = manifest.get("version", 0)
    revoked = version in (client_state.get("revoked_versions") or [])
    report.check("revocation", not revoked,
                 f"version {version} revoked" if revoked else "not revoked")

    integrity_ok = _verify_pack_integrity(root_real, manifest, report)

    exp = _parse_expires(manifest.get("expires"))
    expired = exp is not None and exp <= now
    if expired:
        report.warn(f"manifest expired {manifest.get('expires')}; "
                    "using last-known-good and recommending refresh")

    if is_package:
        # The immutable bundled snapshot: trusted because it shipped in the signed
        # release. Expiry only warns — it is the last-known-good floor.
        trusted = integrity_ok and not revoked
        source = "bootstrap-snapshot"
    else:
        # A refreshed snapshot: trusted only if client state confirms this exact
        # version+digest was previously attestation-verified.
        cur = client_state.get("current") or {}
        matches = (cur.get("version") == version
                   and cur.get("manifest_sha256") == manifest_digest
                   and cur.get("verified_via") == "attestation")
        report.check("client-state:attested", matches,
                     "client state confirms prior attestation"
                     if matches else "no attestation record for this snapshot")
        trusted = integrity_ok and matches and not revoked
        source = "verified-lkg" if trusted else "unverified"

    return {"trusted": trusted, "source": source, "knowledge_root": root_real,
            "version": version, "manifest_sha256": manifest_digest,
            "is_package_bootstrap": is_package,
            "checks": report.checks, "warnings": report.warnings,
            "packs": [p.get("name") for p in manifest.get("packs", [])]}


def _untrusted(report, root_real, source):
    return {"trusted": False, "source": source, "knowledge_root": root_real,
            "version": None, "manifest_sha256": None,
            "checks": report.checks, "warnings": report.warnings, "packs": []}


# --------------------------------------------------------------------------- #
# verify_download — updater-facing (attestation-gated)
# --------------------------------------------------------------------------- #
def verify_download(bundle_dir, anchor=None, client_state=None, now=None,
                    offline_bundle=None, package_root=None) -> dict:
    """Verify a freshly-downloaded bundle. Any failure => action 'discard'."""
    _, bundle_real, _ = resolve_within_root(bundle_dir, bundle_dir)
    now = _now(now)
    report = _Report()
    if anchor is None:
        anchor = load_anchor(package_root)
    if client_state is None:
        client_state = load_client_state(anchor)

    def discard(reason):
        report.warn(f"discarding downloaded bundle: {reason}")
        return {"trusted": False, "action": "discard", "reason": reason,
                "bundle_dir": bundle_real, "checks": report.checks,
                "warnings": report.warnings}

    manifest, manifest_digest = _load_manifest(bundle_real, report)
    if manifest is None:
        return discard("manifest missing or unparseable")

    # A downloaded bundle may not claim bootstrap trust.
    if manifest.get("mode") == "bootstrap":
        report.check("bootstrap:rejected", False,
                     "downloaded bundle claims bootstrap; rejected")
        return discard("downloaded bundle claims bootstrap trust")

    # 1. Attestation over the manifest (which pins every pack hash).
    manifest_path = os.path.join(bundle_real, _MANIFEST_FILE)
    att_ok, att_detail = _gh_attest_verify(manifest_path, anchor, offline_bundle)
    report.check("attestation", att_ok, att_detail)
    if not att_ok:
        return discard(f"attestation failed: {att_detail}")

    # 2. Integrity of the packs the (now-authenticated) manifest pins.
    if not _verify_pack_integrity(bundle_real, manifest, report):
        return discard("pack integrity mismatch")

    # 3. Freshness — a stale/frozen download is rejected outright.
    exp = _parse_expires(manifest.get("expires"))
    fresh = exp is not None and exp > now
    report.check("fresh", fresh, f"expires {manifest.get('expires')}")
    if not fresh:
        return discard("manifest expired (freeze protection)")

    # 4. Rollback protection against persistent client memory (not the bundle).
    version = manifest.get("version", 0)
    floor = client_state.get("highest_version", 0)
    monotonic = version > floor
    report.check("monotonic", monotonic,
                 f"version {version} > highest trusted {floor}"
                 if monotonic else f"rollback: {version} <= {floor}")
    if not monotonic:
        return discard(f"rollback: version {version} <= highest trusted {floor}")

    # 5. prev_digest chain (if a prior version was installed).
    cur = client_state.get("current") or {}
    prev = manifest.get("prev_digest")
    if cur.get("manifest_sha256") and prev is not None:
        chained = prev == cur.get("manifest_sha256")
        report.check("chain", chained,
                     "prev_digest chains to installed manifest"
                     if chained else "prev_digest does not chain")
        if not chained:
            return discard("prev_digest does not chain to installed manifest")

    # 6. Revocation.
    if version in (client_state.get("revoked_versions") or []):
        report.check("revocation", False, f"version {version} revoked")
        return discard(f"version {version} is revoked")

    return {"trusted": True, "action": "install", "bundle_dir": bundle_real,
            "version": version, "manifest_sha256": manifest_digest,
            "identity": {"repo": anchor.get("repo"),
                         "signer_workflow": anchor.get("signer_workflow")},
            "packs": [p.get("name") for p in manifest.get("packs", [])],
            "checks": report.checks, "warnings": report.warnings}


def apply_revocation(anchor, revoked_version, client_state=None) -> dict:
    """Record a revocation in persistent client state (Updater path). Callers must
    only invoke this for an *attested* revocation record (see the release workflow)."""
    if client_state is None:
        client_state = load_client_state(anchor)
    revs = set(client_state.get("revoked_versions") or [])
    revs.add(revoked_version)
    client_state["revoked_versions"] = sorted(revs)
    save_client_state(anchor, client_state)
    return client_state


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def cmd_verify(args) -> int:
    """Assessor-facing: verify the installed/bundled snapshot (no network)."""
    result = verify_installed(knowledge_root=args.knowledge_root, now=args.now)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("trusted") else 1


def cmd_verify_download(args) -> int:
    """Updater-facing: attestation-verify a downloaded bundle."""
    result = verify_download(bundle_dir=args.bundle_dir, now=args.now,
                             offline_bundle=args.bundle)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("trusted") else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Verify the AttestArc knowledge plane (facts; no verdicts)")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("verify", help="verify the installed/bundled snapshot "
                                        "(assessor path; no network)")
    sp.add_argument("--knowledge-root", default=None,
                    help="installed snapshot to verify (default: bundled snapshot)")
    sp.add_argument("--now", default=None, help="ISO timestamp for freshness (testing)")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("verify-download",
                        help="attestation-verify a downloaded bundle (Updater path)")
    sp.add_argument("bundle_dir", help="directory holding the downloaded manifest+packs")
    sp.add_argument("--bundle", default=None,
                    help="offline Sigstore bundle for air-gapped verification")
    sp.add_argument("--now", default=None, help="ISO timestamp for freshness (testing)")
    sp.set_defaults(func=cmd_verify_download)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
