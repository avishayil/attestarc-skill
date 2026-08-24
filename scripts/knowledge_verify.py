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
import tarfile
import tempfile
from datetime import datetime, timezone

from _pathsafe import PathEscapeError, resolve_within_root, safe_extract_tar

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
    raw = (anchor or {}).get("client_state_dir") or "~/.attestarc/state"
    return os.path.abspath(os.path.expanduser(raw))


def _expand_snapshots_dir(anchor: dict) -> str:
    """Installed refreshed snapshots live here, SEPARATE from client state so a
    corrupted snapshot cannot damage rollback memory and vice-versa."""
    raw = (anchor or {}).get("snapshots_dir") or "~/.attestarc/knowledge/snapshots"
    return os.path.abspath(os.path.expanduser(raw))


def client_state_path(anchor: dict) -> str:
    return os.path.join(_expand_state_dir(anchor), _STATE_FILE)


def _empty_state() -> dict:
    return {"highest_version": 0, "highest_manifest_sha256": None,
            "current": None, "revoked_versions": [], "history": []}


def load_client_state(anchor: dict) -> dict:
    """Persistent last-known-good state, OUTSIDE any repo or bundle.

    The attacker cannot supply this; it is the client's own memory of the highest
    version it has trusted and the digests it installed. Two non-happy cases are
    deliberately distinguished:

    * **Missing** (no file) — a fresh machine. A conservative empty floor
      (``highest_version`` 0) is legitimate; dynamic updates may proceed.
    * **Present but corrupt/unparseable** — rollback memory is compromised (a
      truncated write, or tampering to erase the high-water mark so an old
      vulnerable version replays). Fail **closed**: return the empty floor marked
      ``_corrupt`` so update/revocation paths refuse to advance and the assessor
      falls back to the in-package bootstrap until an explicit reinit.
    """
    path = client_state_path(anchor)
    if not os.path.exists(path):
        return _empty_state()
    try:
        data = _load_json(path)
    except (OSError, json.JSONDecodeError):
        corrupt = _empty_state()
        corrupt["_corrupt"] = True
        return corrupt
    if not isinstance(data, dict):
        corrupt = _empty_state()
        corrupt["_corrupt"] = True
        return corrupt
    data.setdefault("highest_version", 0)
    data.setdefault("highest_manifest_sha256", None)
    data.setdefault("current", None)
    data.setdefault("revoked_versions", [])
    data.setdefault("history", [])
    # Legacy backfill: state written before highest_manifest_sha256 existed. If the
    # active snapshot is still the high-water version, its digest IS the chain head.
    if data["highest_manifest_sha256"] is None and data["highest_version"]:
        cur = data.get("current") or {}
        if cur.get("version") == data["highest_version"] and cur.get("manifest_sha256"):
            data["highest_manifest_sha256"] = cur["manifest_sha256"]
    return data


def state_is_corrupt(state: dict) -> bool:
    """True if client state was present but unusable (see :func:`load_client_state`)."""
    return bool((state or {}).get("_corrupt"))


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
def _anchor_identity_regexp(anchor, kind):
    """Return the artifact-SPECIFIC SAN identity regexp for ``kind`` (``"bundle"``
    or ``"revocation"``). A knowledge bundle must be signed from a release tag
    (refs/tags/knowledge-v<N>); a revocation must be signed from refs/heads/main.
    Falls back to a legacy combined ``cert_identity_regexp`` if an older anchor
    still carries one, so verification never silently loosens on upgrade."""
    anchor = anchor or {}
    key = ("cert_identity_regexp_revocation" if kind == "revocation"
           else "cert_identity_regexp_bundle")
    return anchor.get(key) or anchor.get("cert_identity_regexp")


def _gh_attest_verify(artifact_path, anchor, offline_bundle=None, kind="bundle"):
    """Verify a Sigstore build-provenance attestation over ``artifact_path`` with
    the anchor's ARTIFACT-SPECIFIC identity constraints. ``kind`` selects which
    reviewed ref the certificate SAN must bind: ``"bundle"`` → the release tag ref,
    ``"revocation"`` → refs/heads/main. Returns (ok, detail).

    Fail-secure: a missing ``gh``, an anchor with no regexp for this kind, or any
    non-zero exit is a verification FAILURE, never a pass.
    """
    if shutil.which("gh") is None:
        return False, "gh unavailable (cannot verify attestation)"
    repo = (anchor or {}).get("repo")
    if not repo:
        return False, "anchor missing repo"
    cmd = ["gh", "attestation", "verify", artifact_path, "--repo", repo]
    # gh treats [signer-workflow, cert-identity, cert-identity-regex, signer-repo]
    # as a mutually-exclusive group. We use the SAN identity regexp: unlike
    # --signer-workflow (which matches only the workflow PATH and ignores the git
    # ref), the regexp binds the certificate SAN's trailing "@<ref>". The regexp is
    # ARTIFACT-SPECIFIC (see _anchor_identity_regexp): a bundle attested off main,
    # or a revocation attested off a tag, fails here even though the workflow file
    # is the same. --cert-oidc-issuer is orthogonal and always applied.
    ident_re = _anchor_identity_regexp(anchor, kind)
    if ident_re:
        cmd += ["--cert-identity-regex", ident_re]
    else:
        return False, f"anchor missing cert_identity_regexp for kind={kind!r}"
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

    # Freshness is a SEPARATE dimension from integrity/trust. An expired bundled
    # snapshot stays trusted (it is the last-known-good floor), but downstream the
    # assessor treats a stale snapshot's mitigation/down-gate facts as
    # non-conclusion-driving (see knowledge.py apply_freshness). A manifest with no
    # expiry is treated as fresh.
    fresh = not expired
    return {"trusted": trusted, "source": source, "knowledge_root": root_real,
            "version": version, "manifest_sha256": manifest_digest,
            "is_package_bootstrap": is_package,
            "fresh": fresh, "expires": manifest.get("expires"),
            "checks": report.checks, "warnings": report.warnings,
            "packs": [p.get("name") for p in manifest.get("packs", [])]}


def _untrusted(report, root_real, source):
    return {"trusted": False, "source": source, "knowledge_root": root_real,
            "version": None, "manifest_sha256": None,
            "fresh": False, "expires": None,
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

    # 5. prev_digest chain against the HIGH-WATER manifest (the chain head), not the
    # active `current` — a revocation lowers `current` for assessment but must not
    # break the update chain, or the client could never move past a revoked release.
    # Once any prior version was installed (floor > 0), prev_digest is REQUIRED
    # (fail-closed): silently omitting it must not skip chain validation.
    head = client_state.get("highest_manifest_sha256")
    if head is None:
        # Legacy state (written before the chain head existed): if the active
        # snapshot is still the high-water version, its digest IS the head.
        cur = client_state.get("current") or {}
        if cur.get("version") == floor and cur.get("manifest_sha256"):
            head = cur["manifest_sha256"]
    prev = manifest.get("prev_digest")
    if floor > 0:
        if prev is None:
            return discard("prev_digest required (a prior version was installed) "
                           "but the manifest omits it")
        if head is not None and prev != head:
            report.check("chain", False, "prev_digest does not chain to high-water")
            return discard("prev_digest does not chain to the high-water manifest")
        report.check("chain", True, "prev_digest chains to high-water manifest")

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


# --------------------------------------------------------------------------- #
# install — the ONLY path that advances client state (Updater)
# --------------------------------------------------------------------------- #
def _locate_bundle_root(extract_root: str) -> str:
    """Find the directory holding manifest.json after a safe extraction — either
    ``extract_root`` itself or a single top-level subdirectory (a common tar shape)."""
    if os.path.exists(os.path.join(extract_root, _MANIFEST_FILE)):
        return extract_root
    subdirs = [os.path.join(extract_root, d) for d in sorted(os.listdir(extract_root))
               if os.path.isdir(os.path.join(extract_root, d))]
    if len(subdirs) == 1 and os.path.exists(os.path.join(subdirs[0], _MANIFEST_FILE)):
        return subdirs[0]
    raise ValueError("no manifest.json found in extracted bundle")


def _copy_declared(bundle_dir: str, dest_dir: str, pack_names) -> None:
    """Copy manifest.json and exactly the declared packs into ``dest_dir``,
    refusing any path that escapes either root. Nothing else is copied."""
    os.makedirs(dest_dir, exist_ok=True)
    _, bundle_real, _ = resolve_within_root(bundle_dir, bundle_dir)
    for rel in [_MANIFEST_FILE] + list(pack_names or []):
        src = os.path.join(bundle_real, rel)
        _, _, src_ok = resolve_within_root(src, bundle_real)
        dst = os.path.join(dest_dir, rel)
        _, _, dst_ok = resolve_within_root(dst, dest_dir)
        if not (src_ok and dst_ok):
            raise PathEscapeError(rel, dst, dest_dir)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)


def install(bundle, anchor=None, client_state=None, now=None,
            offline_bundle=None, package_root=None) -> dict:
    """Verify a downloaded bundle and, only on success, install it as the active
    snapshot and advance client state. This is the ONLY path that advances the
    high-water mark — verification alone never mutates state.

    Steps: (safe-extract if ``bundle`` is an archive) → ``verify_download`` →
    copy the declared packs into ``snapshots/vN.tmp`` → re-verify the staged bytes
    against the manifest → atomically rename into ``snapshots/vN`` → atomically
    advance client state (``highest_version``, ``current``, ``history``).

    Fail-secure: any failure leaves the installed LKG and client state untouched
    and returns ``action: discard``. A corrupt client state refuses install."""
    if anchor is None:
        anchor = load_anchor(package_root)
    if client_state is None:
        client_state = load_client_state(anchor)
    report = _Report()

    def refuse(reason):
        report.warn(f"refusing install: {reason}")
        return {"trusted": False, "action": "discard", "reason": reason,
                "checks": report.checks, "warnings": report.warnings}

    if state_is_corrupt(client_state):
        return refuse("client state corrupt; refusing to advance (reinit required)")

    staging = tempfile.mkdtemp(prefix="attestarc-install-")
    try:
        if os.path.isdir(bundle):
            bundle_dir = bundle
        else:
            # Verify the archive's OWN attestation BEFORE extraction, so unattested
            # bytes never reach the (already safe) tar reader. The published .tar.gz
            # is attested at release time alongside the manifest. Skipped only for an
            # offline install (no network to fetch the archive's attestation); the
            # extracted manifest attestation + pack integrity still gate the install.
            if offline_bundle is None:
                arch_ok, arch_detail = _gh_attest_verify(bundle, anchor)
                report.check("archive:attested", arch_ok, arch_detail)
                if not arch_ok:
                    return refuse(f"archive attestation failed: {arch_detail}")
            try:
                extract_root = os.path.join(staging, "extract")
                safe_extract_tar(bundle, extract_root)
                bundle_dir = _locate_bundle_root(extract_root)
            except (PathEscapeError, ValueError, OSError, tarfile.TarError) as exc:
                return refuse(f"unsafe or unreadable archive: {exc}")

        verified = verify_download(bundle_dir, anchor=anchor,
                                   client_state=client_state, now=now,
                                   offline_bundle=offline_bundle,
                                   package_root=package_root)
        for c in verified.get("checks", []):
            report.checks.append(c)
        if not verified.get("trusted"):
            return refuse(verified.get("reason", "verification failed"))

        version = verified["version"]
        digest = verified["manifest_sha256"]
        snaps = _expand_snapshots_dir(anchor)
        os.makedirs(snaps, exist_ok=True)
        final = os.path.join(snaps, f"v{version}")
        _, _, within = resolve_within_root(final, snaps)
        if not within:
            return refuse("snapshot path escapes snapshots dir")
        tmp_final = final + ".tmp"
        if os.path.exists(tmp_final):
            shutil.rmtree(tmp_final, ignore_errors=True)

        try:
            _copy_declared(bundle_dir, tmp_final, verified.get("packs"))
            # Re-verify the STAGED copy against the (attested) manifest: the bytes
            # we are about to install must themselves match, not just the source.
            staged_manifest = _load_json(os.path.join(tmp_final, _MANIFEST_FILE))
            _, staged_real, _ = resolve_within_root(tmp_final, tmp_final)
            if not _verify_pack_integrity(staged_real, staged_manifest, report):
                shutil.rmtree(tmp_final, ignore_errors=True)
                return refuse("staged snapshot integrity mismatch")
            if os.path.exists(final):
                shutil.rmtree(final)
            os.replace(tmp_final, final)
        except (OSError, PathEscapeError, json.JSONDecodeError) as exc:
            shutil.rmtree(tmp_final, ignore_errors=True)
            return refuse(f"staging failed: {exc}")

        # Advance client state atomically (single save of the fully-built state).
        new_state = dict(client_state)
        prev_high = int(client_state.get("highest_version") or 0)
        new_state["highest_version"] = max(prev_high, int(version))
        # Advance the chain head only when this install is a NEW high-water version
        # (verify_download already enforced version > floor, so this is always true
        # on a normal install; guarded for safety). Revocation never touches it.
        if int(version) >= prev_high:
            new_state["highest_manifest_sha256"] = digest
        new_state["current"] = {"version": version, "manifest_sha256": digest,
                                "verified_via": "attestation", "path": final}
        history = [h for h in (client_state.get("history") or [])
                   if h.get("version") != version]
        history.append({"version": version, "manifest_sha256": digest, "path": final})
        new_state["history"] = history
        save_client_state(anchor, new_state)
        report.check("state:advanced", True,
                     f"highest_version={new_state['highest_version']}")
        return {"trusted": True, "action": "installed", "version": version,
                "manifest_sha256": digest, "snapshot_path": final,
                "highest_version": new_state["highest_version"],
                "checks": report.checks, "warnings": report.warnings}
    finally:
        shutil.rmtree(staging, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Revocation — verify_and_apply_revocation is the ONLY public path
# --------------------------------------------------------------------------- #
_REVOCATION_TYPE = "attestarc-knowledge-revocation"


def _validate_revocation(rec) -> list:
    """Structural check of an (already attestation-verified) revocation record."""
    if not isinstance(rec, dict):
        return ["revocation is not a JSON object"]
    errs = []
    if rec.get("_type") != _REVOCATION_TYPE:
        errs.append(f"_type must be {_REVOCATION_TYPE!r}")
    rv = rec.get("revoked_versions")
    if (not isinstance(rv, list) or not rv
            or not all(isinstance(x, int) and not isinstance(x, bool) and x > 0
                       for x in rv)):
        errs.append("revoked_versions must be a non-empty list of positive integers")
    return errs


def _apply_revocation(anchor, revoked_versions, client_state=None,
                      persist=True) -> dict:
    """INTERNAL: record revoked version(s) in client state. Never call directly for
    an unverified record — the only public entry is verify_and_apply_revocation."""
    if client_state is None:
        client_state = load_client_state(anchor)
    revs = set(client_state.get("revoked_versions") or [])
    seq = revoked_versions if isinstance(revoked_versions, (list, tuple, set)) \
        else [revoked_versions]
    revs.update(seq)
    client_state["revoked_versions"] = sorted(revs)
    if persist:
        save_client_state(anchor, client_state)
    return client_state


def verify_and_apply_revocation(revocation_path, anchor=None, client_state=None,
                                offline_bundle=None, package_root=None) -> dict:
    """The ONLY public revocation path (kill switch, THREAT_MODEL §8).

    Attestation-verify the revocation record against the anchor, structurally
    validate it, record the revoked version(s), and roll ``current`` back to the
    most recent retained non-revoked snapshot still on disk (or to the in-package
    bootstrap when none remains). Findings assessed under a revoked version are
    surfaced ``requires_reverification`` on the next assessor read (state.py
    reverify re-observes; a knowledge change never auto-resolves a finding).

    Fail-secure: an unattested, unreadable, or malformed revocation is discarded
    and client state is left untouched. A corrupt client state refuses to apply."""
    if anchor is None:
        anchor = load_anchor(package_root)
    if client_state is None:
        client_state = load_client_state(anchor)
    report = _Report()

    def discard(reason):
        report.warn(f"discarding revocation: {reason}")
        return {"applied": False, "action": "discard", "reason": reason,
                "checks": report.checks, "warnings": report.warnings}

    if state_is_corrupt(client_state):
        return discard("client state corrupt; refusing to apply (reinit required)")
    try:
        rec = _load_json(revocation_path)
    except (OSError, json.JSONDecodeError) as exc:
        return discard(f"revocation unreadable: {exc}")

    att_ok, att_detail = _gh_attest_verify(revocation_path, anchor, offline_bundle,
                                           kind="revocation")
    report.check("attestation", att_ok, att_detail)
    if not att_ok:
        return discard(f"revocation attestation failed: {att_detail}")

    errs = _validate_revocation(rec)
    report.check("revocation:schema", not errs, "; ".join(errs) or "valid")
    if errs:
        return discard("revocation record invalid: " + "; ".join(errs))

    new_state = _apply_revocation(anchor, rec["revoked_versions"],
                                  dict(client_state), persist=False)
    revoked = set(new_state["revoked_versions"])
    cur = new_state.get("current") or {}
    rolled_back_from = None
    if cur.get("version") in revoked:
        replacement = None
        for h in reversed(new_state.get("history") or []):
            if (h.get("version") not in revoked and h.get("path")
                    and os.path.isdir(h["path"])):
                replacement = {"version": h["version"],
                               "manifest_sha256": h.get("manifest_sha256"),
                               "verified_via": "attestation", "path": h["path"]}
                break
        rolled_back_from = cur.get("version")
        new_state["current"] = replacement  # None => fall back to bootstrap
    save_client_state(anchor, new_state)
    report.check("state:revoked", True, f"revoked {sorted(revoked)}")
    return {"applied": True, "action": "revoked",
            "revoked_versions": sorted(revoked),
            "rolled_back_from": rolled_back_from,
            "current": new_state.get("current"),
            "requires_reverification": True,
            "checks": report.checks, "warnings": report.warnings}


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


def cmd_install(args) -> int:
    """Updater-facing: verify a downloaded bundle and, on success, install it as
    the active snapshot and advance client state (the only state-advancing path)."""
    result = install(bundle=args.bundle_path, now=args.now,
                     offline_bundle=args.bundle)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("trusted") else 1


def cmd_verify_and_apply_revocation(args) -> int:
    """Updater-facing: attestation-verify a revocation record and apply it."""
    result = verify_and_apply_revocation(revocation_path=args.revocation_path,
                                         offline_bundle=args.bundle)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("applied") else 1


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

    sp = sub.add_parser("install",
                        help="verify a downloaded bundle and install it as the "
                             "active snapshot, advancing client state (Updater path)")
    sp.add_argument("bundle_path",
                    help="downloaded bundle: a directory of manifest+packs or a .tar.gz")
    sp.add_argument("--bundle", default=None,
                    help="offline Sigstore bundle for air-gapped verification")
    sp.add_argument("--now", default=None, help="ISO timestamp for freshness (testing)")
    sp.set_defaults(func=cmd_install)

    sp = sub.add_parser("verify-and-apply-revocation",
                        help="attestation-verify a revocation record and apply it "
                             "(kill switch; Updater path)")
    sp.add_argument("revocation_path", help="path to the signed revocation record")
    sp.add_argument("--bundle", default=None,
                    help="offline Sigstore bundle for air-gapped verification")
    sp.set_defaults(func=cmd_verify_and_apply_revocation)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
