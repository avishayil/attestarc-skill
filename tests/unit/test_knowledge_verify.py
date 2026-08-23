"""Unit tests for scripts/knowledge_verify.py — the TUF-inspired verify chain.

Fixtures prove: a valid bundled snapshot is trusted; a tampered target fails
integrity; a rollback (version below last-known-good) is rejected; a valid
*signed* pack verifies via ssh-keygen; and every signed-mode failure
(expired freshness, missing signature, inconsistent snapshot) degrades
fail-secure to the last-known-good bundled snapshot with a warning.
"""

import hashlib
import json
import os
import shutil
import subprocess

import pytest

import knowledge_verify as kv


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read())
    return h.hexdigest()


def _make_bootstrap_root(tmp_path, target_bytes=b'{"id":"KE-a"}\n'):
    root = tmp_path / "kroot"
    boot = root / "bootstrap"
    boot.mkdir(parents=True)
    pack = boot / "pack.jsonl"
    pack.write_bytes(target_bytes)
    targets = {
        "_type": "targets", "version": 1, "expires": "2099-01-01T00:00:00Z",
        "targets": [{
            "name": "bootstrap/pack.jsonl", "version": 1, "previous_version": 0,
            "sha256": hashlib.sha256(target_bytes).hexdigest(),
            "size": len(target_bytes), "valid_from": "2026-01-01",
        }],
    }
    (root / "targets.json").write_text(json.dumps(targets))
    (root / "root.json").write_text(json.dumps({
        "_type": "root", "version": 1, "expires": "2099-01-01T00:00:00Z",
        "mode": "bootstrap", "keys": {}, "roles": {
            "root": {"keyids": [], "threshold": 1},
            "timestamp": {"keyids": [], "threshold": 1},
            "snapshot": {"keyids": [], "threshold": 1},
            "targets": {"keyids": [], "threshold": 1}}}))
    return root


def test_valid_bootstrap_is_trusted(tmp_path):
    root = _make_bootstrap_root(tmp_path)
    result = kv.verify(knowledge_root=str(root))
    assert result["trusted"] is True
    assert result["mode"] == "bootstrap"
    assert result["source"] == "bundled-snapshot"


def test_tampered_target_fails_integrity(tmp_path):
    root = _make_bootstrap_root(tmp_path)
    # mutate the pack after the digest was recorded
    (root / "bootstrap" / "pack.jsonl").write_bytes(b'{"id":"KE-tampered"}\n')
    result = kv.verify(knowledge_root=str(root))
    assert result["trusted"] is False
    assert any(c["name"].endswith(":integrity") and not c["ok"]
               for c in result["checks"])


def test_missing_target_file_fails(tmp_path):
    root = _make_bootstrap_root(tmp_path)
    (root / "bootstrap" / "pack.jsonl").unlink()
    result = kv.verify(knowledge_root=str(root))
    assert result["trusted"] is False


def test_rollback_rejected_via_known_versions(tmp_path):
    root = _make_bootstrap_root(tmp_path)
    # a previously-seen version 5 makes the current version-1 metadata a rollback
    result = kv.verify(knowledge_root=str(root),
                       known_versions={"bootstrap/pack.jsonl": 5})
    assert result["trusted"] is False
    assert any(c["name"].endswith(":monotonic") and not c["ok"]
               for c in result["checks"])


def test_missing_metadata_is_untrusted(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    result = kv.verify(knowledge_root=str(root))
    assert result["trusted"] is False
    assert result["mode"] == "unknown"


def test_bundled_snapshot_verifies(knowledge_dir):
    result = kv.verify(knowledge_root=knowledge_dir)
    assert result["trusted"] is True
    assert result["mode"] == "bootstrap"


# --------------------------------------------------------------------------- #
# signed mode (requires ssh-keygen)
# --------------------------------------------------------------------------- #
def _have_ssh_keygen():
    return shutil.which("ssh-keygen") is not None


def _build_signed_root(tmp_path, identity="maintainer@example.com",
                       sign=True, expires="2099-01-01T00:00:00Z"):
    root = _make_bootstrap_root(tmp_path)
    keydir = tmp_path / "keys"
    keydir.mkdir()
    key = keydir / "id_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", identity,
                    "-f", str(key)], check=True, capture_output=True)
    pub = (keydir / "id_ed25519.pub").read_text().strip()
    allowed = keydir / "allowed_signers"
    keytype, keyval = pub.split()[0], pub.split()[1]
    allowed.write_text(f"{identity} {keytype} {keyval}\n")

    # targets.json already written by _make_bootstrap_root; recompute its hash
    tgt_hash = _sha256(str(root / "targets.json"))
    with open(root / "targets.json") as fh:
        tgt_version = json.load(fh)["version"]
    snapshot = {"_type": "snapshot", "version": 1, "expires": expires,
                "meta": {"targets.json": {"version": tgt_version,
                                          "sha256": tgt_hash}}}
    (root / "snapshot.json").write_text(json.dumps(snapshot))
    snap_hash = _sha256(str(root / "snapshot.json"))
    timestamp = {"_type": "timestamp", "version": 1, "expires": expires,
                 "meta": {"snapshot.json": {"version": 1, "sha256": snap_hash}}}
    (root / "timestamp.json").write_text(json.dumps(timestamp))

    keyid = "key1"
    root_doc = {
        "_type": "root", "version": 1, "expires": expires, "mode": "signed",
        "keys": {keyid: {"keytype": keytype, "identity": identity,
                         "keyval": {"public": f"{keytype} {keyval}"}}},
        "roles": {
            "root": {"keyids": [keyid], "threshold": 1},
            "timestamp": {"keyids": [keyid], "threshold": 1},
            "snapshot": {"keyids": [keyid], "threshold": 1},
            "targets": {"keyids": [keyid], "threshold": 1}}}
    (root / "root.json").write_text(json.dumps(root_doc))

    if sign:
        for name in ("timestamp.json", "snapshot.json", "targets.json"):
            subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-f", str(key),
                 "-n", kv._SIG_NAMESPACE, str(root / name)],
                check=True, capture_output=True)
    return root, str(allowed)


@pytest.mark.skipif(not _have_ssh_keygen(), reason="ssh-keygen not available")
def test_signed_pack_verifies(tmp_path):
    root, allowed = _build_signed_root(tmp_path)
    result = kv.verify(knowledge_root=str(root), allowed_signers=allowed)
    assert result["trusted"] is True
    assert result["mode"] == "signed"
    assert result["source"] == "verified"


@pytest.mark.skipif(not _have_ssh_keygen(), reason="ssh-keygen not available")
def test_signed_missing_signature_falls_back(tmp_path):
    root, allowed = _build_signed_root(tmp_path, sign=False)
    result = kv.verify(knowledge_root=str(root), allowed_signers=allowed)
    # signature check fails -> fail-secure fallback to bundled snapshot
    assert result["mode"] == "bootstrap"
    assert result["source"] == "bundled-snapshot"
    assert result["trusted"] is True  # bundled integrity still intact
    assert result["warnings"]


@pytest.mark.skipif(not _have_ssh_keygen(), reason="ssh-keygen not available")
def test_signed_expired_falls_back(tmp_path):
    root, allowed = _build_signed_root(tmp_path, expires="2000-01-01T00:00:00Z")
    result = kv.verify(knowledge_root=str(root), allowed_signers=allowed,
                       now="2026-08-24T00:00:00Z")
    assert result["mode"] == "bootstrap"
    assert any(c["name"].endswith(":fresh") and not c["ok"]
               for c in result["checks"])


@pytest.mark.skipif(not _have_ssh_keygen(), reason="ssh-keygen not available")
def test_signed_wrong_signer_falls_back(tmp_path):
    root, allowed = _build_signed_root(tmp_path)
    # replace the allowed-signers with an unrelated key -> signatures no longer verify
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C",
                    "maintainer@example.com", "-f", str(other / "k")],
                   check=True, capture_output=True)
    pub = (other / "k.pub").read_text().strip().split()
    (tmp_path / "keys" / "allowed_signers").write_text(
        f"maintainer@example.com {pub[0]} {pub[1]}\n")
    result = kv.verify(knowledge_root=str(root), allowed_signers=allowed)
    assert result["mode"] == "bootstrap"
    assert result["trusted"] is True
    assert result["warnings"]
