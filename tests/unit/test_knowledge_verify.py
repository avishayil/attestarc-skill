"""Unit tests for scripts/knowledge_verify.py — the attestation-based verify chain.

Trust is anchored by an external ``trust-anchor.json`` (in the signed skill
package) that pins the Sigstore identity a downloaded bundle must have been
produced under. These tests prove the model fails closed:

* the immutable in-package snapshot is bootstrap-trusted;
* a *non-package* snapshot is untrusted unless persistent client state records a
  prior attestation of that exact version+digest;
* a non-package snapshot claiming ``mode: bootstrap`` is rejected;
* a tampered or undeclared pack fails integrity;
* ``verify_download`` discards a bundle on any failure — no valid attestation,
  a bootstrap claim, a rollback vs client memory, expiry (freeze), a broken
  prev_digest chain, or a revoked version — and never falls back to trusting it.
"""

import hashlib
import json
import os

import pytest

import knowledge_verify as kv


def _sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def _write_pack(root, name, data: bytes):
    path = os.path.join(root, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _make_root(tmp_path, version=2, expires="2099-01-01T00:00:00Z",
               mode=None, prev_digest=None, packs=None):
    """Build a knowledge root with one or more packs and a matching manifest.
    Returns (root_dir, manifest_sha256)."""
    root = str(tmp_path / "kroot")
    os.makedirs(root, exist_ok=True)
    packs = packs or {"bootstrap/a.jsonl": b'{"id":"KE-a"}\n'}
    pack_meta = []
    for name, data in packs.items():
        _write_pack(root, name, data)
        pack_meta.append({"name": name, "sha256": _sha256_bytes(data),
                          "size": len(data)})
    manifest = {"_type": "attestarc-knowledge-manifest", "version": version,
                "created_at": "2026-08-24T00:00:00Z", "expires": expires,
                "prev_digest": prev_digest, "packs": pack_meta}
    if mode is not None:
        manifest["mode"] = mode
    mpath = os.path.join(root, "manifest.json")
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    return root, kv._sha256_file(mpath)


_ANCHOR = {"repo": "avishayil/attestarc-skill",
           "signer_workflow": ".github/workflows/release-knowledge.yml",
           "cert_oidc_issuer": "https://token.actions.githubusercontent.com",
           "client_state_dir": None}


def _anchor(tmp_path):
    a = dict(_ANCHOR)
    a["client_state_dir"] = str(tmp_path / "state")
    return a


# --------------------------------------------------------------------------- #
# verify_installed — assessor path
# --------------------------------------------------------------------------- #
def test_in_package_bootstrap_is_trusted(knowledge_dir):
    result = kv.verify_installed(knowledge_root=knowledge_dir)
    assert result["trusted"] is True
    assert result["is_package_bootstrap"] is True
    assert result["source"] == "bootstrap-snapshot"


def test_non_package_snapshot_untrusted_without_client_state(tmp_path):
    root, _ = _make_root(tmp_path)
    result = kv.verify_installed(knowledge_root=root, anchor=_anchor(tmp_path),
                                 client_state={"highest_version": 0,
                                               "current": None,
                                               "revoked_versions": []})
    assert result["trusted"] is False
    assert result["source"] == "unverified"
    assert result["is_package_bootstrap"] is False


def test_non_package_bootstrap_claim_is_rejected(tmp_path):
    root, _ = _make_root(tmp_path, mode="bootstrap")
    result = kv.verify_installed(knowledge_root=root, anchor=_anchor(tmp_path),
                                 client_state={"highest_version": 0,
                                               "current": None,
                                               "revoked_versions": []})
    assert result["trusted"] is False
    assert result["source"] == "rejected"
    assert any(c["name"] == "bootstrap:in-package" and not c["ok"]
               for c in result["checks"])


def test_non_package_trusted_when_client_state_attests(tmp_path):
    root, digest = _make_root(tmp_path, version=3)
    state = {"highest_version": 3, "revoked_versions": [],
             "current": {"version": 3, "manifest_sha256": digest,
                         "verified_via": "attestation"}}
    result = kv.verify_installed(knowledge_root=root, anchor=_anchor(tmp_path),
                                 client_state=state)
    assert result["trusted"] is True
    assert result["source"] == "verified-lkg"


def test_tampered_pack_fails_integrity(tmp_path):
    root, digest = _make_root(tmp_path, version=3)
    state = {"highest_version": 3, "revoked_versions": [],
             "current": {"version": 3, "manifest_sha256": digest,
                         "verified_via": "attestation"}}
    # mutate the pack after the manifest recorded its hash
    _write_pack(root, "bootstrap/a.jsonl", b'{"id":"KE-tampered"}\n')
    result = kv.verify_installed(knowledge_root=root, anchor=_anchor(tmp_path),
                                 client_state=state)
    assert result["trusted"] is False
    assert any(c["name"].endswith(":integrity") and not c["ok"]
               for c in result["checks"])


def test_undeclared_pack_is_rejected(tmp_path):
    root, digest = _make_root(tmp_path, version=3)
    state = {"highest_version": 3, "revoked_versions": [],
             "current": {"version": 3, "manifest_sha256": digest,
                         "verified_via": "attestation"}}
    # smuggle an extra pack not pinned by the manifest
    _write_pack(root, "bootstrap/evil.jsonl", b'{"id":"KE-evil"}\n')
    result = kv.verify_installed(knowledge_root=root, anchor=_anchor(tmp_path),
                                 client_state=state)
    assert result["trusted"] is False
    assert any(c["name"].endswith(":declared") and not c["ok"]
               for c in result["checks"])


def test_revoked_version_untrusted(tmp_path):
    root, digest = _make_root(tmp_path, version=3)
    state = {"highest_version": 3, "revoked_versions": [3],
             "current": {"version": 3, "manifest_sha256": digest,
                         "verified_via": "attestation"}}
    result = kv.verify_installed(knowledge_root=root, anchor=_anchor(tmp_path),
                                 client_state=state)
    assert result["trusted"] is False


def test_missing_manifest_is_untrusted(tmp_path):
    root = str(tmp_path / "empty")
    os.makedirs(root)
    result = kv.verify_installed(knowledge_root=root, anchor=_anchor(tmp_path),
                                 client_state={"highest_version": 0})
    assert result["trusted"] is False
    assert result["source"] == "none"


# --------------------------------------------------------------------------- #
# verify_download — updater path (attestation-gated; failure => discard)
# --------------------------------------------------------------------------- #
def test_download_without_valid_attestation_discarded(tmp_path, monkeypatch):
    root, _ = _make_root(tmp_path)
    # gh unavailable / attestation fails -> discard, never trust-via-local-hash
    monkeypatch.setattr(kv, "_gh_attest_verify",
                        lambda *a, **k: (False, "attestation failed"))
    result = kv.verify_download(root, anchor=_anchor(tmp_path),
                                client_state={"highest_version": 0})
    assert result["trusted"] is False
    assert result["action"] == "discard"
    assert "attestation" in result["reason"]


def test_download_bootstrap_claim_discarded(tmp_path, monkeypatch):
    root, _ = _make_root(tmp_path, mode="bootstrap")
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    result = kv.verify_download(root, anchor=_anchor(tmp_path),
                                client_state={"highest_version": 0})
    assert result["action"] == "discard"
    assert "bootstrap" in result["reason"]


def test_download_rollback_discarded(tmp_path, monkeypatch):
    root, _ = _make_root(tmp_path, version=2)
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    result = kv.verify_download(root, anchor=_anchor(tmp_path),
                                client_state={"highest_version": 5,
                                              "current": None,
                                              "revoked_versions": []})
    assert result["action"] == "discard"
    assert "rollback" in result["reason"]


def test_download_expired_discarded(tmp_path, monkeypatch):
    root, _ = _make_root(tmp_path, version=6, expires="2000-01-01T00:00:00Z")
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    result = kv.verify_download(root, anchor=_anchor(tmp_path), now="2026-08-24T00:00:00Z",
                                client_state={"highest_version": 0,
                                              "current": None,
                                              "revoked_versions": []})
    assert result["action"] == "discard"
    assert "expired" in result["reason"]


def test_download_broken_chain_discarded(tmp_path, monkeypatch):
    root, _ = _make_root(tmp_path, version=4, prev_digest="not-the-installed-digest")
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    state = {"highest_version": 3, "revoked_versions": [],
             "current": {"version": 3, "manifest_sha256": "installed-digest",
                         "verified_via": "attestation"}}
    result = kv.verify_download(root, anchor=_anchor(tmp_path), client_state=state)
    assert result["action"] == "discard"
    assert "chain" in result["reason"]


def test_download_revoked_discarded(tmp_path, monkeypatch):
    root, _ = _make_root(tmp_path, version=7)
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    result = kv.verify_download(root, anchor=_anchor(tmp_path),
                                client_state={"highest_version": 0,
                                              "current": None,
                                              "revoked_versions": [7]})
    assert result["action"] == "discard"
    assert "revoked" in result["reason"]


def test_download_success_installs(tmp_path, monkeypatch):
    root, digest = _make_root(tmp_path, version=8)
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    result = kv.verify_download(root, anchor=_anchor(tmp_path),
                                client_state={"highest_version": 0,
                                              "current": None,
                                              "revoked_versions": []})
    assert result["trusted"] is True
    assert result["action"] == "install"
    assert result["version"] == 8
    assert result["manifest_sha256"] == digest


# --------------------------------------------------------------------------- #
# client state + revocation
# --------------------------------------------------------------------------- #
def test_client_state_roundtrip(tmp_path):
    anchor = _anchor(tmp_path)
    state = kv.load_client_state(anchor)
    assert state["highest_version"] == 0
    state["highest_version"] = 9
    state["current"] = {"version": 9, "manifest_sha256": "abc",
                        "verified_via": "attestation"}
    kv.save_client_state(anchor, state)
    reloaded = kv.load_client_state(anchor)
    assert reloaded["highest_version"] == 9
    assert reloaded["current"]["version"] == 9


def test_apply_revocation_internal_records_version(tmp_path):
    anchor = _anchor(tmp_path)
    kv._apply_revocation(anchor, 4)
    assert 4 in kv.load_client_state(anchor)["revoked_versions"]


def test_apply_revocation_is_not_public(tmp_path):
    """The caller-trusts-me revocation entry is internal; the only public path is
    verify_and_apply_revocation (attestation-gated)."""
    assert not hasattr(kv, "apply_revocation")


# --------------------------------------------------------------------------- #
# load_client_state: missing = fresh floor; corrupt = fail closed
# --------------------------------------------------------------------------- #
def test_missing_client_state_is_fresh_floor(tmp_path):
    state = kv.load_client_state(_anchor(tmp_path))
    assert state["highest_version"] == 0
    assert kv.state_is_corrupt(state) is False


def test_corrupt_client_state_fails_closed(tmp_path):
    anchor = _anchor(tmp_path)
    path = kv.client_state_path(anchor)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{ this is not json")
    state = kv.load_client_state(anchor)
    assert kv.state_is_corrupt(state) is True
    assert state["highest_version"] == 0  # conservative floor, not fail-open trust


# --------------------------------------------------------------------------- #
# install — the ONLY state-advancing path (atomic verify -> stage -> persist)
# --------------------------------------------------------------------------- #
def test_install_advances_state_and_writes_snapshot(tmp_path, monkeypatch):
    root, digest = _make_root(tmp_path, version=8)
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    anchor = _anchor(tmp_path)
    anchor["snapshots_dir"] = str(tmp_path / "snaps")
    result = kv.install(root, anchor=anchor,
                        client_state={"highest_version": 0, "current": None,
                                      "revoked_versions": [], "history": []})
    assert result["trusted"] is True and result["action"] == "installed"
    assert result["version"] == 8
    assert os.path.exists(os.path.join(result["snapshot_path"], "manifest.json"))
    reloaded = kv.load_client_state(anchor)
    assert reloaded["highest_version"] == 8
    assert reloaded["current"]["version"] == 8
    assert reloaded["current"]["manifest_sha256"] == digest
    assert reloaded["current"]["verified_via"] == "attestation"


def test_install_refuses_on_corrupt_state(tmp_path, monkeypatch):
    root, _ = _make_root(tmp_path, version=8)
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    anchor = _anchor(tmp_path)
    anchor["snapshots_dir"] = str(tmp_path / "snaps")
    corrupt = {"highest_version": 0, "current": None, "revoked_versions": [],
               "history": [], "_corrupt": True}
    result = kv.install(root, anchor=anchor, client_state=corrupt)
    assert result["action"] == "discard"
    assert "corrupt" in result["reason"]


def test_install_discards_rollback_without_advancing_state(tmp_path, monkeypatch):
    root, _ = _make_root(tmp_path, version=2)
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    anchor = _anchor(tmp_path)
    anchor["snapshots_dir"] = str(tmp_path / "snaps")
    kv.save_client_state(anchor, {"highest_version": 5, "current": None,
                                  "revoked_versions": [], "history": []})
    result = kv.install(root, anchor=anchor)
    assert result["action"] == "discard" and "rollback" in result["reason"]
    # state untouched
    assert kv.load_client_state(anchor)["highest_version"] == 5


def test_install_from_targz_archive(tmp_path, monkeypatch):
    import tarfile
    root, digest = _make_root(tmp_path, version=9)
    archive = str(tmp_path / "bundle.tar.gz")
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root, arcname="bundle")
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    anchor = _anchor(tmp_path)
    anchor["snapshots_dir"] = str(tmp_path / "snaps")
    result = kv.install(archive, anchor=anchor,
                        client_state={"highest_version": 0, "current": None,
                                      "revoked_versions": [], "history": []})
    assert result["trusted"] is True and result["version"] == 9
    assert kv.load_client_state(anchor)["current"]["manifest_sha256"] == digest


def test_install_archive_refused_when_archive_attestation_fails(tmp_path,
                                                                monkeypatch):
    # The archive's OWN attestation is verified before extraction; an unattested
    # archive is refused and never reaches the tar reader or advances state.
    import tarfile
    root, _ = _make_root(tmp_path, version=9)
    archive = str(tmp_path / "bundle.tar.gz")
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root, arcname="bundle")
    monkeypatch.setattr(kv, "_gh_attest_verify",
                        lambda *a, **k: (False, "no attestation over archive"))
    anchor = _anchor(tmp_path)
    anchor["snapshots_dir"] = str(tmp_path / "snaps")
    result = kv.install(archive, anchor=anchor,
                        client_state={"highest_version": 0, "current": None,
                                      "revoked_versions": [], "history": []})
    assert result["trusted"] is False and result["action"] == "discard"
    assert "archive attestation failed" in result["reason"]
    assert kv.load_client_state(anchor)["highest_version"] == 0


# --------------------------------------------------------------------------- #
# verify_and_apply_revocation — the ONLY public revocation path
# --------------------------------------------------------------------------- #
def _write_revocation(tmp_path, versions, _type="attestarc-knowledge-revocation"):
    path = str(tmp_path / "revocation.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"_type": _type, "revoked_versions": versions,
                   "reason": "compromised", "created_at": "2026-08-24T00:00:00Z"}, fh)
    return path


def test_revocation_without_attestation_is_discarded(tmp_path, monkeypatch):
    rec = _write_revocation(tmp_path, [3])
    monkeypatch.setattr(kv, "_gh_attest_verify",
                        lambda *a, **k: (False, "no attestation"))
    anchor = _anchor(tmp_path)
    result = kv.verify_and_apply_revocation(rec, anchor=anchor,
                                            client_state=kv._empty_state())
    assert result["applied"] is False and result["action"] == "discard"
    assert 3 not in kv.load_client_state(anchor)["revoked_versions"]


def test_revocation_malformed_is_discarded(tmp_path, monkeypatch):
    rec = _write_revocation(tmp_path, [], _type="wrong-type")
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    result = kv.verify_and_apply_revocation(rec, anchor=_anchor(tmp_path),
                                            client_state=kv._empty_state())
    assert result["applied"] is False and "invalid" in result["reason"]


def test_revocation_applies_and_rolls_back_current(tmp_path, monkeypatch):
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    rec = _write_revocation(tmp_path, [5])
    anchor = _anchor(tmp_path)
    v4 = str(tmp_path / "snaps" / "v4")
    os.makedirs(v4, exist_ok=True)
    state = {"highest_version": 5, "revoked_versions": [],
             "current": {"version": 5, "manifest_sha256": "d5",
                         "verified_via": "attestation", "path": str(tmp_path / "v5")},
             "history": [{"version": 4, "manifest_sha256": "d4", "path": v4},
                         {"version": 5, "manifest_sha256": "d5",
                          "path": str(tmp_path / "v5")}]}
    result = kv.verify_and_apply_revocation(rec, anchor=anchor, client_state=state)
    assert result["applied"] is True
    assert result["rolled_back_from"] == 5
    reloaded = kv.load_client_state(anchor)
    assert 5 in reloaded["revoked_versions"]
    assert reloaded["current"]["version"] == 4  # rolled back to retained LKG


# --------------------------------------------------------------------------- #
# PR-E — per-artifact identity + high-water chain
# --------------------------------------------------------------------------- #
def test_anchor_identity_regexp_is_artifact_specific():
    anchor = {"cert_identity_regexp_bundle": "BUNDLE_RE",
              "cert_identity_regexp_revocation": "REVOKE_RE"}
    assert kv._anchor_identity_regexp(anchor, "bundle") == "BUNDLE_RE"
    assert kv._anchor_identity_regexp(anchor, "revocation") == "REVOKE_RE"
    # A revocation attestation is NOT accepted under the bundle identity and vice
    # versa: the two regexps differ, so a bundle signed off main (the revocation
    # ref) cannot satisfy the bundle check.
    assert (kv._anchor_identity_regexp(anchor, "bundle")
            != kv._anchor_identity_regexp(anchor, "revocation"))
    # Legacy fallback: an older anchor with only the combined key still verifies.
    legacy = {"cert_identity_regexp": "LEGACY_RE"}
    assert kv._anchor_identity_regexp(legacy, "bundle") == "LEGACY_RE"
    assert kv._anchor_identity_regexp(legacy, "revocation") == "LEGACY_RE"
    # No regexp at all → gh verify refuses (fail-secure) for this kind.
    ok, detail = kv._gh_attest_verify("x", {"repo": "o/r"}, kind="bundle")
    assert ok is False and "cert_identity_regexp" in detail


def test_download_requires_prev_digest_when_prior_installed(tmp_path, monkeypatch):
    # A prior version was installed (floor 5); a v6 manifest that OMITS prev_digest
    # must be discarded (fail-closed) rather than skipping chain validation.
    root, _ = _make_root(tmp_path, version=6, prev_digest=None)
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    state = {"highest_version": 5, "highest_manifest_sha256": "d5",
             "revoked_versions": [], "current": {"version": 5,
             "manifest_sha256": "d5", "verified_via": "attestation"}}
    result = kv.verify_download(root, anchor=_anchor(tmp_path), client_state=state)
    assert result["action"] == "discard"
    assert "prev_digest required" in result["reason"]


def test_download_chains_to_high_water_not_active_current(tmp_path, monkeypatch):
    # v4 -> v5 -> revoke(v5): `current` rolled back to v4 (d4) but the chain HEAD
    # stays d5. v6 must chain to the head (d5), NOT to the active current (d4), so
    # the client can move past a revoked release.
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    state = {"highest_version": 5, "highest_manifest_sha256": "d5",
             "revoked_versions": [5],
             "current": {"version": 4, "manifest_sha256": "d4",
                         "verified_via": "attestation"}}
    good, _ = _make_root(tmp_path / "good", version=6, prev_digest="d5")
    assert kv.verify_download(good, anchor=_anchor(tmp_path),
                              client_state=state)["action"] == "install"
    bad, _ = _make_root(tmp_path / "bad", version=6, prev_digest="d4")
    res = kv.verify_download(bad, anchor=_anchor(tmp_path), client_state=state)
    assert res["action"] == "discard" and "high-water" in res["reason"]


def test_install_advances_chain_head(tmp_path, monkeypatch):
    import tarfile
    root, digest = _make_root(tmp_path, version=7)
    archive = str(tmp_path / "bundle.tar.gz")
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(root, arcname="bundle")
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    anchor = _anchor(tmp_path)
    anchor["snapshots_dir"] = str(tmp_path / "snaps")
    result = kv.install(archive, anchor=anchor, client_state=kv._empty_state())
    assert result["trusted"] is True and result["version"] == 7
    reloaded = kv.load_client_state(anchor)
    assert reloaded["highest_version"] == 7
    assert reloaded["highest_manifest_sha256"] == digest  # chain head advanced


def test_legacy_state_backfills_chain_head(tmp_path):
    # State written before highest_manifest_sha256 existed: load backfills the head
    # from `current` when the active snapshot is still the high-water version.
    anchor = _anchor(tmp_path)
    os.makedirs(anchor["client_state_dir"], exist_ok=True)
    legacy = {"highest_version": 5, "revoked_versions": [],
              "current": {"version": 5, "manifest_sha256": "d5"}, "history": []}
    with open(kv.client_state_path(anchor), "w", encoding="utf-8") as fh:
        json.dump(legacy, fh)
    loaded = kv.load_client_state(anchor)
    assert loaded["highest_manifest_sha256"] == "d5"


def test_revocation_rolls_back_to_bootstrap_when_no_lkg(tmp_path, monkeypatch):
    monkeypatch.setattr(kv, "_gh_attest_verify", lambda *a, **k: (True, "ok"))
    rec = _write_revocation(tmp_path, [5])
    anchor = _anchor(tmp_path)
    state = {"highest_version": 5, "revoked_versions": [],
             "current": {"version": 5, "manifest_sha256": "d5",
                         "verified_via": "attestation", "path": str(tmp_path / "v5")},
             "history": [{"version": 5, "manifest_sha256": "d5",
                          "path": str(tmp_path / "v5")}]}
    result = kv.verify_and_apply_revocation(rec, anchor=anchor, client_state=state)
    assert result["applied"] is True
    assert kv.load_client_state(anchor)["current"] is None  # falls back to bootstrap
