"""Unit tests for install.py and uninstall.py."""

import os

import pytest

import install
import uninstall


# --------------------------------------------------------------------------- #
# destination resolution
# --------------------------------------------------------------------------- #
def test_dest_dir_project_with_target(tmp_path):
    d = install.dest_dir("claude", "project", str(tmp_path))
    assert d == os.path.join(str(tmp_path), ".claude", "skills", "attestarc")
    d = install.dest_dir("cursor", "project", str(tmp_path))
    assert d == os.path.join(str(tmp_path), ".cursor", "skills", "attestarc")


def test_dest_dir_user_scope_uses_home():
    d = install.dest_dir("claude", "user", None)
    assert d == os.path.join(os.path.expanduser("~"),
                             ".claude", "skills", "attestarc")


def test_validate_source_reads_version():
    version = install.validate_source(install.source_skill_dir())
    assert version and version[0].isdigit()


# --------------------------------------------------------------------------- #
# bundled-knowledge integrity gate
# --------------------------------------------------------------------------- #
def test_bundled_knowledge_integrity_ok():
    # the shipped snapshot's manifest must match its packs
    install.verify_bundled_knowledge(install.source_skill_dir())


def test_install_rejects_tampered_bundled_pack(tmp_path):
    import json
    import shutil
    src = str(tmp_path / "skillsrc")
    shutil.copytree(install.source_skill_dir(), src,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc",
                                                   ".git", "tests"))
    # tamper with a pack after the manifest pinned its hash
    boot = os.path.join(src, "knowledge", "bootstrap")
    pack = os.path.join(boot, sorted(os.listdir(boot))[0])
    with open(pack, "a", encoding="utf-8") as fh:
        fh.write('{"id":"KE-injected"}\n')
    with pytest.raises(install.InstallError, match="tampered"):
        install.verify_bundled_knowledge(src)


def test_install_rejects_provenance_violating_snapshot(tmp_path):
    """A pack can hash-match its manifest yet violate the trust contract (an entry
    declaring a higher authority than the registry assigns its URL). The install
    gate must catch this even after the manifest hash is 'repaired'."""
    import hashlib
    import json
    import shutil
    src = str(tmp_path / "skillsrc")
    shutil.copytree(install.source_skill_dir(), src,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc",
                                                   ".git", "tests"))
    boot = os.path.join(src, "knowledge", "bootstrap")
    pack = os.path.join(boot, "github-actions.jsonl")
    lines = open(pack, encoding="utf-8").read().splitlines()
    first = json.loads(lines[0])
    first["sources"][0]["authority"] = 42  # disagrees with the registry
    lines[0] = json.dumps(first)
    data = ("\n".join(lines) + "\n").encode("utf-8")
    with open(pack, "wb") as fh:
        fh.write(data)
    # Repair the manifest hash/size so the byte-integrity gate passes.
    mpath = os.path.join(src, "knowledge", "manifest.json")
    manifest = json.loads(open(mpath, encoding="utf-8").read())
    for p in manifest["packs"]:
        if p["name"] == "bootstrap/github-actions.jsonl":
            p["sha256"] = hashlib.sha256(data).hexdigest()
            p["size"] = len(data)
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    with pytest.raises(install.InstallError, match="trust contract"):
        install.verify_bundled_knowledge(src)


def test_install_rejects_missing_trust_anchor(tmp_path):
    import shutil
    src = str(tmp_path / "skillsrc")
    shutil.copytree(install.source_skill_dir(), src,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc",
                                                   ".git", "tests"))
    os.remove(os.path.join(src, "knowledge", "trust-anchor.json"))
    with pytest.raises(install.InstallError, match="root of trust"):
        install.verify_bundled_knowledge(src)


# --------------------------------------------------------------------------- #
# install / upgrade
# --------------------------------------------------------------------------- #
def test_install_both_project(tmp_path):
    for platform in ("claude", "cursor"):
        result = install.install_one(platform, "project", str(tmp_path),
                                     force=False, dry_run=False)
        assert result["action"] == "installed"
    for host in (".claude", ".cursor"):
        skill_md = os.path.join(str(tmp_path), host, "skills", "attestarc",
                                "SKILL.md")
        assert os.path.exists(skill_md)
        base = os.path.join(str(tmp_path), host, "skills", "attestarc")
        # scripts, kernel, references, knowledge, and schemas travel with the skill
        assert os.path.exists(os.path.join(base, "scripts", "state.py"))
        assert os.path.exists(os.path.join(base, "core", "methodology.md"))
        assert os.path.exists(os.path.join(base, "schemas", "findings.schema.json"))
        assert os.path.exists(os.path.join(base, "knowledge", "bootstrap",
                                           "github-actions.jsonl"))
        # development scaffolding is NOT shipped
        assert not os.path.exists(os.path.join(base, "tests"))
        assert not os.path.exists(os.path.join(base, "evolution"))
        assert not os.path.exists(os.path.join(base, "assets"))


def test_install_does_not_touch_unrelated_files(tmp_path):
    sentinel = os.path.join(str(tmp_path), "IMPORTANT.txt")
    with open(sentinel, "w") as fh:
        fh.write("do not touch")
    install.install_one("claude", "project", str(tmp_path),
                        force=False, dry_run=False)
    with open(sentinel) as fh:
        assert fh.read() == "do not touch"
    # nothing created outside the .claude tree
    top = set(os.listdir(str(tmp_path)))
    assert top == {"IMPORTANT.txt", ".claude"}


def test_install_detects_existing_and_reports_up_to_date(tmp_path):
    install.install_one("claude", "project", str(tmp_path),
                        force=False, dry_run=False)
    again = install.install_one("claude", "project", str(tmp_path),
                                force=False, dry_run=False)
    assert again["action"] == "up-to-date"
    assert again["installed_version"] == again["version"]


def test_force_reinstalls(tmp_path):
    install.install_one("claude", "project", str(tmp_path),
                        force=False, dry_run=False)
    again = install.install_one("claude", "project", str(tmp_path),
                                force=True, dry_run=False)
    assert again["action"] == "upgraded"


def test_dry_run_makes_no_changes(tmp_path):
    result = install.install_one("claude", "project", str(tmp_path),
                                 force=False, dry_run=True)
    assert result["action"] == "would-install"
    assert not os.path.exists(os.path.join(str(tmp_path), ".claude"))


def test_refuses_to_overwrite_foreign_skill(tmp_path):
    dest = install.dest_dir("claude", "project", str(tmp_path))
    os.makedirs(dest)
    with open(os.path.join(dest, "SKILL.md"), "w") as fh:
        fh.write("---\nname: something-else\n---\n")
    with pytest.raises(install.InstallError):
        install.install_one("claude", "project", str(tmp_path),
                            force=False, dry_run=False)


def test_atomic_copy_leaves_no_staging_dirs(tmp_path):
    install.install_one("claude", "project", str(tmp_path),
                        force=False, dry_run=False)
    skills_dir = os.path.join(str(tmp_path), ".claude", "skills")
    leftovers = [n for n in os.listdir(skills_dir)
                 if n.startswith(".attestarc-staging")]
    assert leftovers == []


# --------------------------------------------------------------------------- #
# attested-tarball install path (bootstrap-anchor + gh attestation verify)
# --------------------------------------------------------------------------- #
def test_load_bootstrap_anchor_reads_shipped_anchor():
    anchor = install.load_bootstrap_anchor()
    assert anchor["repo"] and anchor["issuer"] and anchor["cert_identity_regexp"]
    # the identity regexp must compile (load_bootstrap_anchor asserts this too)
    import re
    re.compile(anchor["cert_identity_regexp"])


def test_load_bootstrap_anchor_missing_is_hard_error(tmp_path):
    with pytest.raises(install.InstallError, match="root of trust"):
        install.load_bootstrap_anchor(str(tmp_path))


def test_load_bootstrap_anchor_missing_field_is_error(tmp_path):
    import json
    (tmp_path / install.BOOTSTRAP_ANCHOR).write_text(
        json.dumps({"repo": "avishayil/attestarc-skill"}))  # no issuer/regexp
    with pytest.raises(install.InstallError, match="missing required field"):
        install.load_bootstrap_anchor(str(tmp_path))


def test_verify_release_tarball_fails_closed_without_gh(tmp_path, monkeypatch):
    tb = tmp_path / "pkg.tar.gz"
    tb.write_bytes(b"x")
    anchor = install.load_bootstrap_anchor()
    monkeypatch.setattr(install.shutil, "which", lambda _: None)
    with pytest.raises(install.InstallError, match="gh CLI not found"):
        install.verify_release_tarball(str(tb), anchor)


def test_verify_release_tarball_fails_on_nonzero_gh(tmp_path, monkeypatch):
    tb = tmp_path / "pkg.tar.gz"
    tb.write_bytes(b"x")
    anchor = install.load_bootstrap_anchor()
    monkeypatch.setattr(install.shutil, "which", lambda _: "/usr/bin/gh")

    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "no attestation found"

    monkeypatch.setattr(install.subprocess, "run", lambda *a, **k: _Proc())
    with pytest.raises(install.InstallError, match="failed attestation verification"):
        install.verify_release_tarball(str(tb), anchor)


def test_verify_release_tarball_passes_on_zero_gh(tmp_path, monkeypatch):
    tb = tmp_path / "pkg.tar.gz"
    tb.write_bytes(b"x")
    anchor = install.load_bootstrap_anchor()
    monkeypatch.setattr(install.shutil, "which", lambda _: "/usr/bin/gh")
    calls = {}

    class _Proc:
        returncode = 0
        stdout = "verified"
        stderr = ""

    def _run(cmd, **k):
        calls["cmd"] = cmd
        return _Proc()

    monkeypatch.setattr(install.subprocess, "run", _run)
    install.verify_release_tarball(str(tb), anchor)  # no raise
    # the anchor identity is passed through to gh, not caller-chosen
    assert "--cert-identity-regexp" in calls["cmd"]
    assert anchor["cert_identity_regexp"] in calls["cmd"]
    assert "--cert-oidc-issuer" in calls["cmd"]


def _build_payload_tarball(path: str) -> None:
    """Tar the shipped SKILL_PAYLOAD at the archive root (as release-skill.yml does)."""
    import tarfile
    src = install.source_skill_dir()
    with tarfile.open(path, "w:gz") as tf:
        for entry in install.SKILL_PAYLOAD:
            p = os.path.join(src, entry)
            if os.path.exists(p):
                tf.add(p, arcname=entry)


def test_install_from_tarball_verifies_then_installs(tmp_path, monkeypatch):
    """End-to-end: verification runs FIRST, then safe-extract + install from the
    verified contents. gh is stubbed out; the extract + install is real."""
    tb = str(tmp_path / "attestarc-skill-vtest.tar.gz")
    _build_payload_tarball(tb)
    order = []
    monkeypatch.setattr(install, "verify_release_tarball",
                        lambda p, a: order.append("verify"))
    real_extract = None
    proj = tmp_path / "proj"
    proj.mkdir()
    results = install.install_from_tarball(
        tb, ["claude"], "project", str(proj), force=False, dry_run=False)
    assert order == ["verify"]  # verify happened (and before install)
    assert results[0]["action"] == "installed"
    assert os.path.exists(
        os.path.join(str(proj), ".claude", "skills", "attestarc", "SKILL.md"))


def test_install_from_tarball_aborts_if_verify_fails(tmp_path, monkeypatch):
    """A verification failure aborts before anything is extracted/installed."""
    tb = str(tmp_path / "pkg.tar.gz")
    _build_payload_tarball(tb)

    def _fail(p, a):
        raise install.InstallError("bad provenance")

    monkeypatch.setattr(install, "verify_release_tarball", _fail)
    proj = tmp_path / "proj"
    proj.mkdir()
    with pytest.raises(install.InstallError, match="bad provenance"):
        install.install_from_tarball(tb, ["claude"], "project", str(proj),
                                     force=False, dry_run=False)
    assert not os.path.exists(os.path.join(str(proj), ".claude"))


# --------------------------------------------------------------------------- #
# uninstall
# --------------------------------------------------------------------------- #
def test_uninstall_removes_only_the_skill(tmp_path):
    install.install_one("claude", "project", str(tmp_path),
                        force=False, dry_run=False)
    sentinel = os.path.join(str(tmp_path), ".claude", "settings.json")
    with open(sentinel, "w") as fh:
        fh.write("{}")
    result = uninstall.uninstall_one("claude", "project", str(tmp_path),
                                     dry_run=False)
    assert result["action"] == "removed"
    assert not os.path.exists(install.dest_dir("claude", "project",
                                               str(tmp_path)))
    assert os.path.exists(sentinel)  # unrelated host config untouched


def test_uninstall_absent_is_noop(tmp_path):
    result = uninstall.uninstall_one("cursor", "project", str(tmp_path),
                                     dry_run=False)
    assert result["action"] == "absent"


def test_uninstall_refuses_foreign_dir(tmp_path):
    dest = install.dest_dir("claude", "project", str(tmp_path))
    os.makedirs(dest)
    with open(os.path.join(dest, "SKILL.md"), "w") as fh:
        fh.write("---\nname: not-attestarc\n---\n")
    with pytest.raises(install.InstallError):
        uninstall.uninstall_one("claude", "project", str(tmp_path),
                                dry_run=False)


def test_cli_install_uninstall_roundtrip(tmp_path, capsys):
    assert install.main(["--platform", "both", "--scope", "project",
                         "--target", str(tmp_path)]) == 0
    assert uninstall.main(["--platform", "both", "--scope", "project",
                          "--target", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "installed" in out and "removed" in out
