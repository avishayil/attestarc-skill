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
        # scripts and references travel with the skill
        assert os.path.exists(os.path.join(str(tmp_path), host, "skills",
                                           "attestarc", "scripts", "state.py"))


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
