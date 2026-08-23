"""Unit tests for repository discovery (facts only)."""

import os
import subprocess

import pytest

import discover_repo as dr


def test_secure_repo_fixture_detection(fixtures_dir):
    result = dr.discover(os.path.join(fixtures_dir, "secure-repo"))
    d = result["detected"]
    assert d["scm"] == "github"
    assert d["scm_verified_remotely"] is False
    assert "github-actions" in d["ci"]
    assert "python" in d["languages"]
    assert "pip" in d["package_managers"]
    assert "dependabot" in d["security_files"]
    assert ".github/workflows/ci.yml" in d["workflow_files"]
    # discovery emits no verdicts
    assert "findings" not in result


def test_scm_inferred_note_present(fixtures_dir):
    result = dr.discover(os.path.join(fixtures_dir, "secure-repo"))
    assert any("not verified" in n for n in result["notes"])


def test_scm_from_remote():
    assert dr._scm_from_remote("git@github.com:acme/svc.git") == "github"
    assert dr._scm_from_remote("https://gitlab.com/acme/svc.git") == "gitlab"
    assert dr._scm_from_remote(None) is None


def test_normalize_remote_owner_repo():
    assert dr._normalize_remote(
        "https://github.com/acme/payment-service.git"
    ) == "acme/payment-service"
    assert dr._normalize_remote(
        "git@github.com:acme/payment-service.git"
    ) == "acme/payment-service"


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


@pytest.fixture
def git_repo(tmp_path):
    root = str(tmp_path)
    try:
        _git(["init", "-q"], root)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git not available")
    _git(["config", "user.email", "t@example.com"], root)
    _git(["config", "user.name", "Test"], root)
    _git(["remote", "add", "origin",
          "https://github.com/acme/payment-service.git"], root)
    return root


def test_git_repo_remote_and_scm(git_repo):
    result = dr.discover(git_repo)
    assert result["git"]["repository"] is True
    assert "github.com/acme/payment-service" in result["git"]["remote"]
    assert result["git"]["remote_host"] == "github.com"
    assert "current_branch" in result["git"]
    assert result["detected"]["scm"] == "github"
    assert result["detected"]["remote_slug"] == "acme/payment-service"


def test_embedded_credentials_are_redacted():
    for url in (
        "https://x-access-token:ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345@github.com/acme/svc.git",
        "https://user:supersecrettoken@github.com/acme/svc.git",
    ):
        red = dr._redact_remote(url)
        assert "ghs_" not in red["redacted_url"]
        assert "supersecrettoken" not in red["redacted_url"]
        assert "@" not in red["redacted_url"]
        assert red["host"] == "github.com"
        assert red["slug"] == "acme/svc"


def test_current_branch_not_labeled_default_when_unknown(git_repo):
    # A fresh local repo has no origin/HEAD, so default_branch is unknown while
    # current_branch is populated; the two must not be conflated.
    result = dr.discover(git_repo)
    assert result["git"]["default_branch"] is None
    assert any("Default branch could not be determined" in n
               for n in result["notes"])


def test_nested_workflows_are_not_active_ci(tmp_path):
    """Workflows outside the repo root never execute on GitHub, so they must be
    reported separately and must not be counted as the repo's active CI."""
    root = str(tmp_path)
    nested = os.path.join(root, "tests", "fixtures", "example",
                          ".github", "workflows")
    os.makedirs(nested)
    with open(os.path.join(nested, "build.yml"), "w") as fh:
        fh.write("on: push\njobs: {}\n")
    d = dr.discover(root)["detected"]
    assert d["workflow_files"] == []          # nothing at the real root
    assert "github-actions" not in d["ci"]    # nested workflows are not CI
    assert any(p.endswith("example/.github/workflows/build.yml")
               for p in d["non_root_workflow_files"])
    result = dr.discover(root)
    assert any("outside the repository root" in n for n in result["notes"])


def test_root_workflows_are_active_ci(tmp_path):
    root = str(tmp_path)
    wf = os.path.join(root, ".github", "workflows")
    os.makedirs(wf)
    with open(os.path.join(wf, "ci.yml"), "w") as fh:
        fh.write("on: push\njobs: {}\n")
    d = dr.discover(root)["detected"]
    assert ".github/workflows/ci.yml" in d["workflow_files"]
    assert d["non_root_workflow_files"] == []
    assert "github-actions" in d["ci"]


def test_detects_docker_and_terraform(tmp_path):
    root = str(tmp_path)
    with open(os.path.join(root, "Dockerfile"), "w") as fh:
        fh.write("FROM scratch\n")
    with open(os.path.join(root, "main.tf"), "w") as fh:
        fh.write('resource "null_resource" "x" {}\n')
    result = dr.discover(root)
    assert result["detected"]["containers"] is True
    assert result["detected"]["terraform"] is True
    assert "terraform" in result["detected"]["iac"]
