"""Unit tests for the git diff inspector (security-capability deltas)."""

import os
import subprocess

import pytest

import inspect_git_diff as igd


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


SECURE_WF = """\
name: CI
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: make
"""

RISKY_WF = """\
name: CI
on:
  push:
    branches: [main]
  pull_request_target:
permissions:
  contents: write
  id-token: write
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: evil/action@v1
      - run: make
"""


@pytest.fixture
def wf_repo(tmp_path):
    root = str(tmp_path)
    try:
        _git(["init", "-q"], root)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git not available")
    _git(["config", "user.email", "t@example.com"], root)
    _git(["config", "user.name", "Test"], root)
    wf_dir = os.path.join(root, ".github", "workflows")
    os.makedirs(wf_dir)
    path = os.path.join(wf_dir, "ci.yml")
    with open(path, "w") as fh:
        fh.write(SECURE_WF)
    _git(["add", "-A"], root)
    _git(["commit", "-q", "-m", "initial"], root)
    return root, path


def test_no_changes_no_workflow_deltas(wf_repo):
    root, _ = wf_repo
    result = igd.inspect_diff(root)
    assert result["git"]["repository"] is True
    assert result["workflow_changes"] == []


def test_detects_capability_gains(wf_repo):
    root, path = wf_repo
    with open(path, "w") as fh:
        fh.write(RISKY_WF)  # modify working tree
    result = igd.inspect_diff(root)  # working tree vs HEAD
    assert ".github/workflows/ci.yml" in result["changed_files"]
    changes = result["workflow_changes"]
    assert len(changes) == 1
    delta = changes[0]["security_delta"]

    assert "id-token" in delta["permissions_gained"]
    assert delta["permissions_gained"]["contents"]["after"] == "write"
    assert "pull_request_target" in delta["new_privileged_triggers"]
    assert delta["new_self_hosted_runner"] is True
    assert "evil/action@v1" in delta["new_mutable_action_references"]
    assert delta["new_untrusted_checkout_refs"] == [
        "${{ github.event.pull_request.head.sha }}"
    ]


def test_before_after_snapshots(wf_repo):
    root, path = wf_repo
    with open(path, "w") as fh:
        fh.write(RISKY_WF)
    result = igd.inspect_diff(root)
    change = result["workflow_changes"][0]
    assert change["before"]["permissions"] == {"contents": "read"}
    assert change["after"]["permissions"]["id-token"] == "write"
    assert "pull_request_target" in change["after"]["triggers"]


def test_not_a_git_repo(tmp_path):
    result = igd.inspect_diff(str(tmp_path))
    assert result["git"]["repository"] is False
    assert result["workflow_changes"] == []
