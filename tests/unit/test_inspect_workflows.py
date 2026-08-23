"""Unit tests for the GitHub Actions workflow inspector and YAML-subset parser."""

import os

import inspect_workflows as iw


def inspect_fixture(fixtures_dir, name):
    root = os.path.join(fixtures_dir, name)
    paths = iw._iter_workflow_files(root)
    return iw.inspect_paths(paths, root=root)["workflows"]


# --------------------------------------------------------------------------- #
# parser primitives
# --------------------------------------------------------------------------- #
def test_parse_basic_mapping_and_sequence():
    data, partial = iw.parse_yaml(
        "name: CI\n"
        "on:\n"
        "  push:\n"
        "    branches: [main, dev]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: make\n"
    )
    assert partial is False
    assert data["name"] == "CI"
    assert data["on"]["push"]["branches"] == ["main", "dev"]
    steps = data["jobs"]["build"]["steps"]
    assert steps[0]["uses"] == "actions/checkout@v4"
    assert steps[1]["run"] == "make"


def test_on_key_not_coerced_to_boolean():
    # In real YAML, `on` parses to True; our parser must keep it as a key.
    data, _ = iw.parse_yaml("on:\n  push:\n")
    assert "on" in data


def test_block_scalar_run_is_captured():
    data, _ = iw.parse_yaml(
        "jobs:\n"
        "  a:\n"
        "    steps:\n"
        "      - run: |\n"
        "          echo hello\n"
        "          echo ${{ github.event.pull_request.title }}\n"
    )
    run = data["jobs"]["a"]["steps"][0]["run"]
    assert "echo hello" in run
    assert "pull_request.title" in run


def test_comments_and_quotes_handled():
    data, _ = iw.parse_yaml(
        'name: "a # not a comment"  # real comment\n'
        "on: push  # trailing\n"
    )
    assert data["name"] == "a # not a comment"
    assert data["on"] == "push"


def test_scalar_sequence_items():
    data, partial = iw.parse_yaml(
        'on:\n  push:\n    tags:\n      - "v*"\n      - "release-*"\n'
    )
    assert partial is False
    assert data["on"]["push"]["tags"] == ["v*", "release-*"]


def test_parser_never_raises_on_garbage():
    for junk in ("\t\t: : :\n  - - -\n", "%%%%\n:::\n", "a:\n\tb: c\n"):
        data, partial = iw.parse_yaml(junk)
        # Must not raise; partial flag communicates uncertainty.
        assert isinstance(partial, bool)


# --------------------------------------------------------------------------- #
# action reference classification
# --------------------------------------------------------------------------- #
def test_pinned_sha_detected():
    a = iw._classify_action("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
    assert a["pinned"] is True
    assert a["ref"] == "11bd71901bbe5b1630ceea73d27597364c9af683"
    assert a["kind"] == "external"


def test_mutable_tag_not_pinned():
    a = iw._classify_action("docker/login-action@v3")
    assert a["pinned"] is False
    assert a["name"] == "docker/login-action"


def test_local_and_docker_and_reusable():
    assert iw._classify_action("./.github/actions/foo")["kind"] == "local"
    assert iw._classify_action("docker://alpine:3")["kind"] == "docker"
    ru = iw._classify_action("acme/repo/.github/workflows/release.yml@v1")
    assert ru["kind"] == "reusable-workflow"


# --------------------------------------------------------------------------- #
# fixture-level facts
# --------------------------------------------------------------------------- #
def test_secure_repo_is_clean_at_fact_level(fixtures_dir):
    wf = inspect_fixture(fixtures_dir, "secure-repo")[0]
    assert wf["parse_partial"] is False
    assert wf["permissions"] == {"contents": "read"}
    assert "pull_request_target" not in wf["triggers"]
    for job in wf["jobs"]:
        assert job["self_hosted"] is False
        assert job["checkout_refs"] == []
        for action in job["actions"]:
            assert action["pinned"] is True  # every external action is SHA-pinned


def test_vulnerable_actions_has_mutable_reference(fixtures_dir):
    wf = inspect_fixture(fixtures_dir, "vulnerable-actions")[0]
    refs = {a["name"]: a["pinned"] for job in wf["jobs"] for a in job["actions"]}
    assert refs["third-party/example"] is False


def test_dangerous_pr_target_correlated_facts(fixtures_dir):
    wf = inspect_fixture(fixtures_dir, "dangerous-pr-target")[0]
    assert "pull_request_target" in wf["triggers"]
    assert wf["permissions"]["contents"] == "write"
    job = wf["jobs"][0]
    # attacker-controlled checkout ref under the privileged trigger
    assert job["checkout_refs"]
    assert job["checkout_refs"][0]["references_untrusted_ref"] is True
    # untrusted input flows into a run step
    untrusted = [u for s in job["run_steps"] for u in s["references_untrusted_input"]]
    assert "github.event.pull_request.title" in untrusted


def test_excessive_permissions_and_self_hosted(fixtures_dir):
    wf = inspect_fixture(fixtures_dir, "excessive-permissions")[0]
    assert wf["permissions"] == "write-all"
    assert wf["jobs"][0]["self_hosted"] is True


def test_supply_chain_id_token_and_environment(fixtures_dir):
    wf = inspect_fixture(fixtures_dir, "supply-chain")[0]
    assert wf["permissions"]["id-token"] == "write"
    assert wf["permissions"]["packages"] == "write"
    assert wf["jobs"][0]["environment"] == "production"
    mutable = [a["name"] for a in wf["jobs"][0]["actions"] if a["pinned"] is False]
    assert "docker/login-action" in mutable
