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
# docker image mutability: digest = immutable, tag / implicit-latest = mutable
# --------------------------------------------------------------------------- #
def test_docker_tag_is_mutable():
    a = iw._classify_action("docker://alpine:3.19")
    assert a["kind"] == "docker"
    assert a["pinned"] is False
    assert a["ref"] == "3.19"
    assert a["name"] == "docker://alpine"


def test_docker_implicit_latest_is_mutable():
    a = iw._classify_action("docker://alpine")
    assert a["kind"] == "docker"
    assert a["pinned"] is False
    assert a["ref"] is None


def test_docker_digest_is_pinned():
    digest = "sha256:" + "a" * 64
    a = iw._classify_action(f"docker://alpine@{digest}")
    assert a["kind"] == "docker"
    assert a["pinned"] is True
    assert a["ref"] == digest


def test_docker_registry_port_tag_not_confused():
    # A registry port (:5000) must not be read as the image tag.
    a = iw._classify_action("docker://registry.example.com:5000/team/img:1.2")
    assert a["kind"] == "docker"
    assert a["pinned"] is False
    assert a["ref"] == "1.2"
    assert a["name"] == "docker://registry.example.com:5000/team/img"


def test_docker_registry_port_no_tag_is_mutable():
    a = iw._classify_action("docker://registry.example.com:5000/team/img")
    assert a["kind"] == "docker"
    assert a["pinned"] is False
    assert a["ref"] is None


# --------------------------------------------------------------------------- #
# ref_kind / looks_like_version: movable branch vs movable version tag vs SHA
# --------------------------------------------------------------------------- #
def test_ref_kind_sha_is_not_version():
    a = iw._classify_action(
        "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
    assert a["ref_kind"] == "sha"
    assert a["looks_like_version"] is False


def test_ref_kind_version_tag_is_movable_and_version_like():
    for ref in ("v4", "v1.2", "v1.2.3", "1.2.3", "v2.0.0-rc.1"):
        a = iw._classify_action(f"actions/checkout@{ref}")
        assert a["ref_kind"] == "movable", ref
        assert a["looks_like_version"] is True, ref
        assert a["pinned"] is False, ref


def test_ref_kind_branch_is_movable_but_not_version_like():
    for ref in ("main", "master", "develop", "release"):
        a = iw._classify_action(f"third-party/example@{ref}")
        assert a["ref_kind"] == "movable", ref
        assert a["looks_like_version"] is False, ref


def test_ref_kind_none_for_local_and_missing_ref():
    local = iw._classify_action("./.github/actions/foo")
    assert local["ref_kind"] == "none"
    assert local["looks_like_version"] is False
    # An external action with no @ref at all.
    noref = iw._classify_action("actions/checkout")
    assert noref["ref_kind"] == "none"
    assert noref["looks_like_version"] is False


def test_ref_kind_docker_tag_digest_and_latest():
    tag = iw._classify_action("docker://alpine:3.19")
    assert tag["ref_kind"] == "movable"
    assert tag["looks_like_version"] is True
    branchy = iw._classify_action("docker://alpine:edge")
    assert branchy["ref_kind"] == "movable"
    assert branchy["looks_like_version"] is False
    digest = iw._classify_action("docker://alpine@sha256:" + "a" * 64)
    assert digest["ref_kind"] == "sha"
    assert digest["looks_like_version"] is False
    latest = iw._classify_action("docker://alpine")
    assert latest["ref_kind"] == "movable"
    assert latest["looks_like_version"] is False


# --------------------------------------------------------------------------- #
# trigger_details: per-event qualifiers, back-compat flat triggers preserved
# --------------------------------------------------------------------------- #
def test_trigger_details_push_tags_vs_branches():
    wf = iw.inspect_workflow_text(
        "on:\n"
        "  push:\n"
        "    tags: ['v*']\n"
        "    branches: [main]\n"
        "    paths: ['src/**']\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: make\n",
        "ci.yml",
    )
    assert wf["triggers"] == ["push"]  # flat list unchanged
    details = wf["trigger_details"]
    assert details["push"]["tags"] == ["v*"]
    assert details["push"]["branches"] == ["main"]
    assert details["push"]["paths"] == ["src/**"]


def test_trigger_details_preserves_pull_request_target_distinction():
    wf = iw.inspect_workflow_text(
        "on:\n"
        "  pull_request:\n"
        "    types: [opened, synchronize]\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: make\n",
        "ci.yml",
    )
    details = wf["trigger_details"]
    assert "pull_request" in details
    assert "pull_request_target" in details
    assert details["pull_request"]["types"] == ["opened", "synchronize"]
    # pull_request_target with an empty body is present but unqualified.
    assert details["pull_request_target"] == {}


def test_trigger_details_list_and_string_forms():
    listed = iw.inspect_workflow_text(
        "on: [push, pull_request]\njobs: {}\n", "ci.yml")
    assert listed["trigger_details"] == {"push": {}, "pull_request": {}}
    single = iw.inspect_workflow_text("on: push\njobs: {}\n", "ci.yml")
    assert single["trigger_details"] == {"push": {}}


def test_trigger_details_schedule_cron_captured():
    wf = iw.inspect_workflow_text(
        "on:\n"
        "  schedule:\n"
        "    - cron: '0 0 * * *'\n"
        "jobs: {}\n",
        "ci.yml",
    )
    assert wf["trigger_details"]["schedule"]["cron"] == ["0 0 * * *"]


def test_trigger_details_empty_on_unparseable():
    wf = iw.inspect_workflow_text("%%% not yaml\n:::\n- - -\n", "ci.yml")
    assert wf["trigger_details"] == {}


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


# --------------------------------------------------------------------------- #
# reusable-workflow calls: uses_pinned + secrets passing (inline YAML)
# --------------------------------------------------------------------------- #
_SHA = "1234567890abcdef1234567890abcdef12345678"  # 40 hex chars


def test_job_uses_pinned_true_for_sha_ref():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  call:\n"
        "    uses: org/repo/.github/workflows/x.yml@" + _SHA + "\n",
        "caller.yml",
    )
    assert wf["parse_partial"] is False
    job = wf["jobs"][0]
    assert job["uses_pinned"] is True


def test_job_uses_pinned_false_for_mutable_ref():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  call:\n"
        "    uses: org/repo/.github/workflows/x.yml@main\n",
        "caller.yml",
    )
    job = wf["jobs"][0]
    assert job["uses_pinned"] is False


def test_job_uses_pinned_none_when_no_job_level_uses():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n",
        "ci.yml",
    )
    job = wf["jobs"][0]
    assert job["uses_pinned"] is None


def test_job_secrets_inherit():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  call:\n"
        "    uses: org/repo/.github/workflows/x.yml@main\n"
        "    secrets: inherit\n",
        "caller.yml",
    )
    assert wf["jobs"][0]["secrets"] == "inherit"


def test_job_secrets_explicit_mapping():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  call:\n"
        "    uses: org/repo/.github/workflows/x.yml@main\n"
        "    secrets:\n"
        "      TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n",
        "caller.yml",
    )
    secrets = wf["jobs"][0]["secrets"]
    assert isinstance(secrets, dict)
    assert secrets["TOKEN"] == "${{ secrets.DEPLOY_TOKEN }}"


def test_job_secrets_none_when_absent():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n",
        "ci.yml",
    )
    assert wf["jobs"][0]["secrets"] is None


# --------------------------------------------------------------------------- #
# cache usage (presence fact)
# --------------------------------------------------------------------------- #
def test_uses_cache_true_for_actions_cache():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/cache@v4\n",
        "ci.yml",
    )
    assert wf["jobs"][0]["uses_cache"] is True


def test_uses_cache_true_for_setup_action_with_cache_input():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          cache: npm\n",
        "ci.yml",
    )
    assert wf["jobs"][0]["uses_cache"] is True


def test_uses_cache_false_without_cache_action():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: make\n",
        "ci.yml",
    )
    assert wf["jobs"][0]["uses_cache"] is False


# --------------------------------------------------------------------------- #
# fetch-then-execute run-step facts, and run_step recording policy
# --------------------------------------------------------------------------- #
def test_fetch_execute_curl_pipe_bash():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: curl -sSL https://example.com/install.sh | bash\n",
        "ci.yml",
    )
    steps = wf["jobs"][0]["run_steps"]
    assert len(steps) == 1
    assert steps[0]["fetch_execute"] is True
    assert steps[0]["fetch_execute_excerpt"]
    assert "curl" in steps[0]["fetch_execute_excerpt"]


def test_fetch_execute_wget_chmod():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: wget https://example.com/tool -O tool && chmod +x tool\n",
        "ci.yml",
    )
    steps = wf["jobs"][0]["run_steps"]
    assert len(steps) == 1
    assert steps[0]["fetch_execute"] is True
    assert "wget" in steps[0]["fetch_execute_excerpt"]


def test_benign_run_is_recorded_with_excerpt():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hello world\n",
        "ci.yml",
    )
    # Every ``run:`` step is a fact: command execution the host may need to
    # reason about, even with no expression and no fetch-execute. It carries a
    # compact, sanitized excerpt but no untrusted/fetch signal.
    steps = wf["jobs"][0]["run_steps"]
    assert len(steps) == 1
    assert steps[0]["has_run"] is True
    assert steps[0]["run_excerpt"] == "echo hello world"
    assert steps[0]["expressions"] == []
    assert steps[0]["references_untrusted_input"] == []
    assert steps[0]["fetch_execute"] is False


def test_benign_uses_step_with_trusted_expression_is_not_a_run_step():
    # A ``uses:`` step whose only expression is trusted (``matrix.*``) is an
    # action, not command execution: it belongs to ``actions`` and must not be
    # forced into ``run_steps`` (the pre-fix behavior that inflated run_steps).
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/setup-node@v4\n"
        "        with:\n"
        "          node-version: ${{ matrix.node }}\n",
        "ci.yml",
    )
    job = wf["jobs"][0]
    assert job["run_steps"] == []
    assert [a["name"] for a in job["actions"]] == ["actions/setup-node"]


def test_run_step_with_expression_recorded_without_fetch_execute():
    wf = iw.inspect_workflow_text(
        "on: push\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo ${{ github.sha }}\n",
        "ci.yml",
    )
    steps = wf["jobs"][0]["run_steps"]
    assert len(steps) == 1
    assert steps[0]["fetch_execute"] is False
    assert steps[0]["fetch_execute_excerpt"] is None
    assert steps[0]["expressions"] == ["github.sha"]


# --------------------------------------------------------------------------- #
# Regression tests for parser bugs found in the v0.3.0 real-repo feedback pass
# --------------------------------------------------------------------------- #
def test_leading_document_start_marker_does_not_drop_facts():
    # A leading ``---`` must not make the whole workflow parse as a block
    # sequence (which returned a list and discarded every fact).
    wf = iw.inspect_workflow_text(
        "---\n"
        "name: CI\n"
        "on: [push]\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: pytest\n",
        "ci.yml",
    )
    assert wf["parse_partial"] is False
    assert wf["name"] == "CI"
    assert wf["triggers"] == ["push"]
    assert wf["permissions"] == {"contents": "read"}
    assert [j["id"] for j in wf["jobs"]] == ["build"]


def test_trailing_document_end_marker_is_ignored():
    wf = iw.inspect_workflow_text(
        "name: CI\n"
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: pytest\n"
        "...\n",
        "ci.yml",
    )
    assert wf["parse_partial"] is False
    assert [j["id"] for j in wf["jobs"]] == ["build"]


def test_block_sequence_at_same_indent_as_key_is_parsed():
    # ``steps:`` and its ``- `` items at the SAME column is common GitHub
    # Actions style; the items must not be dropped.
    wf = iw.inspect_workflow_text(
        "name: CI\n"
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "    - uses: actions/checkout@v4\n"
        "    - uses: actions/cache@v4\n"
        "    - run: pytest -q\n",
        "ci.yml",
    )
    assert wf["parse_partial"] is False
    job = wf["jobs"][0]
    assert [a["name"] for a in job["actions"]] == [
        "actions/checkout",
        "actions/cache",
    ]
    assert job["uses_cache"] is True
    assert len(job["run_steps"]) == 1
    assert job["run_steps"][0]["run_excerpt"] == "pytest -q"


def test_fetch_execute_matches_language_interpreters():
    # ``curl ... | python3 -`` (and node/ruby/perl) is fetch-then-execute just
    # like ``| bash``.
    for cmd in (
        "curl -sSL https://example.com/i.py | python3 -",
        "wget -qO- https://example.com/i.js | node",
        "curl https://example.com/i.rb | ruby",
    ):
        matched, excerpt = iw._fetch_execute_facts(cmd)
        assert matched is True, cmd
        assert excerpt == cmd
    # A pinned package install is not fetch-execute.
    assert iw._fetch_execute_facts("pip install requests==2.31.0")[0] is False


def test_run_excerpt_is_whitespace_collapsed_and_truncated():
    long_run = "echo start\n" + ("x" * 500) + "\necho end"
    excerpt = iw._run_excerpt(long_run)
    assert "\n" not in excerpt
    assert excerpt.endswith("...")
    assert len(excerpt) == 203  # 200 chars + "..."


# --------------------------------------------------------------------------- #
# read-path containment (the repository is untrusted input)
# --------------------------------------------------------------------------- #
def _make_repo_with_workflows(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: make\n"
    )
    return repo


def _secret_outside(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.yml"
    secret.write_text("on: push\njobs:\n  leak:\n    runs-on: ubuntu-latest\n")
    return outside, secret


def test_inspect_paths_refuses_absolute_path_outside_root(tmp_path):
    repo = _make_repo_with_workflows(tmp_path)
    _outside, secret = _secret_outside(tmp_path)
    wfs = iw.inspect_paths([str(secret)], root=str(repo))["workflows"]
    assert len(wfs) == 1
    assert wfs[0]["out_of_root"] is True
    assert wfs[0]["parse_partial"] is True
    assert "jobs" not in wfs[0]  # never parsed / leaked


def test_inspect_paths_refuses_dotdot_traversal(tmp_path):
    repo = _make_repo_with_workflows(tmp_path)
    _outside, _secret = _secret_outside(tmp_path)
    wfs = iw.inspect_paths(["../outside/secret.yml"], root=str(repo))["workflows"]
    assert len(wfs) == 1
    assert wfs[0]["out_of_root"] is True
    assert "jobs" not in wfs[0]


def test_inspect_paths_refuses_symlinked_workflow_file(tmp_path):
    repo = _make_repo_with_workflows(tmp_path)
    _outside, secret = _secret_outside(tmp_path)
    link = repo / ".github" / "workflows" / "evil.yml"
    os.symlink(str(secret), str(link))
    wfs = iw.inspect_paths([".github/workflows/evil.yml"], root=str(repo))["workflows"]
    assert len(wfs) == 1
    assert wfs[0]["out_of_root"] is True
    assert "jobs" not in wfs[0]


def test_inspect_paths_refuses_symlink_to_nonexistent_outside_target(tmp_path):
    # A *broken* symlink whose target is outside root must still be refused --
    # os.path.realpath resolves the escaping link even when the target is absent.
    repo = _make_repo_with_workflows(tmp_path)
    link = repo / ".github" / "workflows" / "evil.yml"
    os.symlink(os.path.join("..", "..", "..", "outside", "gone.yml"), str(link))
    wfs = iw.inspect_paths([".github/workflows/evil.yml"], root=str(repo))["workflows"]
    assert len(wfs) == 1
    assert wfs[0]["out_of_root"] is True
    assert "jobs" not in wfs[0]
    # ...and enumeration skips it entirely.
    assert os.path.join(".github", "workflows", "evil.yml") \
        not in iw._iter_workflow_files(str(repo))


def test_inspect_paths_reads_a_legit_in_root_workflow(tmp_path):
    # Sanity: normal in-root files are still parsed.
    repo = _make_repo_with_workflows(tmp_path)
    wfs = iw.inspect_paths([".github/workflows/ci.yml"], root=str(repo))["workflows"]
    assert len(wfs) == 1
    assert "out_of_root" not in wfs[0]
    assert "jobs" in wfs[0]


def test_iter_workflow_files_skips_symlinked_entry(tmp_path):
    repo = _make_repo_with_workflows(tmp_path)
    _outside, secret = _secret_outside(tmp_path)
    os.symlink(str(secret), str(repo / ".github" / "workflows" / "evil.yml"))
    found = iw._iter_workflow_files(str(repo))
    assert os.path.join(".github", "workflows", "ci.yml") in found
    assert os.path.join(".github", "workflows", "evil.yml") not in found


def test_iter_workflow_files_skips_symlinked_workflows_dir(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".github").mkdir(parents=True)
    outside_wf = tmp_path / "outside_wf"
    outside_wf.mkdir()
    (outside_wf / "ci.yml").write_text("on: push\n")
    os.symlink(str(outside_wf), str(repo / ".github" / "workflows"))
    assert iw._iter_workflow_files(str(repo)) == []
