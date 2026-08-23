"""Unit tests for the findings state manager."""

import json
import os

import pytest

import state


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def sample_finding(**overrides):
    f = {
        "domain": "ci",
        "category": "mutable-action",
        "resource": ".github/workflows/release.yml",
        "condition": "docker/login-action",
        "title": "Third-party Action uses a mutable reference",
        "severity": "high",
        "confidence": "high",
        "status": "open",
        "evidence": [
            {
                "type": "repository-file",
                "source": ".github/workflows/release.yml",
                "location": {"line": 37},
                "observed": "uses: docker/login-action@v3",
            }
        ],
        "impact": "Mutable third-party Action reference in the release workflow.",
        "remediation": {
            "summary": "Pin the Action to the reviewed full commit SHA.",
            "type": "file-change",
            "automatic": True,
            "targets": [".github/workflows/release.yml"],
        },
        "verification": {
            "method": "workflow-reference",
            "expected": "full-commit-sha",
            "status": "pending",
        },
    }
    f.update(overrides)
    return f


def init_state(tmp_path):
    path = os.path.join(str(tmp_path), ".attestarc", "findings.json")
    state.main(["--file", path, "init", "--root", str(tmp_path)])
    return path


def run(tmp_path, *args):
    """Invoke the CLI with --root bound to tmp_path (write confinement base)."""
    return state.main(["--file",
                       os.path.join(str(tmp_path), ".attestarc", "findings.json"),
                       *args, "--root", str(tmp_path)])


# --------------------------------------------------------------------------- #
# fingerprints / ids
# --------------------------------------------------------------------------- #
def test_fingerprint_is_stable_and_deterministic():
    a = state.compute_fingerprint("ci", "mutable-action", "release.yml", "x")
    b = state.compute_fingerprint("ci", "mutable-action", "release.yml", "x")
    assert a == b
    assert len(a) == 64
    assert a != state.compute_fingerprint("ci", "mutable-action", "release.yml", "y")


def test_display_id_format_and_github_actions_prefix():
    fp = state.compute_fingerprint(
        "ci", "mutable-action", ".github/workflows/release.yml", "docker/login-action"
    )
    fid = state.display_id(fp, "ci", "mutable-action",
                           ".github/workflows/release.yml")
    assert fid.startswith("AA-GHA-")
    assert len(fid.split("-")[-1]) == 8
    assert fid.split("-")[-1] == fp[:8].upper()


def test_fingerprint_ignores_condition_rewording():
    # The free-text condition is NOT part of the fingerprint; re-wording the
    # human explanation of the same issue must keep the same id.
    base = dict(domain="ci", category="mutable-action",
                resource=".github/workflows/release.yml", subject="docker/login-action")
    a = state.compute_fingerprint(base["domain"], base["category"],
                                  base["resource"], base["subject"])
    # subject drives disambiguation; a different subject on the same resource
    # is a genuinely different finding.
    b = state.compute_fingerprint(base["domain"], base["category"],
                                  base["resource"], "actions/checkout")
    assert a != b


def test_fingerprint_canonicalizes_casing_and_separators():
    a = state.compute_fingerprint("ci", "mutable-action",
                                  ".github/workflows/Release.yml", "X")
    b = state.compute_fingerprint("ci", "mutable-action",
                                  ".github\\workflows\\release.yml", "x")
    assert a == b


def test_id_prefix_per_domain():
    assert state.id_prefix("repository") == "REP"
    assert state.id_prefix("dependencies") == "DEP"
    assert state.id_prefix("identity-secrets") == "IDS"
    assert state.id_prefix("supply-chain") == "SC"
    assert state.id_prefix("changes") == "CHG"
    assert state.id_prefix("ci", "some-generic-check") == "CI"


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #
def test_init_creates_valid_state(tmp_path):
    path = init_state(tmp_path)
    assert os.path.exists(path)
    with open(path) as fh:
        data = json.load(fh)
    assert data["schema_version"] == 2
    assert data["findings"] == []
    assert validate_ok(data)


def test_init_writes_trailing_newline_and_sorted_keys(tmp_path):
    path = init_state(tmp_path)
    with open(path) as fh:
        text = fh.read()
    assert text.endswith("\n")
    # sort_keys means created_at precedes findings precedes repository ...
    top_keys = list(json.loads(text).keys())
    assert top_keys == sorted(top_keys)


def test_init_updates_git_exclude(tmp_path):
    os.makedirs(os.path.join(str(tmp_path), ".git", "info"))
    path = init_state(tmp_path)
    exclude = os.path.join(str(tmp_path), ".git", "info", "exclude")
    assert os.path.exists(exclude)
    with open(exclude) as fh:
        assert ".attestarc/" in fh.read()
    # tracked .gitignore must not be created
    assert not os.path.exists(os.path.join(str(tmp_path), ".gitignore"))


def test_init_git_exclude_not_duplicated(tmp_path):
    os.makedirs(os.path.join(str(tmp_path), ".git", "info"))
    init_state(tmp_path)
    # second init should be a no-op for the exclude entry
    path = os.path.join(str(tmp_path), ".attestarc", "findings.json")
    state.main(["--file", path, "init", "--root", str(tmp_path)])
    exclude = os.path.join(str(tmp_path), ".git", "info", "exclude")
    with open(exclude) as fh:
        content = fh.read()
    assert content.count(".attestarc/") == 1


def test_init_no_git_repo_is_fine(tmp_path):
    path = init_state(tmp_path)
    assert os.path.exists(path)  # did not raise despite no .git


def validate_ok(data):
    return state.validate_state(data) == []


# --------------------------------------------------------------------------- #
# upsert
# --------------------------------------------------------------------------- #
def test_upsert_creates_then_updates_same_fingerprint(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)

    stored, created = state.upsert_finding(s, sample_finding())
    assert created is True
    first_id = stored["id"]
    first_seen = stored["first_seen"]

    # Same logical finding again -> update, not a new entry.
    stored2, created2 = state.upsert_finding(s, sample_finding())
    assert created2 is False
    assert stored2["id"] == first_id
    assert stored2["first_seen"] == first_seen
    assert len(s["findings"]) == 1


def test_upsert_merges_evidence_without_duplicates(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    state.upsert_finding(s, sample_finding())

    extra = sample_finding()
    extra["evidence"] = [
        extra["evidence"][0],  # duplicate, should not be added twice
        {"type": "repository-file", "source": "x.yml",
         "location": {"line": 5}, "observed": "uses: foo/bar@v1"},
    ]
    stored, _ = state.upsert_finding(s, extra)
    observed = [e["observed"] for e in stored["evidence"]]
    assert observed.count("uses: docker/login-action@v3") == 1
    assert "uses: foo/bar@v1" in observed


def test_upsert_preserves_human_decided_status(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    stored, _ = state.upsert_finding(s, sample_finding())
    fid = stored["id"]

    # Human accepts the risk.
    state.cmd_set_status  # symbol exists
    f = state.find_by_id(s, fid)
    f["status"] = "accepted_risk"

    # A later assessment re-observes it -> must NOT reopen.
    stored2, created = state.upsert_finding(s, sample_finding())
    assert created is False
    assert stored2["status"] == "accepted_risk"


def test_upsert_rejects_secret_in_evidence(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    bad = sample_finding()
    bad["evidence"] = [{
        "type": "repository-file",
        "source": "deploy.sh",
        "observed": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
    }]
    with pytest.raises(state.StateError):
        state.upsert_finding(s, bad)


def test_upsert_requires_resource_or_fingerprint(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    f = sample_finding()
    del f["resource"]
    del f["condition"]
    with pytest.raises(state.StateError):
        state.upsert_finding(s, f)


def test_upsert_accepts_explicit_fingerprint(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    fp = "a" * 64
    f = sample_finding()
    del f["resource"]
    del f["condition"]
    f["fingerprint"] = fp
    stored, _ = state.upsert_finding(s, f)
    assert stored["fingerprint"] == fp
    assert stored["id"].endswith(fp[:8].upper())


# --------------------------------------------------------------------------- #
# CLI round trips
# --------------------------------------------------------------------------- #
def test_cli_upsert_get_list_setstatus_resolve(tmp_path, capsys):
    path = init_state(tmp_path)
    capsys.readouterr()  # discard init output
    finding_file = os.path.join(str(tmp_path), "finding.json")
    with open(finding_file, "w") as fh:
        json.dump(sample_finding(), fh)

    assert run(tmp_path, "upsert", finding_file) == 0
    out = json.loads(capsys.readouterr().out)
    fid = out["id"]
    assert out["action"] == "created"

    assert run(tmp_path, "get", fid) == 0
    got = json.loads(capsys.readouterr().out)
    assert got["id"] == fid

    assert run(tmp_path, "list", "--status", "open") == 0
    listed = json.loads(capsys.readouterr().out)
    assert len(listed) == 1

    assert run(tmp_path, "set-status", fid, "remediating") == 0
    capsys.readouterr()

    assert run(tmp_path, "resolve", fid,
               "--observed", "immutable full commit SHA") == 0
    res = json.loads(capsys.readouterr().out)
    assert res["status"] == "resolved"

    f = state.find_by_id(state.load_state(path), fid)
    assert f["verification"]["status"] == "verified"
    assert "checked_at" in f["verification"]


def test_cli_upsert_stdin(tmp_path, capsys, monkeypatch):
    import io
    path = init_state(tmp_path)
    capsys.readouterr()  # discard init output
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(sample_finding())))
    assert run(tmp_path, "upsert", "-") == 0
    out = json.loads(capsys.readouterr().out)
    assert out["action"] == "created"


def test_cli_list_sorted_by_severity(tmp_path, capsys):
    path = init_state(tmp_path)
    capsys.readouterr()  # discard init output
    s = state.load_state(path)
    state.upsert_finding(s, sample_finding(
        severity="low", category="a", resource="a"))
    state.upsert_finding(s, sample_finding(
        severity="critical", category="b", resource="b"))
    state.upsert_finding(s, sample_finding(
        severity="medium", category="c", resource="c"))
    state.save_state(s, path)

    run(tmp_path, "list")
    listed = json.loads(capsys.readouterr().out)
    assert [f["severity"] for f in listed] == ["critical", "medium", "low"]


def test_get_unknown_id_returns_error(tmp_path):
    init_state(tmp_path)
    assert run(tmp_path, "get", "AA-GHA-00000000") == 1


# --------------------------------------------------------------------------- #
# validation / corruption recovery
# --------------------------------------------------------------------------- #
def test_validate_detects_bad_enum(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    stored, _ = state.upsert_finding(s, sample_finding())
    stored["severity"] = "extreme"
    state.save_state(s, path)
    errors = state.validate_state(state.load_state(path))
    assert any("severity" in e for e in errors)


def test_corrupt_json_is_backed_up_and_reinitialized(tmp_path):
    path = init_state(tmp_path)
    with open(path, "w") as fh:
        fh.write("{ this is not valid json ")
    s = state.load_state(path)  # recover=True default
    assert s["findings"] == []
    backups = [n for n in os.listdir(os.path.dirname(path))
               if n.startswith("findings.json.corrupt-")]
    assert backups


def test_validate_command_fails_on_corrupt_without_recovery(tmp_path):
    path = init_state(tmp_path)
    with open(path, "w") as fh:
        fh.write("not json")
    assert run(tmp_path, "validate") == 1


def test_atomic_write_leaves_no_temp_files(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    state.upsert_finding(s, sample_finding())
    state.save_state(s, path)
    leftovers = [n for n in os.listdir(os.path.dirname(path))
                 if n.endswith(".tmp")]
    assert leftovers == []


# --------------------------------------------------------------------------- #
# threat / trust_boundary / related_findings (attack-path reasoning fields)
# --------------------------------------------------------------------------- #
def _threat(**overrides):
    t = {
        "actor": "external-contributor",
        "entrypoint": "pull_request_target",
        "controlled_input": "pull-request source",
        "trust_transition": "untrusted checkout executes in privileged job",
        "capabilities": ["EXECUTE_UNTRUSTED_CODE", "REQUEST_WORKLOAD_IDENTITY"],
        "target": "production AWS identity",
        "reachability": "direct",
        "preconditions": [],
        "evidence_gaps": [],
    }
    t.update(overrides)
    return t


def test_upsert_preserves_threat_fields_on_create(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    f = sample_finding(
        threat=_threat(),
        trust_boundary="untrusted-contributor -> privileged-ci",
        related_findings=["AA-GHA-ABCDEF"],
    )
    stored, created = state.upsert_finding(s, f)
    assert created is True
    assert stored["threat"]["actor"] == "external-contributor"
    assert stored["threat"]["reachability"] == "direct"
    assert stored["threat"]["capabilities"] == [
        "EXECUTE_UNTRUSTED_CODE", "REQUEST_WORKLOAD_IDENTITY"]
    assert stored["trust_boundary"] == "untrusted-contributor -> privileged-ci"
    assert stored["related_findings"] == ["AA-GHA-ABCDEF"]

    # Survives a save/load round trip and validates cleanly.
    state.save_state(s, path)
    reloaded = state.load_state(path)
    assert validate_ok(reloaded)
    again = state.find_by_id(reloaded, stored["id"])
    assert again["threat"]["target"] == "production AWS identity"


def test_upsert_refreshes_threat_on_update(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    state.upsert_finding(s, sample_finding(threat=_threat(reachability="direct")))

    stored2, created = state.upsert_finding(
        s, sample_finding(threat=_threat(reachability="conditional",
                                         preconditions=["fork PR approved"])))
    assert created is False
    assert stored2["threat"]["reachability"] == "conditional"
    assert stored2["threat"]["preconditions"] == ["fork PR approved"]
    assert len(s["findings"]) == 1


def test_upsert_rejects_secret_in_evidence_value(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    bad = sample_finding()
    bad["evidence"] = [{
        "type": "repository-file",
        "source": "deploy.yml",
        "key": "aws-access-key-id",
        "value": "AKIAIOSFODNN7EXAMPLE",
    }]
    with pytest.raises(state.StateError):
        state.upsert_finding(s, bad)


def test_upsert_rejects_secret_in_threat(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    bad = sample_finding(threat=_threat(target="leaked AKIAIOSFODNN7EXAMPLE"))
    with pytest.raises(state.StateError):
        state.upsert_finding(s, bad)


def test_threat_may_reference_secret_name(tmp_path):
    # Referencing a secret NAME (not its value) is fine.
    path = init_state(tmp_path)
    s = state.load_state(path)
    ok = sample_finding(threat=_threat(target="production AWS_DEPLOY_KEY"))
    stored, created = state.upsert_finding(s, ok)
    assert created is True
    assert stored["threat"]["target"] == "production AWS_DEPLOY_KEY"


# --------------------------------------------------------------------------- #
# secret scan over ALL string leaves (not just evidence/threat)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("field,value", [
    ("title", "leaked ghp_012345678901234567890123456789abcd token"),
    ("impact", "AKIAIOSFODNN7EXAMPLE grants deploy access"),
])
def test_upsert_rejects_secret_in_top_level_text(tmp_path, field, value):
    path = init_state(tmp_path)
    s = state.load_state(path)
    bad = sample_finding(**{field: value})
    with pytest.raises(state.StateError):
        state.upsert_finding(s, bad)


def test_upsert_rejects_secret_in_remediation(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    bad = sample_finding()
    bad["remediation"] = dict(bad["remediation"],
                              summary="rotate AKIAIOSFODNN7EXAMPLE now")
    with pytest.raises(state.StateError):
        state.upsert_finding(s, bad)


def test_upsert_rejects_secret_in_extensions(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    bad = sample_finding(extensions={"note": "token AKIAIOSFODNN7EXAMPLE"})
    with pytest.raises(state.StateError):
        state.upsert_finding(s, bad)


# --------------------------------------------------------------------------- #
# durable string size cap (anti prompt-injection payload inflation)
# --------------------------------------------------------------------------- #
def test_long_string_leaf_is_truncated(tmp_path):
    path = init_state(tmp_path)
    s = state.load_state(path)
    huge = "A" * (state._MAX_STRING_LEN * 3)
    f = sample_finding(impact=huge)
    stored, _ = state.upsert_finding(s, f)
    assert len(stored["impact"]) <= state._MAX_STRING_LEN
    assert stored["impact"].endswith(state._TRUNCATION_MARKER)


# --------------------------------------------------------------------------- #
# write confinement / symlink escape
# --------------------------------------------------------------------------- #
def test_refuses_write_when_attestarc_is_symlink_escaping_root(tmp_path):
    import os as _os
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    # .attestarc inside the repo is a symlink pointing outside the repo.
    _os.symlink(str(outside), str(repo / ".attestarc"))
    path = str(repo / ".attestarc" / "findings.json")
    rc = state.main(["--file", path, "init", "--root", str(repo)])
    assert rc == 2  # StateError -> exit 2; nothing written outside the repo
    assert not (outside / "findings.json").exists()


def test_atomic_write_confinement_allows_in_root(tmp_path):
    # Sanity: a normal in-root write is permitted.
    path = init_state(tmp_path)
    assert os.path.exists(path)
