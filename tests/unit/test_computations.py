"""Tests for the OKF Attested-Computation modeling of the kernel helpers
(``scripts/computations/``) and its structural ``attester``.

The attester is a **structural receipt validator only** — it must accept the real
fact receipts the helpers emit, refuse a verdict-shaped receipt (the facts-not-
verdicts layer boundary, SPECIFICATION.md §2.6/§12.5), and never crash on garbage.
It must never itself grow into a verdict emitter.
"""

import glob
import json
import os
import sys

import pytest

import okf

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))
_COMP_DIR = os.path.join(_REPO_ROOT, "scripts", "computations")
if _COMP_DIR not in sys.path:
    sys.path.insert(0, _COMP_DIR)

import attester  # noqa: E402

import discover_repo  # noqa: E402
import inspect_git_diff  # noqa: E402
import inspect_workflows  # noqa: E402


def _concept_paths():
    return attester.concept_files(_COMP_DIR)


# --------------------------------------------------------------------------- #
# Concept files: present, canonical, well-formed, in the right trust zone
# --------------------------------------------------------------------------- #
def test_the_three_helpers_are_modeled():
    ids = set()
    for p in _concept_paths():
        ids.add(attester.load_computation(p)["id"])
    assert ids == {"AC-discover-repo", "AC-inspect-workflows",
                   "AC-inspect-git-diff"}


def test_every_concept_is_canonical_okf():
    for p in _concept_paths():
        raw = open(p, encoding="utf-8").read()
        assert okf.roundtrip_ok(raw), f"non-canonical: {p}"


def test_concepts_declare_facts_read_only_offline():
    for p in _concept_paths():
        fm = okf.read_concept(p)["frontmatter"]
        assert fm["type"] == "Attested Computation"
        ns = fm["attestarc"]
        # The load-bearing invariants of this trust zone.
        assert ns["emits"] == "facts"
        assert ns["read_only"] is True
        assert ns["network"] is False
        assert ns["executes_repo_code"] is False
        assert ns["receipt"]["required_keys"]
        assert "verdict" in ns["receipt"]["forbidden_keys"]


def test_entrypoints_exist():
    for p in _concept_paths():
        ep = attester.load_computation(p)["entrypoint"]
        assert os.path.exists(os.path.join(_REPO_ROOT, ep)), ep


def test_computation_tree_is_not_the_knowledge_plane():
    # A different trust zone: these describe kernel scripts and must never sit in
    # the knowledge bundle where they would be attested as volatile facts.
    assert os.path.commonpath(
        [_COMP_DIR, os.path.join(_REPO_ROOT, "knowledge")]
    ) == _REPO_ROOT
    assert not glob.glob(os.path.join(_REPO_ROOT, "knowledge", "bootstrap",
                                      "**", "AC-*.md"), recursive=True)


def test_verify_concepts_self_check_passes():
    result = attester.verify_concepts(_COMP_DIR)
    assert result["all_ok"] is True, result


# --------------------------------------------------------------------------- #
# Attester accepts the REAL fact receipts the helpers emit
# --------------------------------------------------------------------------- #
def _validate(concept_slug, receipt):
    comp = attester.load_computation(os.path.join(_COMP_DIR, concept_slug))
    return attester.validate_receipt(comp, receipt)


def test_real_discover_repo_receipt_is_valid():
    receipt = discover_repo.discover(_REPO_ROOT)
    res = _validate("discover-repo.md", receipt)
    assert res["structurally_valid"] is True, res["violations"]


def test_real_inspect_workflows_receipt_is_valid():
    wf_files = inspect_workflows._iter_workflow_files(_REPO_ROOT)
    receipt = inspect_workflows.inspect_paths(wf_files, root=_REPO_ROOT)
    res = _validate("inspect-workflows.md", receipt)
    assert res["structurally_valid"] is True, res["violations"]


def test_real_inspect_git_diff_receipt_is_valid():
    receipt = inspect_git_diff.inspect_diff(_REPO_ROOT)
    res = _validate("inspect-git-diff.md", receipt)
    assert res["structurally_valid"] is True, res["violations"]


# --------------------------------------------------------------------------- #
# Structural violations
# --------------------------------------------------------------------------- #
def test_verdict_shaped_receipt_is_refused():
    receipt = {"git": {}, "detected": {}, "notes": [],
               "verdict": "CRITICAL", "severity": "high"}
    res = _validate("discover-repo.md", receipt)
    assert res["structurally_valid"] is False
    forbidden = {v["key"] for v in res["violations"]
                 if v["kind"] == "forbidden-key"}
    assert forbidden == {"verdict", "severity"}


def test_missing_required_key_and_wrong_type_are_caught():
    res = _validate("discover-repo.md", {"git": [], "detected": {}})
    kinds = {(v["kind"], v.get("key")) for v in res["violations"]}
    assert ("missing-required-key", "notes") in kinds
    assert ("wrong-type", "git") in kinds
    assert res["structurally_valid"] is False


def test_non_object_receipt_is_refused_not_crashed():
    for junk in ([], "x", 3, None, True):
        res = _validate("discover-repo.md", junk)
        assert res["structurally_valid"] is False
        assert any(v["kind"] == "receipt-not-object" for v in res["violations"])


def test_malformed_concept_degrades_to_parse_partial(tmp_path):
    bad = tmp_path / "broken.md"
    bad.write_text("no frontmatter here at all\n", encoding="utf-8")
    comp = attester.load_computation(str(bad))
    assert comp["parse_partial"] is True
    # validating any receipt against a partial concept fails closed, never raises
    res = attester.validate_receipt(comp, {"anything": 1})
    assert res["structurally_valid"] is False
    assert any(v["kind"] in ("concept-parse-partial", "not-facts-emitter")
               for v in res["violations"])


# --------------------------------------------------------------------------- #
# The attester is structural-only: it must NEVER emit a security verdict
# --------------------------------------------------------------------------- #
def test_attester_output_carries_no_verdict():
    receipt = discover_repo.discover(_REPO_ROOT)
    res = _validate("discover-repo.md", receipt)
    # The result is a structural fact set: exactly these keys, nothing that looks
    # like a security judgment.
    assert set(res.keys()) == {"computation_id", "structurally_valid",
                               "violations", "checked_keys"}
    for banned in ("verdict", "severity", "finding", "findings", "conclusion",
                   "remediation", "risk"):
        assert banned not in res


def test_cli_check_reads_receipt_from_stdin(capsys, monkeypatch):
    receipt = json.dumps(discover_repo.discover(_REPO_ROOT))
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(receipt))
    rc = attester.main(["check",
                        os.path.join(_COMP_DIR, "discover-repo.md"), "-"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["structurally_valid"] is True


def test_cli_check_on_non_json_never_crashes(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("}{ not json"))
    rc = attester.main(["check",
                        os.path.join(_COMP_DIR, "discover-repo.md"), "-"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["structurally_valid"] is False
    assert out["violations"][0]["kind"] == "receipt-not-json"
