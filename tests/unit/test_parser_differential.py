"""Differential assurance for the hand-written block-YAML workflow parser.

The shipped skill is stdlib-only, so ``inspect_workflows`` includes its own
conservative YAML-subset parser instead of depending on PyYAML. This test is a
DEV-ONLY cross-check: when PyYAML is installed (``pip install .[dev]``) it parses
the same corpus with a real YAML implementation and asserts the two parsers
agree on the *security-relevant facts* AttestArc actually reads — triggers,
top-level permissions, and each job's action references and pin state.

Only the parser is under test: both trees are run through the very same
``inspect_workflows`` classifier helpers, so any disagreement is a parser bug,
not a classifier difference. The test skips cleanly when PyYAML is absent, and
no shipped helper ever imports it.
"""

import os

import pytest

import inspect_workflows as iw

yaml = pytest.importorskip("yaml", reason="PyYAML is a dev-only differential aid")


# Workflows that live within the block-YAML subset the hand parser targets.
_CORPUS = [
    # simple push CI, pinned action
    "name: CI\n"
    "on:\n  push:\n    branches: [main, dev]\n"
    "permissions:\n  contents: read\n"
    "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
    "      - run: make\n",
    # privileged trigger, write perms, mutable + docker refs
    "on:\n  pull_request_target:\n"
    "permissions:\n  contents: write\n  id-token: write\n"
    "jobs:\n  a:\n    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: third-party/example@v1\n"
    "      - uses: docker://alpine:3.19\n"
    "      - run: echo hi\n",
    # list-form triggers
    "on: [push, pull_request]\n"
    "jobs:\n  t:\n    runs-on: ubuntu-latest\n"
    "    steps:\n      - uses: actions/setup-node@v4\n",
    # scalar trigger
    "on: push\n"
    "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n",
    # write-all string permissions
    "on: push\npermissions: write-all\n"
    "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n",
    # leading document-start marker (must not be read as a sequence item)
    "---\n"
    "name: CI\non: [push]\n"
    "permissions:\n  contents: read\n"
    "jobs:\n  build:\n    runs-on: ubuntu-latest\n"
    "    steps:\n      - uses: actions/checkout@v4\n      - run: pytest\n",
    # block sequence indented at the SAME column as its ``steps:`` key
    "name: CI\non:\n  push:\n    branches: [main]\n"
    "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "    - uses: actions/checkout@v4\n"
    "    - uses: actions/cache@v4\n"
    "    - run: pytest -q\n",
]


def _on_value(data):
    # PyYAML coerces the bare key ``on`` to the boolean True (YAML 1.1).
    if isinstance(data, dict):
        if "on" in data:
            return data["on"]
        if True in data:
            return data[True]
    return None


def _facts_from_pyyaml(text):
    data = yaml.safe_load(text)
    triggers = set(iw._triggers(_on_value(data)))
    perms = iw._norm_permissions(data.get("permissions"))
    jobs = {}
    for jname, jdef in (data.get("jobs") or {}).items():
        refs = []
        for step in (jdef.get("steps") or []):
            uses = step.get("uses") if isinstance(step, dict) else None
            if isinstance(uses, str):
                a = iw._classify_action(uses)
                refs.append((a["name"], a["pinned"], a["kind"]))
        jobs[str(jname)] = refs
    return triggers, perms, jobs


def _facts_from_ours(text):
    wf = iw.inspect_workflow_text(text, "x.yml")
    triggers = set(wf["triggers"])
    perms = wf["permissions"]
    jobs = {
        j["id"]: [(a["name"], a["pinned"], a["kind"]) for a in j["actions"]]
        for j in wf["jobs"]
    }
    return triggers, perms, jobs, wf["parse_partial"]


@pytest.mark.parametrize("text", _CORPUS, ids=range(len(_CORPUS)))
def test_hand_parser_agrees_with_pyyaml_on_facts(text):
    ours_triggers, ours_perms, ours_jobs, partial = _facts_from_ours(text)
    assert partial is False, "corpus entry must parse fully for a fair compare"
    ref_triggers, ref_perms, ref_jobs = _facts_from_pyyaml(text)
    assert ours_triggers == ref_triggers
    assert ours_perms == ref_perms
    assert ours_jobs == ref_jobs


def _iter_fixture_workflows(fixtures_dir):
    for name in sorted(os.listdir(fixtures_dir)):
        root = os.path.join(fixtures_dir, name)
        if not os.path.isdir(root):
            continue
        for rel in iw._iter_workflow_files(root):
            yield name, os.path.join(root, rel)


def test_fixture_workflows_match_pyyaml_facts(fixtures_dir):
    compared = 0
    for name, full in _iter_fixture_workflows(fixtures_dir):
        with open(full, "r", encoding="utf-8") as fh:
            text = fh.read()
        ours_triggers, ours_perms, ours_jobs, partial = _facts_from_ours(text)
        if partial:
            continue  # partial parse is an explicit "uncertain"; not comparable
        try:
            ref_triggers, ref_perms, ref_jobs = _facts_from_pyyaml(text)
        except yaml.YAMLError:
            continue  # not valid full YAML; the subset parser may still cope
        assert ours_triggers == ref_triggers, f"{name}: triggers differ"
        assert ours_perms == ref_perms, f"{name}: permissions differ"
        assert ours_jobs == ref_jobs, f"{name}: action refs differ"
        compared += 1
    assert compared > 0, "expected to compare at least one fixture workflow"
