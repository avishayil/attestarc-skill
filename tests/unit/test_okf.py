"""Unit tests for the OKF concept subset reader/writer (``scripts/okf.py``).

Covers the canonical normal form, the round-trip fixpoint the release pipeline
relies on, graceful ``parse_partial`` degradation (never raises on bad input),
and a dev-only differential cross-check that PyYAML reads our canonical output to
the same structure (mirroring ``test_parser_differential`` for the workflow
parser).
"""

import pytest

import okf


# --------------------------------------------------------------------------- #
# Round-trip fixpoint: dump -> parse -> dump is stable, and parse inverts dump.
# --------------------------------------------------------------------------- #
_OBJECTS = [
    {},
    {"a": "x"},
    {"n": 42, "neg": -7, "t": True, "f": False, "nil": None},
    {"empty_map": {}, "empty_list": []},
    {"tags": ["analytics", "ga4", "sharded-tables"]},
    {"nested": {"product": "github.com", "events": ["pull_request", "push"]}},
    {"sources": [{"author": "GitHub", "resource": "https://docs.github.com/x"},
                 {"author": "SLSA", "resource": "https://slsa.dev/spec"}]},
    {"deep": {"a": {"b": {"c": [1, 2, 3]}}}},
    {"seq_of_seq": [[1, 2], [3, 4]]},
    # strings that must survive quoting
    {"weird": 'he said "hi"\nand\tleft', "back": "a\\b", "colon": "https://x:8080/y"},
    # a realistic verified-entry-shaped frontmatter
    {"type": "platform-semantics",
     "title": "Fork PR token default",
     "sources": [{"author": "GitHub", "resource": "https://docs.github.com/a"}],
     "attestarc": {
         "id": "KE-gha-forkpr-token-default",
         "platform": "github-actions",
         "subject": "fork-pr-permissions",
         "claim_key": "gha.pull_request_target.fork_token_default",
         "applies_to": {"product": "github.com", "events": ["pull_request"]},
         "valid_from": "2023-01-01",
         "status": "active",
         "confidence": "authoritative",
         "effect": "mitigation",
         "sources": [{"url": "https://docs.github.com/a", "type": "vendor-docs",
                      "authority": 100, "retrieved_at": "2026-08-24"}],
         "last_verified": "2026-08-24"}},
]


@pytest.mark.parametrize("obj", _OBJECTS, ids=range(len(_OBJECTS)))
def test_parse_inverts_dump(obj):
    text = okf.dump_frontmatter(obj)
    assert okf.parse_frontmatter(text) == obj


@pytest.mark.parametrize("obj", _OBJECTS, ids=range(len(_OBJECTS)))
def test_dump_is_idempotent_through_parse(obj):
    once = okf.dump_frontmatter(obj)
    assert okf.dump_frontmatter(okf.parse_frontmatter(once)) == once


def test_dump_sorts_keys_and_indents_by_two():
    obj = {"b": 1, "a": {"y": 2, "x": 3}}
    assert okf.dump_frontmatter(obj) == 'a:\n  x: 3\n  y: 2\nb: 1'


def test_sequence_of_maps_uses_bare_dash_block():
    obj = {"sources": [{"resource": "https://x", "author": "GitHub"}]}
    assert okf.dump_frontmatter(obj) == (
        'sources:\n  -\n    author: "GitHub"\n    resource: "https://x"')


def test_strings_always_quoted_scalars_not():
    obj = {"s": "true", "b": True, "n": 5, "z": "5"}
    text = okf.dump_frontmatter(obj)
    assert 'b: true' in text
    assert 'n: 5' in text
    assert 's: "true"' in text   # the *string* "true" stays quoted, distinct from bool
    assert 'z: "5"' in text      # the *string* "5" stays quoted, distinct from int


# --------------------------------------------------------------------------- #
# Concept files: frontmatter + body, exact body preservation, roundtrip_ok.
# --------------------------------------------------------------------------- #
def test_render_read_roundtrip_and_body_preserved():
    fm = {"type": "guidance", "attestarc": {"id": "KE-x-y"}}
    body = "The claim prose.\n\nWith a second paragraph and no trailing newline"
    raw = okf.render_concept(fm, body)
    got = okf.read_concept(raw, is_path=False)
    assert got["_parse_partial"] is False
    assert got["frontmatter"] == fm
    assert got["body"] == body
    assert okf.roundtrip_ok(raw) is True


def test_body_with_trailing_newline_preserved():
    raw = okf.render_concept({"type": "api"}, "line one\nline two\n")
    got = okf.read_concept(raw, is_path=False)
    assert got["body"] == "line one\nline two\n"
    assert okf.roundtrip_ok(raw) is True


def test_body_may_contain_yaml_fence_lines():
    # A '---' inside the body must not be mistaken for the closing fence: only the
    # first '\n---\n' after the opening fence closes frontmatter.
    fm = {"type": "standard"}
    body = "# Heading\n\n---\n\nmore prose"
    raw = okf.render_concept(fm, body)
    got = okf.read_concept(raw, is_path=False)
    assert got["frontmatter"] == fm
    assert got["body"] == body


def test_write_and_read_file(tmp_path):
    fm = {"type": "platform-semantics", "attestarc": {"id": "KE-a-b"}}
    body = "claim text"
    path = tmp_path / "concept.md"
    okf.write_concept(str(path), fm, body)
    got = okf.read_concept(str(path))
    assert got["frontmatter"] == fm
    assert got["body"] == body
    assert okf.roundtrip_ok(path.read_text(encoding="utf-8")) is True


# --------------------------------------------------------------------------- #
# Fail-closed: the reader never raises; malformed input degrades to parse_partial.
# --------------------------------------------------------------------------- #
_MALFORMED = [
    "key:\tvalue",                       # tab
    "key: value\n   bad: indent",        # odd indentation (3 spaces)
    'k: "unterminated',                  # malformed quoted string
    "- just\n- a\n- sequence",           # top level not a mapping
    "a: 1\n    b: 2",                    # misindented nested block
    "novalue",                           # no colon
    "dup: 1\ndup: 2",                    # duplicate key
    "k:\n  -",                           # bare dash without an item block
]


@pytest.mark.parametrize("text", _MALFORMED, ids=range(len(_MALFORMED)))
def test_parse_frontmatter_degrades_never_raises(text):
    result = okf.parse_frontmatter(text)
    assert result.get("_parse_partial") is True
    assert "_raw" in result


def test_read_concept_no_frontmatter_is_partial():
    got = okf.read_concept("no fences here\njust text", is_path=False)
    assert got["_parse_partial"] is True
    assert got["body"] == "no fences here\njust text"


def test_read_concept_unterminated_frontmatter_is_partial():
    got = okf.read_concept("---\ntype: api\nno closing fence", is_path=False)
    assert got["_parse_partial"] is True


def test_read_missing_file_degrades(tmp_path):
    got = okf.read_concept(str(tmp_path / "nope.md"))
    assert got["_parse_partial"] is True
    assert got["frontmatter"] == {}


def test_roundtrip_ok_false_for_noncanonical():
    # Extra blank line + single-space indent: parses (tolerantly) but is NOT the
    # canonical byte form, so the release self-check must reject it.
    assert okf.roundtrip_ok('---\ntype:  "api"\n---\nbody') is False


# --------------------------------------------------------------------------- #
# Writer surfaces programming errors (it is compile/dev-side, not the read path).
# --------------------------------------------------------------------------- #
def test_dump_rejects_unserializable_value():
    with pytest.raises(okf.OKFError):
        okf.dump_frontmatter({"f": 1.5})            # float: not in the subset


def test_dump_rejects_bad_key():
    with pytest.raises(okf.OKFError):
        okf.dump_frontmatter({"bad key": 1})        # space in key


# --------------------------------------------------------------------------- #
# Differential: PyYAML reads our canonical output to the same structure.
# Dev-only aid; skips cleanly when PyYAML is absent (no shipped helper imports it).
# --------------------------------------------------------------------------- #
def test_pyyaml_agrees_with_our_canonical_form():
    yaml = pytest.importorskip("yaml", reason="PyYAML is a dev-only differential aid")
    for obj in _OBJECTS:
        text = okf.dump_frontmatter(obj)
        if not text:
            continue
        assert yaml.safe_load(text) == obj, f"PyYAML disagreed on {obj!r}"
