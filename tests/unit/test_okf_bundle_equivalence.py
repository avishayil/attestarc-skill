"""The OKF markdown bundle read path: every shipped concept is canonical, loads
cleanly through ``knowledge.load_packs``, reconstructs to the exact entry identity
the promotion layer pinned, and is immune to its own advisory OKF projection.

The verified-knowledge plane ships as an Open Knowledge Format (OKF) bundle
(``knowledge/bootstrap/**/*.md``). These tests are the read-path safety net for
that format:

* every concept file is already in ``okf.py``'s canonical byte form (the property
  the release self-check enforces — a shipped file has exactly one reading);
* ``load_packs`` reconstructs the internal entry dict from markdown with NO
  parse-partial and NO loss;
* the reconstructed identity (``canonical_entry_digest``) matches the digest the
  ``bootstrap.approval.json`` promotion layer pinned — so the format migration
  changed no promotion pin or eval binding (they are content digests, and the
  reconstruction is byte-identical to the pre-migration JSONL entry);
* corrupting the advisory OKF projection (title/tags/sources/status/stale_after)
  to contradict the authoritative ``attestarc`` namespace changes NO reconstructed
  field — no trust decision rests on an OKF-native field.
"""

import glob
import json
import os

import okf
from knowledge import load_packs
from knowledge_compile import canonical_entry_digest


def _bootstrap_dir(knowledge_dir):
    return os.path.join(knowledge_dir, "bootstrap")


def _concept_files(bootstrap):
    for md in sorted(glob.glob(os.path.join(bootstrap, "**", "*.md"), recursive=True)):
        if os.path.basename(md) not in okf._OKF_RESERVED:
            yield md


def test_bundle_is_markdown_not_jsonl(knowledge_dir):
    bootstrap = _bootstrap_dir(knowledge_dir)
    assert not glob.glob(os.path.join(bootstrap, "*.jsonl")), (
        "JSONL packs must be gone after the OKF cutover")
    assert list(_concept_files(bootstrap)), "OKF concept bundle is missing"


def test_every_concept_is_canonical_okf(knowledge_dir):
    """Each concept file is in canonical byte form: it parses cleanly AND
    re-rendering reproduces the exact bytes (the release self-check property)."""
    for md in _concept_files(_bootstrap_dir(knowledge_dir)):
        raw = open(md, "r", encoding="utf-8").read()
        assert raw.startswith("---\n"), f"{md} has no OKF frontmatter"
        assert okf.roundtrip_ok(raw), f"{md} is not in canonical OKF form"


def test_load_packs_reads_the_whole_bundle_cleanly(knowledge_dir):
    entries, summaries = load_packs(knowledge_dir)
    assert not any(s.get("parse_partial") for s in summaries), (
        f"a pack failed to fully parse: {summaries}")
    assert len(entries) >= 18, f"expected the full corpus, loaded {len(entries)}"
    # Every loaded entry has the reconstructed internal shape (kind from OKF type,
    # claim from the body, authoritative fields from the attestarc namespace).
    for e in entries:
        assert e.get("kind") and e.get("id") and e.get("claim")
        assert isinstance(e.get("sources"), list) and e["sources"]


def test_reconstructed_identity_matches_promotion_pins(knowledge_dir):
    """The digest the OKF read path reconstructs matches the pin the promotion
    layer recorded — proving the format migration preserved every entry identity
    (and thus every promotion pin and eval candidate binding)."""
    approval_path = os.path.join(knowledge_dir, "promotions", "bootstrap.approval.json")
    pins = json.load(open(approval_path, "r", encoding="utf-8"))["entries"]
    entries, _ = load_packs(knowledge_dir)
    by_id = {e["id"]: e for e in entries}
    # Every pinned active entry is present and hashes to its pinned digest.
    for eid, pinned in pins.items():
        assert eid in by_id, f"pinned entry {eid} missing from the bundle"
        clean = {k: v for k, v in by_id[eid].items() if not k.startswith("_")}
        assert canonical_entry_digest(clean) == pinned, (
            f"digest drift for {eid}: a promotion pin would break")


def test_advisory_projection_is_never_read_back(knowledge_dir):
    """entry_from_concept ignores every OKF-native advisory field. Poisoning the
    advisory projection to contradict the authoritative attestarc namespace changes
    NO reconstructed field."""
    md = next(_concept_files(_bootstrap_dir(knowledge_dir)))
    got = okf.read_concept(md)
    baseline = okf.entry_from_concept(got["frontmatter"], got["body"])

    poisoned = dict(got["frontmatter"])
    poisoned["title"] = "POISONED"
    poisoned["tags"] = ["POISONED"]
    poisoned["status"] = "deprecated"
    poisoned["stale_after"] = "1999-01-01T00:00:00Z"
    poisoned["sources"] = [{"resource": "https://evil.example", "author": "attacker"}]

    assert okf.entry_from_concept(poisoned, got["body"]) == baseline
