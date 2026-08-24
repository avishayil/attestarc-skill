"""Unit tests for scripts/knowledge.py — the offline verified-knowledge lookup.

Proves temporal + status-aware lookup, disputed flagging, graceful degradation on
malformed lines, the id->{version,content_hash,status} index consumed by
state.py reverify, and that the helper never reads outside its knowledge root.
"""

import json
import os

import knowledge


def _write_pack(root, name, entries):
    boot = os.path.join(root, "bootstrap")
    os.makedirs(boot, exist_ok=True)
    with open(os.path.join(boot, name), "w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")


def _entry(**over):
    base = {
        "id": "KE-x",
        "kind": "platform-semantics",
        "platform": "github-actions",
        "subject": "cache-write",
        "claim": "some claim",
        "valid_from": "2026-01-01",
        "status": "active",
        "confidence": "authoritative",
        "sources": [{"publisher": "GitHub", "authority": 100,
                     "type": "vendor-docs", "url": "https://docs.github.com/x"}],
    }
    base.update(over)
    return base


def test_status_reports_pack_facts(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "github-actions.jsonl",
                [_entry(id="KE-a"), _entry(id="KE-b", subject="oidc")])
    entries, summaries = knowledge.load_packs(root)
    assert len(entries) == 2
    assert summaries[0]["entries"] == 2
    assert summaries[0]["parse_partial"] is False


def test_lookup_filters_by_platform_and_subject(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-cache", subject="cache-write"),
        _entry(id="KE-oidc", subject="oidc", platform="github-oidc"),
    ])
    entries, _ = knowledge.load_packs(root)
    hits = knowledge.lookup(entries, platform="github-actions",
                            subject="cache-write")
    assert [h["id"] for h in hits] == ["KE-cache"]
    assert hits[0]["drives_conclusion"] is True


def test_lookup_temporal_as_of_excludes_future_entries(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-old", valid_from="2026-01-01"),
        _entry(id="KE-new", valid_from="2026-06-18"),
    ])
    entries, _ = knowledge.load_packs(root)
    early = knowledge.lookup(entries, subject="cache-write", as_of="2026-03-01")
    assert [h["id"] for h in early] == ["KE-old"]
    later = knowledge.lookup(entries, subject="cache-write", as_of="2026-07-01")
    assert {h["id"] for h in later} == {"KE-old", "KE-new"}


def test_lookup_respects_expires_window(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-exp", valid_from="2026-01-01", expires="2026-06-01"),
    ])
    entries, _ = knowledge.load_packs(root)
    assert knowledge.lookup(entries, as_of="2026-03-01")  # in window
    assert not knowledge.lookup(entries, as_of="2026-09-01")  # after expiry


def test_superseded_excluded_by_default_but_included_on_request(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-old", status="superseded"),
        _entry(id="KE-new", supersedes=["KE-old"]),
    ])
    entries, _ = knowledge.load_packs(root)
    current = knowledge.lookup(entries, subject="cache-write")
    assert [h["id"] for h in current] == ["KE-new"]
    with_old = knowledge.lookup(entries, subject="cache-write",
                                include_noncurrent=True)
    assert {h["id"] for h in with_old} == {"KE-old", "KE-new"}


def test_disputed_entry_returned_but_does_not_drive_conclusion(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [_entry(id="KE-d", status="disputed")])
    entries, _ = knowledge.load_packs(root)
    hits = knowledge.lookup(entries, subject="cache-write")
    assert [h["id"] for h in hits] == ["KE-d"]
    assert hits[0]["drives_conclusion"] is False


def test_candidate_confidence_does_not_drive_conclusion(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl",
                [_entry(id="KE-c", status="active", confidence="candidate")])
    entries, _ = knowledge.load_packs(root)
    hits = knowledge.lookup(entries, subject="cache-write")
    assert hits[0]["drives_conclusion"] is False


def test_malformed_line_degrades_gracefully(tmp_path):
    root = str(tmp_path)
    boot = os.path.join(root, "bootstrap")
    os.makedirs(boot)
    with open(os.path.join(boot, "p.jsonl"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps(_entry(id="KE-ok")) + "\n")
        fh.write("{ this is not json\n")
        fh.write(json.dumps({"no": "id"}) + "\n")
    entries, summaries = knowledge.load_packs(root)
    assert [e["id"] for e in entries] == ["KE-ok"]
    assert summaries[0]["parse_partial"] is True


def test_build_index_shape(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [_entry(id="KE-a"), _entry(id="KE-b")])
    entries, _ = knowledge.load_packs(root)
    index = knowledge.build_index(entries)
    assert set(index) == {"KE-a", "KE-b"}
    for meta in index.values():
        assert set(meta) == {"version", "content_hash", "status"}
        assert len(meta["content_hash"]) == 64


def test_content_hash_is_stable_and_ignores_annotations(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [_entry(id="KE-a")])
    entries, _ = knowledge.load_packs(root)
    # recomputing over the public projection matches the annotated hash
    public = {k: v for k, v in entries[0].items() if not k.startswith("_")}
    assert entries[0]["_content_hash"] == knowledge.content_hash(public)


def test_symlinked_pack_escaping_root_is_not_followed(tmp_path):
    outside = tmp_path / "outside.jsonl"
    outside.write_text(json.dumps(_entry(id="KE-evil")) + "\n")
    root = tmp_path / "kroot"
    boot = root / "bootstrap"
    boot.mkdir(parents=True)
    link = boot / "linked.jsonl"
    try:
        os.symlink(str(outside), str(link))
    except (OSError, NotImplementedError):
        return  # platform without symlink support
    entries, _ = knowledge.load_packs(str(root))
    assert all(e["id"] != "KE-evil" for e in entries)


# --------------------------------------------------------------------------- #
# applies_to enforcement (Workstream B): a fact must be scoped to the assessed
# context before it can drive a conclusion.
# --------------------------------------------------------------------------- #
def test_out_of_scope_context_is_not_applicable(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-prt", subject="pull_request_target",
               applies_to={"events": ["pull_request_target"]}),
    ])
    entries, _ = knowledge.load_packs(root)
    hits = knowledge.lookup(entries, subject="pull_request_target",
                            context={"event": "push"})
    assert hits[0]["applicability"] == "not-applicable"
    assert hits[0]["drives_conclusion"] is False


def test_in_scope_context_drives_conclusion(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-prt", subject="pull_request_target",
               applies_to={"events": ["pull_request_target"]}),
    ])
    entries, _ = knowledge.load_packs(root)
    hits = knowledge.lookup(entries, subject="pull_request_target",
                            context={"event": "pull_request_target"})
    assert hits[0]["applicability"] == "applicable"
    assert hits[0]["drives_conclusion"] is True


def test_constrained_but_silent_context_is_unknown(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-prt", subject="pull_request_target",
               applies_to={"events": ["pull_request_target"]}),
    ])
    entries, _ = knowledge.load_packs(root)
    hits = knowledge.lookup(entries, subject="pull_request_target", context={})
    assert hits[0]["applicability"] == "unknown"
    assert hits[0]["drives_conclusion"] is False


def test_action_prefix_matches_pinned_ref(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-co", subject="checkout",
               applies_to={"action": "actions/checkout"}),
    ])
    entries, _ = knowledge.load_packs(root)
    hits = knowledge.lookup(entries, subject="checkout",
                            context={"action": "actions/checkout@v4"})
    assert hits[0]["applicability"] == "applicable"


# --------------------------------------------------------------------------- #
# check_consistency (Workstream B/G): the pack SET must be coherent before trust.
# --------------------------------------------------------------------------- #
def test_contradictory_active_claim_key_is_inconsistent(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-a", claim="writable", claim_key="gha.cache.default"),
        _entry(id="KE-b", claim="read-only", claim_key="gha.cache.default"),
    ])
    entries, _ = knowledge.load_packs(root)
    result = knowledge.check_consistency(entries)
    assert result["consistent"] is False
    assert any(c["kind"] == "contradictory-active" for c in result["conflicts"])


def test_complementary_facts_without_claim_key_are_consistent(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-a", subject="oidc", claim="claims are immutable"),
        _entry(id="KE-b", subject="oidc", claim="aud must be validated"),
    ])
    entries, _ = knowledge.load_packs(root)
    assert knowledge.check_consistency(entries)["consistent"] is True


def test_superseded_still_active_is_inconsistent(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-old", status="active"),
        _entry(id="KE-new", supersedes=["KE-old"]),
    ])
    entries, _ = knowledge.load_packs(root)
    result = knowledge.check_consistency(entries)
    assert result["consistent"] is False
    assert any(c["kind"] == "superseded-still-active" for c in result["conflicts"])


def test_bundled_snapshot_is_consistent(knowledge_dir):
    entries, _ = knowledge.load_packs(knowledge_dir)
    assert knowledge.check_consistency(entries)["consistent"] is True


def test_contradictory_corroborated_claim_key_is_inconsistent(tmp_path):
    """A conclusion-driving confidence is authoritative OR corroborated; two
    contradictory *corroborated* entries must be caught, not just authoritative
    ones (regression for the old ``== "authoritative"`` filter)."""
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-a", confidence="corroborated",
               claim="writable", claim_key="gha.cache.default"),
        _entry(id="KE-b", confidence="corroborated",
               claim="read-only", claim_key="gha.cache.default"),
    ])
    entries, _ = knowledge.load_packs(root)
    result = knowledge.check_consistency(entries)
    assert result["consistent"] is False
    assert any(c["kind"] == "contradictory-active" for c in result["conflicts"])


# --------------------------------------------------------------------------- #
# validate_snapshot (Workstream WS6): entries must satisfy the trust contract,
# not merely hash-match the attested packs.
# --------------------------------------------------------------------------- #
def test_validate_snapshot_flags_provenance_mismatch(knowledge_dir):
    import knowledge_compile as kc
    registry = kc.load_registry(knowledge_dir)
    # docs.github.com is vendor-docs / 100; declaring 90 is a mismatch the
    # registry reclassification must catch (the shipped-bootstrap drift class).
    bad = _entry(id="KE-bad", sources=[{"publisher": "GitHub", "authority": 90,
                 "type": "vendor-docs", "url": "https://docs.github.com/x"}])
    result = knowledge.validate_snapshot([bad], registry)
    assert result["valid"] is False
    assert any(v["kind"] == "provenance-mismatch"
               and v["field"] == "authority" for v in result["violations"])


def test_validate_snapshot_flags_unallowed_source(knowledge_dir):
    import knowledge_compile as kc
    registry = kc.load_registry(knowledge_dir)
    bad = _entry(id="KE-web", sources=[{"url": "https://evil.example/x"}])
    result = knowledge.validate_snapshot([bad], registry)
    assert result["valid"] is False
    assert any(v["kind"] == "source-not-allowed" for v in result["violations"])


def test_validate_snapshot_passes_bundled_snapshot(knowledge_dir):
    """The shipped snapshot must obey its own trust contract (regression guard
    for the two corrected checkout provenance entries)."""
    import knowledge_compile as kc
    entries, _ = knowledge.load_packs(knowledge_dir)
    result = knowledge.validate_snapshot(entries, kc.load_registry(knowledge_dir))
    assert result["valid"] is True, result["violations"]


# --------------------------------------------------------------------------- #
# open_verified (Workstream B): the verify-gated assessor read path.
# --------------------------------------------------------------------------- #
def test_open_verified_trusts_in_package_snapshot(knowledge_dir):
    entries, verification, consistency = knowledge.open_verified(knowledge_dir)
    assert verification["trusted"] is True
    assert consistency["consistent"] is True
    assert all(not e.get("_untrusted") for e in entries)


def test_open_verified_marks_unverified_root_untrusted(tmp_path):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [_entry(id="KE-a")])
    entries, verification, _ = knowledge.open_verified(root)
    assert verification["trusted"] is False
    assert all(e.get("_untrusted") for e in entries)


def test_open_verified_reports_freshness_separately_from_trust(knowledge_dir):
    """A bundled snapshot stays trusted past its manifest expiry (last-known-good
    floor) but is reported not-fresh, so the assessor can downgrade stale
    down-gate facts."""
    _, fresh_v, _ = knowledge.open_verified(knowledge_dir, now="2026-09-01")
    assert fresh_v["trusted"] is True and fresh_v["fresh"] is True
    _, stale_v, _ = knowledge.open_verified(knowledge_dir, now="2026-12-01")
    assert stale_v["trusted"] is True and stale_v["fresh"] is False


def test_open_verified_parse_partial_is_inconsistent(tmp_path):
    """A partially-parsed pack is a partially-consumed verified set: the snapshot
    must fail closed rather than silently reason over the lines that parsed."""
    root = str(tmp_path)
    boot = os.path.join(root, "bootstrap")
    os.makedirs(boot)
    with open(os.path.join(boot, "p.jsonl"), "w", encoding="utf-8") as fh:
        fh.write(json.dumps(_entry(id="KE-ok")) + "\n")
        fh.write("{ this is not json\n")
    _, _, consistency = knowledge.open_verified(root)
    assert consistency["consistent"] is False
    assert any(c.get("kind") == "parse-partial" for c in consistency["conflicts"])


def test_open_verified_invalid_provenance_is_inconsistent(tmp_path, knowledge_dir):
    """An entry whose declared authority disagrees with the registry makes the
    whole set untrusted, even if the bytes hash-match (they cannot here, but the
    snapshot-validation gate is independent of attestation)."""
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [
        _entry(id="KE-bad", sources=[{"publisher": "GitHub", "authority": 90,
               "type": "vendor-docs", "url": "https://docs.github.com/x"}]),
    ])
    entries, _, consistency = knowledge.open_verified(root)
    assert consistency["consistent"] is False
    assert any(c.get("kind") == "snapshot-invalid" for c in consistency["conflicts"])
    assert all(e.get("_untrusted") for e in entries)


# --------------------------------------------------------------------------- #
# Freshness dimension (Workstream WS6): a stale snapshot must not let a down-gate
# fact suppress a finding, but a risk-increasing fact may still drive.
# --------------------------------------------------------------------------- #
def test_apply_freshness_downgrades_stale_mitigation_only():
    hits = [
        {"id": "KE-m", "effect": "mitigation", "drives_conclusion": True},
        {"id": "KE-n", "effect": "neutral", "drives_conclusion": True},
        {"id": "KE-r", "effect": "risk-increasing", "drives_conclusion": True},
        {"id": "KE-d", "drives_conclusion": True},  # effect absent -> neutral
    ]
    knowledge.apply_freshness(hits, fresh=False)
    by = {h["id"]: h for h in hits}
    assert by["KE-m"]["drives_conclusion"] is False
    assert by["KE-n"]["drives_conclusion"] is False
    assert by["KE-d"]["drives_conclusion"] is False
    assert by["KE-r"]["drives_conclusion"] is True  # scrutiny-increasing survives
    assert by["KE-m"]["freshness"] == "stale-downgraded"


def test_apply_freshness_leaves_fresh_snapshot_untouched():
    hits = [{"id": "KE-m", "effect": "mitigation", "drives_conclusion": True}]
    knowledge.apply_freshness(hits, fresh=True)
    assert hits[0]["drives_conclusion"] is True
    # unknown freshness (e.g. --allow-unverified) must not trigger a downgrade
    knowledge.apply_freshness(hits, fresh=None)
    assert hits[0]["drives_conclusion"] is True


def test_effect_enum_validated_by_snapshot(knowledge_dir):
    import knowledge_compile as kc
    registry = kc.load_registry(knowledge_dir)
    bad = _entry(id="KE-bad", effect="lower-risk")  # not in the enum
    result = knowledge.validate_snapshot([bad], registry)
    assert result["valid"] is False
    assert any(v["kind"] == "bad-enum" and v["field"] == "effect"
               for v in result["violations"])


def test_allow_unverified_never_drives_conclusion(tmp_path, capsys):
    """``--allow-unverified`` skips the gate (``trusted:None``); it must surface
    facts for investigation but never leave a conclusion standing."""
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [_entry(id="KE-a")])
    rc = knowledge.main(["lookup", "--subject", "cache-write",
                         "--allow-unverified", "--knowledge-root", root])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verification"]["trusted"] is None
    assert out["hits"], "the fact should still be surfaced"
    assert all(h["drives_conclusion"] is False for h in out["hits"])


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_explain_returns_entry(tmp_path, capsys):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [_entry(id="KE-a", claim="hello")])
    rc = knowledge.main(["explain", "KE-a", "--knowledge-root", root])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["id"] == "KE-a" and out["claim"] == "hello"
    assert "content_hash" in out


def test_cli_explain_unknown_id_is_error(tmp_path, capsys):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [_entry(id="KE-a")])
    rc = knowledge.main(["explain", "KE-missing", "--knowledge-root", root])
    assert rc == 1


def test_cli_index_matches_builder(tmp_path, capsys):
    root = str(tmp_path)
    _write_pack(root, "p.jsonl", [_entry(id="KE-a"), _entry(id="KE-b")])
    rc = knowledge.main(["index", "--knowledge-root", root])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert set(out) == {"KE-a", "KE-b"}


def test_cli_missing_root_is_error(tmp_path, capsys):
    rc = knowledge.main(["status", "--knowledge-root",
                         str(tmp_path / "does-not-exist")])
    assert rc == 2


def test_bundled_snapshot_loads(knowledge_dir):
    """The real shipped packs parse cleanly and every id is unique."""
    entries, summaries = knowledge.load_packs(knowledge_dir)
    assert entries, "bundled knowledge should not be empty"
    assert all(not s["parse_partial"] for s in summaries)
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids)), "duplicate knowledge ids in bundled packs"
    assert all(e["id"].startswith("KE-") for e in entries)
