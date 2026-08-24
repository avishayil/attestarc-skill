"""Unit tests for scripts/knowledge_compile.py — the Updater's deterministic steps.

Proves: registry-derived authority (never model-chosen), the HTTPS + origin +
org/repo path-scoped fetch allowlist, the candidate/verified schema split (the
model never declares status/confidence/authority), self-verifying quarantine
receipts + mandatory provenance binding, redirect provenance + URL normalization,
contradiction + semantic-diff detection against an immutable baseline, the derived
security direction, and the derived promotion-tier policy from
core/promotion-policy.md.
"""

import json
import os

import knowledge_compile as kc


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _candidate(**over):
    """A minimal, well-formed *candidate* (no status/confidence, no per-source
    authority). Its single source points at an allowlisted origin; bind it to a
    receipt with ``_bound`` when a validation/promotion path is exercised."""
    base = {
        "id": "KE-test-x", "kind": "platform-semantics",
        "platform": "github-actions", "subject": "cache-write",
        "claim": "cache writes are ref-scoped", "valid_from": "2026-06-26",
        "sources": [{"url": "https://docs.github.com/x"}],
    }
    base.update(over)
    return base


def _quarantine(tmp_path, reg, body="doc body",
                url="https://docs.github.com/x", **kw):
    out = str(tmp_path / "q")
    rec = kc.quarantine(body, url, out, reg, "2026-08-24T00:00:00Z", **kw)
    return out, rec


def _bound(rec, url="https://docs.github.com/x", **over):
    """A candidate whose source is bound to a quarantine receipt id."""
    return _candidate(sources=[{"url": url, "receipt_id": rec["receipt_id"]}],
                      **over)


def _facts(**over):
    base = {"eval_result": {"passed": True}, "signature_valid": True,
            "change_paths": [], "removed_or_modified_evals": []}
    base.update(over)
    return base


_OK = {"valid": True, "errors": [], "warnings": [], "max_authority": 100,
       "receipts": {}}


# --------------------------------------------------------------------------- #
# registry + source classification
# --------------------------------------------------------------------------- #
def test_registry_parses_tiers_and_allowlist(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    assert reg["tiers"]["vendor-docs"] == 100
    assert reg["tiers"]["arbitrary-web"] == 0
    origins = {r["origin"] for r in reg["allowlist"]}
    assert "https://docs.github.com" in origins
    assert all({"origin", "publisher", "type"} <= set(r) for r in reg["allowlist"])
    gh = next(r for r in reg["allowlist"] if r["origin"] == "https://github.com")
    assert gh["path_prefixes"] == ["/actions/", "/github/"]


def test_allowlisted_origin_gets_registry_authority(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    fact = kc.classify_source("https://docs.github.com/en/actions", reg)
    assert fact["allowed"] is True
    assert fact["authority"] == 100
    assert fact["type"] == "vendor-docs"


def test_unlisted_origin_is_arbitrary_web(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    fact = kc.classify_source("https://evil.example.com/poison", reg)
    assert fact["allowed"] is False
    assert fact["authority"] == 0
    assert fact["type"] == "arbitrary-web"


def test_subdomain_not_implicitly_trusted(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    fact = kc.classify_source("https://attacker.github.io/x", reg)
    assert fact["allowed"] is False


def test_http_scheme_rejected(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    fact = kc.classify_source("http://docs.github.com/x", reg)
    assert fact["allowed"] is False
    assert "non-https" in fact["reason"]


def test_trusted_repo_org_is_vendor_repo(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    fact = kc.classify_source(
        "https://github.com/actions/checkout/blob/main/action.yml", reg)
    assert fact["allowed"] is True
    assert fact["type"] == "vendor-repo"
    assert fact["authority"] == 90


def test_attacker_repo_on_same_host_is_not_vendor_repo(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    fact = kc.classify_source("https://github.com/attacker/evil/blob/main/x", reg)
    assert fact["allowed"] is False
    assert fact["authority"] == 0


def test_dot_segment_traversal_out_of_trusted_prefix_rejected(knowledge_dir):
    """/actions/../attacker/evil normalizes to /attacker/evil and fails the
    trusted-prefix test — a candidate cannot smuggle a trusted org prefix."""
    reg = kc.load_registry(knowledge_dir)
    fact = kc.classify_source(
        "https://github.com/actions/../attacker/evil", reg)
    assert fact["allowed"] is False
    assert fact["authority"] == 0


# --------------------------------------------------------------------------- #
# candidate/verified split — validate-candidate
# --------------------------------------------------------------------------- #
def test_valid_candidate_passes(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    result = kc.validate_candidate(_bound(rec), reg, quarantine_dir=out)
    assert result["valid"] is True, result["errors"]
    assert result["errors"] == []


def test_candidate_declaring_status_is_structural_error(tmp_path, knowledge_dir):
    """status/confidence are ASSIGNED by promotion; a candidate carrying either
    is rejected — the model never declares trusted fields."""
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    for field in ("status", "confidence"):
        cand = _bound(rec, **{field: "active" if field == "status"
                              else "authoritative"})
        result = kc.validate_candidate(cand, reg, quarantine_dir=out)
        assert result["valid"] is False
        assert any("assigned by promotion" in e for e in result["errors"]), field


def test_model_chosen_authority_is_rejected(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    cand = _candidate(sources=[{"url": "https://docs.github.com/x",
                                "receipt_id": rec["receipt_id"],
                                "authority": 55}])
    result = kc.validate_candidate(cand, reg, quarantine_dir=out)
    assert result["valid"] is False
    assert any("never model-chosen" in e for e in result["errors"])


def test_candidate_lying_about_vendor_docs_is_reclassified(knowledge_dir):
    """A candidate that labels an attacker URL 'vendor-docs' is caught by
    reclassifying the URL — the registry, not the model, decides authority."""
    reg = kc.load_registry(knowledge_dir)
    cand = _candidate(sources=[{"type": "vendor-docs",
                                "url": "https://evil.example.com/fake-docs"}])
    result = kc.validate_candidate(cand, reg)
    assert result["valid"] is False
    assert any("arbitrary-web" in e for e in result["errors"])
    assert result["max_authority"] == 0


def test_promotion_eligible_source_needs_a_receipt(knowledge_dir):
    """An allowlisted origin with no receipt_id (inline hash only) is rejected:
    the fetched, self-verified object is mandatory for a promotion-eligible URL."""
    reg = kc.load_registry(knowledge_dir)
    cand = _candidate(sources=[{"url": "https://docs.github.com/x",
                                "content_hash": "a" * 64,
                                "retrieved_at": "2026-08-24T00:00:00Z"}])
    result = kc.validate_candidate(cand, reg)
    assert result["valid"] is False
    assert any("resolvable receipt_id" in e for e in result["errors"])


def test_unknown_field_rejected(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    cand = _bound(rec, verdict="critical")  # not a candidate-schema field
    result = kc.validate_candidate(cand, reg, quarantine_dir=out)
    assert result["valid"] is False
    assert any("unknown fields" in e for e in result["errors"])


def test_bad_enum_rejected(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    result = kc.validate_candidate(_bound(rec, kind="totally-fine"), reg,
                                   quarantine_dir=out)
    assert result["valid"] is False


def test_secret_in_candidate_rejected(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    cand = _bound(rec, claim="use token ghp_" + "a" * 36)
    result = kc.validate_candidate(cand, reg, quarantine_dir=out)
    assert result["valid"] is False
    assert any("secret" in e for e in result["errors"])


def test_missing_required_field_rejected(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    cand = _bound(rec)
    del cand["claim"]
    result = kc.validate_candidate(cand, reg, quarantine_dir=out)
    assert result["valid"] is False
    assert any("claim" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# quarantine receipts — self-verifying, full-hash ids, redirect provenance
# --------------------------------------------------------------------------- #
def test_quarantine_emits_full_hash_receipt(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg, body="hello world")
    assert rec["allowed"] is True
    assert rec["authority"] == 100 and rec["source_type"] == "vendor-docs"
    # full sha256, not a truncated prefix
    assert rec["receipt_id"] == "QR-" + rec["content_hash"]
    assert len(rec["content_hash"]) == 64
    assert os.path.exists(rec["stored_path"])
    assert os.path.exists(rec["receipt_path"])
    assert rec["requested_url"] == rec["final_url"]
    assert rec["redirect_chain"] == []
    resolved = kc.resolve_receipt(rec["receipt_id"], out, reg)
    assert resolved["content_hash"] == rec["content_hash"]


def test_receipt_with_tampered_raw_does_not_resolve(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg, body="original")
    # Tamper with the stored bytes so they no longer rehash to the receipt hash.
    with open(rec["stored_path"], "w", encoding="utf-8") as fh:
        fh.write("swapped-out payload")
    assert kc.resolve_receipt(rec["receipt_id"], out, reg) is None


def test_receipt_with_missing_raw_does_not_resolve(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    os.remove(rec["stored_path"])
    assert kc.resolve_receipt(rec["receipt_id"], out, reg) is None


def test_cross_origin_redirect_is_not_trusted(tmp_path, knowledge_dir):
    """An allowlisted final URL reached via a redirect that crosses origin is
    stored but marked not-allowed, so it can never back a promotion."""
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(
        tmp_path, reg, url="https://docs.github.com/x",
        requested_url="https://evil.example.com/x",
        redirect_chain=["https://evil.example.com/x"])
    assert rec["allowed"] is False
    assert "cross-origin" in rec["reason"]
    assert rec["authority"] == 0
    # and a candidate bound to it fails validation (not promotion-eligible object)
    cand = _bound(rec)
    result = kc.validate_candidate(cand, reg, quarantine_dir=out)
    assert result["valid"] is False


def test_candidate_bound_by_receipt_id_passes(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    result = kc.validate_candidate(_bound(rec), reg, quarantine_dir=out)
    assert result["valid"] is True, result["errors"]


def test_candidate_with_unresolvable_receipt_rejected(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _candidate(sources=[{"url": "https://docs.github.com/x",
                                "receipt_id": "QR-does-not-exist"}])
    result = kc.validate_candidate(cand, reg, quarantine_dir=str(tmp_path / "q"))
    assert result["valid"] is False
    assert any("does not resolve" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# conflict + semantic diff (against an immutable baseline)
# --------------------------------------------------------------------------- #
def test_conflict_detected_on_contradicting_claim():
    existing = [{"id": "KE-a", "platform": "p", "subject": "s",
                 "status": "active", "confidence": "authoritative",
                 "claim": "original"}]
    cand = {"platform": "p", "subject": "s", "claim": "different"}
    result = kc.find_conflicts(cand, existing)
    assert result["has_conflict"] is True
    assert result["conflicts"][0]["id"] == "KE-a"


def test_supersedes_is_not_a_conflict():
    existing = [{"id": "KE-a", "platform": "p", "subject": "s",
                 "status": "active", "confidence": "authoritative",
                 "claim": "original"}]
    cand = {"platform": "p", "subject": "s", "claim": "new",
            "supersedes": ["KE-a"]}
    assert kc.find_conflicts(cand, existing)["has_conflict"] is False


def test_same_claim_is_not_a_conflict():
    existing = [{"id": "KE-a", "platform": "p", "subject": "s",
                 "status": "active", "confidence": "authoritative",
                 "claim": "same"}]
    cand = {"platform": "p", "subject": "s", "claim": "same"}
    assert kc.find_conflicts(cand, existing)["has_conflict"] is False


def test_semantic_diff_new_id_is_added():
    diff = kc.semantic_diff(_candidate(), [])
    assert diff["change"] == "added"
    assert diff["modifies_active_security"] is False


def test_semantic_diff_same_id_changed_claim_is_modified_active():
    baseline = [{"id": "KE-test-x", "platform": "github-actions",
                 "subject": "cache-write", "status": "active",
                 "confidence": "authoritative", "claim": "old claim"}]
    diff = kc.semantic_diff(_candidate(claim="new, different claim"), baseline)
    assert diff["change"] == "modified"
    assert "claim" in diff["changed_fields"]
    assert diff["modifies_active_security"] is True


def test_semantic_diff_superseding_active_flags_security():
    baseline = [{"id": "KE-old", "platform": "p", "subject": "s",
                 "status": "active", "confidence": "authoritative",
                 "claim": "x"}]
    diff = kc.semantic_diff(_candidate(supersedes=["KE-old"]), baseline)
    assert diff["superseded_active"] == ["KE-old"]
    assert diff["modifies_active_security"] is True


# --------------------------------------------------------------------------- #
# derived security direction (never model-declared)
# --------------------------------------------------------------------------- #
def test_new_mitigation_is_security_negative():
    diff = kc.semantic_diff(_candidate(effect="mitigation"), [])
    d = kc.derive_direction(_candidate(effect="mitigation"), diff)
    assert d["direction"] == "negative"
    assert d["security_negative"] is True


def test_new_risk_increasing_is_positive():
    diff = kc.semantic_diff(_candidate(effect="risk-increasing"), [])
    d = kc.derive_direction(_candidate(effect="risk-increasing"), diff)
    assert d["direction"] == "positive"
    assert d["security_negative"] is False


def test_flipping_active_risk_toward_mitigation_is_negative():
    baseline = [{"id": "KE-test-x", "platform": "github-actions",
                 "subject": "cache-write", "status": "active",
                 "confidence": "authoritative", "claim": "old",
                 "effect": "risk-increasing"}]
    cand = _candidate(claim="now safe", effect="mitigation")
    d = kc.derive_direction(cand, kc.semantic_diff(cand, baseline))
    assert d["direction"] == "negative"


# --------------------------------------------------------------------------- #
# may-promote — the deterministic policy (facts DERIVED, not asserted)
# --------------------------------------------------------------------------- #
def test_clean_authoritative_new_knowledge_auto_promotes(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(_candidate(), _facts(), registry=reg,
                            baseline_entries=[], validation=_OK)
    assert result["tier"] == "auto-promote", result["reasons"]


def test_may_promote_refuses_unvalidated_candidate(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    bad = {"valid": False, "errors": ["boom"]}
    result = kc.may_promote(_candidate(), _facts(), registry=reg,
                            baseline_entries=[], validation=bad)
    assert result["tier"] == "never-auto"
    assert result["derived"]["validated"] is False


def test_superseding_change_requires_review(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _candidate(supersedes=["KE-old"])
    result = kc.may_promote(cand, _facts(), registry=reg, baseline_entries=[],
                            validation=_OK)
    assert result["tier"] == "require-review"


def test_additive_edit_of_active_entry_requires_review(knowledge_dir):
    """An additive edit of an active entry (same id, changed claim) routes to
    review even without 'supersedes' — closes the additive-edit dodge."""
    reg = kc.load_registry(knowledge_dir)
    baseline = [{"id": "KE-test-x", "platform": "github-actions",
                 "subject": "cache-write", "status": "active",
                 "confidence": "authoritative", "claim": "the old claim"}]
    cand = _candidate(claim="a materially different claim")  # no supersedes
    result = kc.may_promote(cand, _facts(), registry=reg,
                            baseline_entries=baseline, validation=_OK)
    assert result["tier"] == "require-review"
    assert result["derived"]["modifies_active_security"] is True


def test_security_negative_direction_requires_review(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _candidate(effect="mitigation")
    result = kc.may_promote(cand, _facts(), registry=reg, baseline_entries=[],
                            validation=_OK)
    assert result["tier"] == "require-review"
    assert result["derived"]["direction"] == "negative"


def test_conflict_requires_review(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    baseline = [{"id": "KE-a", "platform": "github-actions",
                 "subject": "cache-write", "status": "active",
                 "confidence": "authoritative", "claim": "something else"}]
    result = kc.may_promote(_candidate(), _facts(), registry=reg,
                            baseline_entries=baseline, validation=_OK)
    assert result["tier"] == "require-review"


def test_missing_eval_result_blocks_auto_promote(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(_candidate(), _facts(eval_result=None),
                            registry=reg, baseline_entries=[], validation=_OK)
    assert result["tier"] == "require-review"


def test_failing_eval_result_blocks_auto_promote(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(_candidate(), _facts(eval_result={"passed": False}),
                            registry=reg, baseline_entries=[], validation=_OK)
    assert result["tier"] == "require-review"


def test_failed_published_signature_blocks_auto_promote(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(_candidate(), _facts(signature_valid=False),
                            registry=reg, baseline_entries=[], validation=_OK)
    assert result["tier"] == "require-review"


def test_absent_signature_never_reads_as_valid_and_does_not_block(knowledge_dir):
    """signature_valid=None means 'not attested yet' — it must NOT block content
    promotion (the attestation is applied at release, verified at runtime)."""
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(_candidate(), _facts(signature_valid=None),
                            registry=reg, baseline_entries=[], validation=_OK)
    assert result["tier"] == "auto-promote", result["reasons"]


def test_low_authority_source_is_never_auto(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _candidate(sources=[{"url": "https://randomblog.example/x"}])
    result = kc.may_promote(cand, _facts(), registry=reg, baseline_entries=[],
                            validation=_OK)
    assert result["tier"] == "never-auto"


def test_root_of_trust_change_is_two_party(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(_candidate(),
                            _facts(change_paths=["knowledge/sources.yaml"]),
                            registry=reg, baseline_entries=[], validation=_OK)
    assert result["tier"] == "two-party-review"


def test_eval_weakening_is_two_party(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(
        _candidate(),
        _facts(removed_or_modified_evals=["evals/cases/known-good.md"]),
        registry=reg, baseline_entries=[], validation=_OK)
    assert result["tier"] == "two-party-review"


def test_most_severe_tier_wins(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _candidate(supersedes=["KE-old"])
    result = kc.may_promote(
        cand, _facts(change_paths=["scripts/knowledge_verify.py"]),
        registry=reg, baseline_entries=[], validation=_OK)
    assert result["tier"] == "two-party-review"


# --------------------------------------------------------------------------- #
# promote_to_verified — assigns the trusted fields the model may never declare
# --------------------------------------------------------------------------- #
def test_promote_assigns_status_and_authoritative_confidence(tmp_path,
                                                             knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    cand = _bound(rec)
    validation = kc.validate_candidate(cand, reg, quarantine_dir=out)
    assert validation["valid"], validation["errors"]
    verified = kc.promote_to_verified(cand, validation, reg)
    assert verified["status"] == "active"
    assert verified["confidence"] == "authoritative"  # single high-authority origin
    src = verified["sources"][0]
    assert src["publisher"] == "GitHub"
    assert src["type"] == "vendor-docs" and src["authority"] == 100
    assert src["content_hash"] == rec["content_hash"]
    assert src["retrieved_at"] == "2026-08-24T00:00:00Z"
    # a promoted entry no longer carries a model-supplied receipt_id
    assert "receipt_id" not in src


def test_promote_derives_corroborated_from_two_independent_origins(tmp_path,
                                                                   knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out = str(tmp_path / "q")
    r1 = kc.quarantine("body one", "https://docs.github.com/x", out, reg,
                       "2026-08-24T00:00:00Z")
    r2 = kc.quarantine("body two", "https://slsa.dev/spec", out, reg,
                       "2026-08-24T00:00:00Z")
    cand = _candidate(sources=[
        {"url": "https://docs.github.com/x", "receipt_id": r1["receipt_id"]},
        {"url": "https://slsa.dev/spec", "receipt_id": r2["receipt_id"]}])
    validation = kc.validate_candidate(cand, reg, quarantine_dir=out)
    assert validation["valid"], validation["errors"]
    verified = kc.promote_to_verified(cand, validation, reg)
    assert verified["confidence"] == "corroborated"


# --------------------------------------------------------------------------- #
# evaluate_candidate — the single, unskippable orchestrator
# --------------------------------------------------------------------------- #
def test_evaluate_candidate_auto_promotes_clean_input(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    result = kc.evaluate_candidate(
        _bound(rec), reg, out, [], {"passed": True},
        change_facts={"change_paths": [], "removed_or_modified_evals": []})
    assert result["validation"]["valid"] is True
    assert result["promotion"]["tier"] == "auto-promote", result["promotion"]


def test_evaluate_candidate_blocks_invalid_input(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    # unresolvable receipt -> validation fails -> promotion refuses
    cand = _candidate(sources=[{"url": "https://docs.github.com/x",
                                "receipt_id": "QR-nope"}])
    result = kc.evaluate_candidate(cand, reg, str(tmp_path / "q"), [],
                                   {"passed": True})
    assert result["validation"]["valid"] is False
    assert result["promotion"]["tier"] == "never-auto"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_check_source(knowledge_dir, capsys):
    rc = kc.main(["check-source", "--url", "https://slsa.dev/spec",
                  "--knowledge-root", knowledge_dir])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["type"] == "standard" and out["authority"] == 90


def test_cli_promote_refuses_non_auto(tmp_path, knowledge_dir, capsys, monkeypatch):
    reg = kc.load_registry(knowledge_dir)
    out, rec = _quarantine(tmp_path, reg)
    cand = _bound(rec, supersedes=["KE-old"])  # supersede -> require-review
    ev = tmp_path / "eval.json"
    ev.write_text(json.dumps({"passed": True}))
    monkeypatch.setattr("sys.stdin", _Stdin(json.dumps(cand)))
    rc = kc.main(["promote", "--knowledge-root", knowledge_dir,
                  "--baseline", knowledge_dir, "--quarantine-dir", out,
                  "--eval-result", str(ev)])
    assert rc == 1
    assert "refusing to promote" in capsys.readouterr().err


class _Stdin:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text
