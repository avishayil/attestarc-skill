"""Unit tests for scripts/knowledge_compile.py — the Updater's deterministic steps.

Proves: registry-derived authority (never model-chosen), the HTTPS + origin +
org/repo path-scoped fetch allowlist, URL reclassification during candidate
validation, quarantine receipts + provenance binding, contradiction detection,
and the derived promotion-tier policy from core/promotion-policy.md.
"""

import json
import os

import knowledge_compile as kc


def _valid_candidate(**over):
    base = {
        "id": "KE-test-x", "kind": "platform-semantics",
        "platform": "github-actions", "subject": "cache-write",
        "claim": "cache writes are ref-scoped", "valid_from": "2026-06-26",
        "status": "active", "confidence": "authoritative",
        "sources": [{"publisher": "GitHub", "authority": 100,
                     "type": "vendor-docs", "url": "https://docs.github.com/x",
                     "content_hash": "a" * 64,
                     "retrieved_at": "2026-08-24T00:00:00Z"}],
    }
    base.update(over)
    return base


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
    # the repo host record carries scoping path_prefixes
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


# --------------------------------------------------------------------------- #
# validate-candidate
# --------------------------------------------------------------------------- #
def test_valid_candidate_passes(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.validate_candidate(_valid_candidate(), reg)
    assert result["valid"] is True, result["errors"]
    assert result["errors"] == []


def test_model_chosen_authority_is_rejected(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _valid_candidate(sources=[{"publisher": "GitHub", "authority": 55,
                                      "type": "vendor-docs",
                                      "url": "https://docs.github.com/x",
                                      "content_hash": "a" * 64,
                                      "retrieved_at": "2026-08-24T00:00:00Z"}])
    result = kc.validate_candidate(cand, reg)
    assert result["valid"] is False
    assert any("never model-chosen" in e for e in result["errors"])


def test_candidate_lying_about_vendor_docs_is_reclassified(knowledge_dir):
    """A candidate that labels an attacker URL 'vendor-docs' is caught by
    reclassifying the URL — the registry, not the model, decides authority."""
    reg = kc.load_registry(knowledge_dir)
    cand = _valid_candidate(sources=[{"publisher": "GitHub", "authority": 100,
                                      "type": "vendor-docs",
                                      "url": "https://evil.example.com/fake-docs",
                                      "content_hash": "a" * 64,
                                      "retrieved_at": "2026-08-24T00:00:00Z"}])
    result = kc.validate_candidate(cand, reg)
    assert result["valid"] is False
    assert any("arbitrary-web" in e for e in result["errors"])
    assert result["max_authority"] == 0


def test_source_without_provenance_binding_rejected(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _valid_candidate(sources=[{"url": "https://docs.github.com/x"}])
    result = kc.validate_candidate(cand, reg)
    assert result["valid"] is False
    assert any("content_hash" in e for e in result["errors"])


def test_unknown_field_rejected(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _valid_candidate(verdict="critical")  # not a schema field
    result = kc.validate_candidate(cand, reg)
    assert result["valid"] is False
    assert any("unknown fields" in e for e in result["errors"])


def test_bad_enum_rejected(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.validate_candidate(_valid_candidate(status="totally-fine"), reg)
    assert result["valid"] is False


def test_secret_in_candidate_rejected(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _valid_candidate(claim="use token ghp_" + "a" * 36)
    result = kc.validate_candidate(cand, reg)
    assert result["valid"] is False
    assert any("secret" in e for e in result["errors"])


def test_missing_required_field_rejected(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _valid_candidate()
    del cand["claim"]
    result = kc.validate_candidate(cand, reg)
    assert result["valid"] is False
    assert any("claim" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# quarantine receipts + provenance resolution
# --------------------------------------------------------------------------- #
def test_quarantine_emits_receipt(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out = str(tmp_path / "q")
    rec = kc.quarantine("hello world", "https://docs.github.com/x", out, reg,
                        "2026-08-24T00:00:00Z")
    assert rec["allowed"] is True
    assert rec["authority"] == 100 and rec["source_type"] == "vendor-docs"
    assert rec["receipt_id"].startswith("QR-")
    assert os.path.exists(rec["stored_path"])
    assert os.path.exists(rec["receipt_path"])
    resolved = kc.resolve_receipt(rec["receipt_id"], out)
    assert resolved["content_hash"] == rec["content_hash"]


def test_candidate_bound_by_receipt_id_passes(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out = str(tmp_path / "q")
    rec = kc.quarantine("doc body", "https://docs.github.com/x", out, reg,
                        "2026-08-24T00:00:00Z")
    cand = _valid_candidate(sources=[{"url": "https://docs.github.com/x",
                                      "receipt_id": rec["receipt_id"]}])
    result = kc.validate_candidate(cand, reg, quarantine_dir=out)
    assert result["valid"] is True, result["errors"]


def test_candidate_with_unresolvable_receipt_rejected(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _valid_candidate(sources=[{"url": "https://docs.github.com/x",
                                      "receipt_id": "QR-does-not-exist"}])
    result = kc.validate_candidate(cand, reg, quarantine_dir=str(tmp_path / "q"))
    assert result["valid"] is False
    assert any("does not resolve" in e for e in result["errors"])


# --------------------------------------------------------------------------- #
# conflict
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


# --------------------------------------------------------------------------- #
# may-promote — the deterministic policy (facts are DERIVED, not asserted)
# --------------------------------------------------------------------------- #
def _facts(**over):
    base = {"evals_pass": True, "signature_valid": True,
            "change_paths": [], "removed_or_modified_evals": []}
    base.update(over)
    return base


def test_clean_authoritative_new_knowledge_auto_promotes(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(_valid_candidate(), _facts(), registry=reg,
                            existing=[])
    assert result["tier"] == "auto-promote"


def test_superseding_change_requires_review(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _valid_candidate(supersedes=["KE-old"])
    result = kc.may_promote(cand, _facts(), registry=reg, existing=[])
    assert result["tier"] == "require-review"


def test_conflict_requires_review(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    existing = [{"id": "KE-a", "platform": "github-actions",
                 "subject": "cache-write", "status": "active",
                 "confidence": "authoritative", "claim": "something else"}]
    result = kc.may_promote(_valid_candidate(), _facts(), registry=reg,
                            existing=existing)
    assert result["tier"] == "require-review"


def test_failing_evals_block_auto_promote(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(_valid_candidate(), _facts(evals_pass=False),
                            registry=reg, existing=[])
    assert result["tier"] == "require-review"


def test_invalid_signature_blocks_auto_promote(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(_valid_candidate(), _facts(signature_valid=False),
                            registry=reg, existing=[])
    assert result["tier"] == "require-review"


def test_low_authority_source_is_never_auto(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _valid_candidate(confidence="candidate",
                            sources=[{"url": "https://randomblog.example/x",
                                      "content_hash": "a" * 64,
                                      "retrieved_at": "2026-08-24T00:00:00Z"}])
    result = kc.may_promote(cand, _facts(), registry=reg, existing=[])
    assert result["tier"] == "never-auto"


def test_root_of_trust_change_is_two_party(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(_valid_candidate(),
                            _facts(change_paths=["knowledge/sources.yaml"]),
                            registry=reg, existing=[])
    assert result["tier"] == "two-party-review"


def test_eval_weakening_is_two_party(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.may_promote(
        _valid_candidate(),
        _facts(removed_or_modified_evals=["evals/cases/known-good.md"]),
        registry=reg, existing=[])
    assert result["tier"] == "two-party-review"


def test_most_severe_tier_wins(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    # root-of-trust (two-party) beats a mere supersede (require-review) trigger
    cand = _valid_candidate(supersedes=["KE-old"])
    result = kc.may_promote(
        cand, _facts(change_paths=["scripts/knowledge_verify.py"]),
        registry=reg, existing=[])
    assert result["tier"] == "two-party-review"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_check_source(knowledge_dir, capsys):
    rc = kc.main(["check-source", "--url", "https://slsa.dev/spec",
                  "--knowledge-root", knowledge_dir])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["type"] == "standard" and out["authority"] == 90
