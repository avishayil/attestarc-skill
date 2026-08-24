"""Unit tests for scripts/knowledge_compile.py — the Updater's deterministic steps.

Proves: registry-derived authority (never model-chosen), the fetch allowlist,
schema/provenance/secret validation, contradiction detection, and the
deterministic promotion-tier policy from core/promotion-policy.md.
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
                     "type": "vendor-docs", "url": "https://docs.github.com/x"}],
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
    domains = {r["domain"] for r in reg["allowlist"]}
    assert "docs.github.com" in domains
    assert all({"domain", "publisher", "type"} <= set(r) for r in reg["allowlist"])


def test_allowlisted_domain_gets_registry_authority(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    fact = kc.classify_source("https://docs.github.com/en/actions", reg)
    assert fact["allowed"] is True
    assert fact["authority"] == 100
    assert fact["type"] == "vendor-docs"


def test_unlisted_domain_is_arbitrary_web(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    fact = kc.classify_source("https://evil.example.com/poison", reg)
    assert fact["allowed"] is False
    assert fact["authority"] == 0
    assert fact["type"] == "arbitrary-web"


def test_subdomain_not_implicitly_trusted(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    # a bare github.com entry must not vouch for an arbitrary *.github.io host
    fact = kc.classify_source("https://attacker.github.io/x", reg)
    assert fact["allowed"] is False


# --------------------------------------------------------------------------- #
# validate-candidate
# --------------------------------------------------------------------------- #
def test_valid_candidate_passes(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    result = kc.validate_candidate(_valid_candidate(), reg)
    assert result["valid"] is True
    assert result["errors"] == []


def test_model_chosen_authority_is_rejected(knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    cand = _valid_candidate(sources=[{"publisher": "GitHub", "authority": 55,
                                      "type": "vendor-docs",
                                      "url": "https://docs.github.com/x"}])
    result = kc.validate_candidate(cand, reg)
    assert result["valid"] is False
    assert any("never model-chosen" in e for e in result["errors"])


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
# may-promote — the deterministic policy
# --------------------------------------------------------------------------- #
def _facts(**over):
    base = {"evals_pass": True, "signature_valid": True, "has_conflict": False,
            "direction": "positive", "changes_root_of_trust": False,
            "weakens_eval": False, "alters_reachability_or_severity": False,
            "max_authority": 100}
    base.update(over)
    return base


def test_clean_authoritative_change_auto_promotes():
    result = kc.may_promote(_valid_candidate(), _facts())
    assert result["tier"] == "auto-promote"


def test_security_negative_requires_review():
    result = kc.may_promote(_valid_candidate(), _facts(direction="negative"))
    assert result["tier"] == "require-review"


def test_unknown_direction_requires_review():
    result = kc.may_promote(_valid_candidate(), _facts(direction=None))
    assert result["tier"] == "require-review"


def test_conflict_requires_review():
    result = kc.may_promote(_valid_candidate(), _facts(has_conflict=True))
    assert result["tier"] == "require-review"


def test_failing_evals_block_auto_promote():
    result = kc.may_promote(_valid_candidate(), _facts(evals_pass=False))
    assert result["tier"] == "require-review"


def test_low_authority_source_is_never_auto():
    cand = _valid_candidate(confidence="candidate",
                            sources=[{"publisher": "blog", "authority": 40,
                                      "type": "issue", "url": "https://x"}])
    result = kc.may_promote(cand, _facts(max_authority=40))
    assert result["tier"] == "never-auto"


def test_root_of_trust_change_is_two_party():
    result = kc.may_promote(_valid_candidate(),
                            _facts(changes_root_of_trust=True))
    assert result["tier"] == "two-party-review"


def test_eval_weakening_is_two_party():
    result = kc.may_promote(_valid_candidate(), _facts(weakens_eval=True))
    assert result["tier"] == "two-party-review"


def test_most_severe_tier_wins():
    # root-of-trust (two-party) beats a mere require-review trigger
    result = kc.may_promote(_valid_candidate(),
                            _facts(direction="negative",
                                   changes_root_of_trust=True))
    assert result["tier"] == "two-party-review"


# --------------------------------------------------------------------------- #
# quarantine + CLI
# --------------------------------------------------------------------------- #
def test_quarantine_stores_by_hash(tmp_path, knowledge_dir):
    reg = kc.load_registry(knowledge_dir)
    out = str(tmp_path / "q")
    fact = kc.quarantine("hello world", "https://docs.github.com/x", out, reg)
    assert fact["allowed"] is True
    assert os.path.exists(fact["stored_path"])
    assert len(fact["content_hash"]) == 64
    with open(fact["stored_path"]) as fh:
        assert fh.read() == "hello world"


def test_cli_check_source(knowledge_dir, capsys):
    rc = kc.main(["check-source", "--url", "https://slsa.dev/spec",
                  "--knowledge-root", knowledge_dir])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["type"] == "standard" and out["authority"] == 90
