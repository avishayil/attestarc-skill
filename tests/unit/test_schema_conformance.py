"""Guard that state.py output stays inside the closed findings schema.

The schema (schemas/findings.schema.json) is now strict: stable objects use
additionalProperties:false with an explicit 'extensions' escape hatch. jsonschema
is not a runtime (or dev) dependency, so instead of full validation we assert
that every key state.py actually persists is declared in the schema. This is the
cheap check that catches drift between the writer and its contract.
"""

import json
import os

import state


def _load_schema(schemas_dir):
    with open(os.path.join(schemas_dir, "findings.schema.json")) as fh:
        return json.load(fh)


def _allowed_keys(schema, definition):
    return set(schema["definitions"][definition]["properties"].keys())


def _full_finding():
    return {
        "domain": "ci",
        "category": "mutable-action",
        "resource": ".github/workflows/release.yml",
        "subject": "docker/login-action",
        "condition": "uses a mutable tag",
        "title": "Third-party Action uses a mutable reference",
        "severity": "high",
        "confidence": "high",
        "status": "open",
        "impact": "x",
        "trust_boundary": "a -> b",
        "related_findings": [],
        "knowledge_dependencies": [
            {"id": "KE-gha-cache-write-triggers", "version": "1"},
        ],
        "evidence": [{
            "type": "repository-file",
            "source": ".github/workflows/release.yml",
            "location": {"line": 1},
            "observed": "uses: docker/login-action@v3",
        }],
        "remediation": {"summary": "pin", "type": "file-change",
                        "automatic": True, "targets": ["x"]},
        "verification": {"method": "workflow-reference", "expected": "sha",
                         "status": "pending"},
        "threat": {"actor": "external-contributor", "reachability": "direct",
                   "capabilities": ["MODIFY_PIPELINE"]},
    }


def test_schema_is_valid_json_and_closed(schemas_dir):
    schema = _load_schema(schemas_dir)
    assert schema["properties"]["schema_version"]["const"] == state.SCHEMA_VERSION
    assert schema["additionalProperties"] is False
    assert schema["definitions"]["finding"]["additionalProperties"] is False


def test_persisted_finding_keys_are_all_in_schema(schemas_dir):
    schema = _load_schema(schemas_dir)
    stored = state.normalize_finding(_full_finding())
    allowed = _allowed_keys(schema, "finding")
    extra = set(stored.keys()) - allowed
    assert not extra, f"state.py persists keys absent from the schema: {extra}"


def test_persisted_nested_object_keys_are_in_schema(schemas_dir):
    schema = _load_schema(schemas_dir)
    stored = state.normalize_finding(_full_finding())
    for obj_key, definition in (("evidence", "evidence"),
                                ("remediation", "remediation"),
                                ("verification", "verification"),
                                ("threat", "threat")):
        allowed = _allowed_keys(schema, definition)
        value = stored[obj_key]
        items = value if isinstance(value, list) else [value]
        for item in items:
            extra = set(item.keys()) - allowed
            assert not extra, f"{obj_key} has keys absent from schema: {extra}"


def test_schema_version_is_4(schemas_dir):
    assert _load_schema(schemas_dir)["properties"]["schema_version"]["const"] == 4
    assert state.SCHEMA_VERSION == 4


def test_new_definitions_exist(schemas_dir):
    schema = _load_schema(schemas_dir)
    defs = schema["definitions"]
    for name in ("related_finding", "risk_acceptance", "assessor_safety_event",
                 "knowledge_dependency"):
        assert name in defs, f"missing definition: {name}"
    # finding.type taxonomy is additive/optional.
    assert set(defs["finding"]["properties"]["type"]["enum"]) == {
        "exposure", "attack-path", "hardening"}
    # related_findings items are now typed objects, not bare id strings.
    assert defs["finding"]["properties"]["related_findings"]["items"]["$ref"] == \
        "#/definitions/related_finding"
    assert set(defs["related_finding"]["properties"]["relationship"]["enum"]) == {
        "contributes_to", "superseded_by", "duplicate_of"}
    # risk_acceptance carries the lapse date.
    assert "expires_at" in defs["risk_acceptance"]["properties"]


def test_flat_risk_acceptance_fields_removed(schemas_dir):
    """The flat accepted_by/accepted_at fields migrated into risk_acceptance."""
    finding_props = _load_schema(schemas_dir)["definitions"]["finding"]["properties"]
    assert "accepted_by" not in finding_props
    assert "accepted_at" not in finding_props
    assert "risk_acceptance" in finding_props


def test_top_level_assessor_safety_events_declared(schemas_dir):
    schema = _load_schema(schemas_dir)
    assert "assessor_safety_events" in schema["properties"]
    assert schema["properties"]["assessor_safety_events"]["items"]["$ref"] == \
        "#/definitions/assessor_safety_event"


def test_schema_id_matches_version(schemas_dir):
    assert _load_schema(schemas_dir)["$id"].endswith("findings-4.json")


def test_knowledge_dependency_definition(schemas_dir):
    schema = _load_schema(schemas_dir)
    dep = schema["definitions"]["knowledge_dependency"]
    assert dep["additionalProperties"] is False
    assert dep["required"] == ["id"]
    assert set(dep["properties"].keys()) == {"id", "version", "content_hash"}
    # findings reference it as an optional array on the finding.
    assert schema["definitions"]["finding"]["properties"][
        "knowledge_dependencies"]["items"]["$ref"] == \
        "#/definitions/knowledge_dependency"


# --------------------------------------------------------------------------- #
# knowledge-plane schemas parse and carry the expected closed vocabularies.
# --------------------------------------------------------------------------- #
def test_all_schemas_parse(schemas_dir):
    for name in ("findings.schema.json", "knowledge.schema.json",
                 "knowledge-manifest.schema.json",
                 "learning-candidate.schema.json"):
        with open(os.path.join(schemas_dir, name)) as fh:
            assert json.load(fh)["$id"]


def test_learning_candidate_vocabulary(schemas_dir):
    with open(os.path.join(schemas_dir, "learning-candidate.schema.json")) as fh:
        schema = json.load(fh)
    props = schema["properties"]
    assert schema["additionalProperties"] is False
    assert set(props["change_target"]["enum"]) == {
        "knowledge", "reference", "helper", "methodology"}
    assert set(props["security_regression_direction"]["enum"]) == {
        "positive", "neutral", "negative"}
    # a candidate is a proposal: direction must be declared up front.
    assert "security_regression_direction" in schema["required"]


def test_knowledge_manifest_role_types(schemas_dir):
    """The attestation model: the metadata schema anchors exactly two documents —
    the external trust_anchor and the per-release manifest. The homemade
    root/timestamp/snapshot/targets role files are gone."""
    with open(os.path.join(schemas_dir, "knowledge-manifest.schema.json")) as fh:
        schema = json.load(fh)
    consts = {branch["$ref"].split("/")[-1] for branch in schema["oneOf"]}
    assert consts == {"trust_anchor", "manifest"}
    anchor = schema["definitions"]["trust_anchor"]
    assert {"_type", "repo", "signer_workflow", "cert_oidc_issuer"} <= set(
        anchor["required"])
    manifest = schema["definitions"]["manifest"]
    assert {"_type", "version", "created_at", "expires", "packs"} <= set(
        manifest["required"])
    # mode is optional + defensive: a downloaded bundle claiming bootstrap is rejected.
    assert manifest["properties"]["mode"]["enum"] == ["bootstrap", "signed"]


def test_assessor_safety_event_has_content_hash(schemas_dir):
    props = _load_schema(schemas_dir)["definitions"]["assessor_safety_event"]["properties"]
    assert "content_hash" in props
    assert props["content_hash"]["pattern"] == "^[0-9a-f]{64}$"


# --------------------------------------------------------------------------- #
# validator <-> schema parity: the hand-rolled validate_state must enforce the
# same closed vocabularies the schema declares (no jsonschema at runtime).
# --------------------------------------------------------------------------- #
def test_validator_key_sets_match_schema(schemas_dir):
    schema = _load_schema(schemas_dir)
    assert state._TOPLEVEL_KEYS == set(schema["properties"].keys())
    assert state._FINDING_KEYS == _allowed_keys(schema, "finding")
    assert state._RELATED_KEYS == _allowed_keys(schema, "related_finding")
    assert state._RISK_ACCEPTANCE_KEYS == _allowed_keys(schema, "risk_acceptance")
    assert state._SAFETY_EVENT_KEYS == _allowed_keys(schema, "assessor_safety_event")
    assert state._KNOWLEDGE_DEP_KEYS == _allowed_keys(schema, "knowledge_dependency")


def test_validator_enums_match_schema(schemas_dir):
    schema = _load_schema(schemas_dir)
    defs = schema["definitions"]
    assert set(state.FINDING_TYPES) == set(defs["finding"]["properties"]["type"]["enum"])
    assert set(state.RELATIONSHIPS) == set(
        defs["related_finding"]["properties"]["relationship"]["enum"])
    assert set(state.REACHABILITY) == set(
        defs["threat"]["properties"]["reachability"]["enum"])
    assert set(state.EVIDENCE_TYPES) == set(
        defs["evidence"]["properties"]["type"]["enum"])
    assert set(state._SAFETY_SOURCES) == set(
        defs["assessor_safety_event"]["properties"]["source"]["enum"])
