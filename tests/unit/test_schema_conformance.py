"""Guard that state.py output stays inside the closed findings schema.

The schema (assets/findings.schema.json) is now strict: stable objects use
additionalProperties:false with an explicit 'extensions' escape hatch. jsonschema
is not a runtime (or dev) dependency, so instead of full validation we assert
that every key state.py actually persists is declared in the schema. This is the
cheap check that catches drift between the writer and its contract.
"""

import json
import os

import state


def _load_schema(assets_dir):
    with open(os.path.join(assets_dir, "findings.schema.json")) as fh:
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


def test_schema_is_valid_json_and_closed(assets_dir):
    schema = _load_schema(assets_dir)
    assert schema["properties"]["schema_version"]["const"] == state.SCHEMA_VERSION
    assert schema["additionalProperties"] is False
    assert schema["definitions"]["finding"]["additionalProperties"] is False


def test_persisted_finding_keys_are_all_in_schema(assets_dir):
    schema = _load_schema(assets_dir)
    stored = state.normalize_finding(_full_finding())
    allowed = _allowed_keys(schema, "finding")
    extra = set(stored.keys()) - allowed
    assert not extra, f"state.py persists keys absent from the schema: {extra}"


def test_persisted_nested_object_keys_are_in_schema(assets_dir):
    schema = _load_schema(assets_dir)
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
