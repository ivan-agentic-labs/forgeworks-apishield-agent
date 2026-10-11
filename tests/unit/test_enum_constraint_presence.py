"""Counterexamples checked by an independent JSON Schema validator."""
import json

import pytest
from jsonschema import Draft202012Validator

from apishield_agent.domain.analysis import deterministic_openapi_diff_bytes


def contract(schema, surface):
    operation = {"responses": {"200": {"description": "ok"}}}
    media = {"content": {"application/json": {"schema": schema}}}
    if surface == "response":
        operation["responses"]["200"].update(media)
    elif surface == "request":
        operation["requestBody"] = media
    else:
        operation["parameters"] = [{"name": "status", "in": "query", "schema": schema}]
    return {"openapi": "3.1.0", "paths": {"/items": {"post": operation}}}


def diff(old, new, surface):
    return deterministic_openapi_diff_bytes(json.dumps(contract(old, surface)).encode(), json.dumps(contract(new, surface)).encode())


@pytest.mark.parametrize("surface,family", [("request", "REQUEST"), ("parameter", "REQUEST_PARAMETER")])
@pytest.mark.parametrize("schema,witness", [({"type": "string", "enum": ["open"]}, "closed"), ({"enum": [True]}, 1), ({"enum": [None]}, "value")])
def test_new_input_enum_rejects_previously_valid_witness(surface, family, schema, witness):
    old = {key: value for key, value in schema.items() if key != "enum"}
    assert Draft202012Validator(old).is_valid(witness)
    assert not Draft202012Validator(schema).is_valid(witness)
    findings = diff(old, schema, surface)
    assert [(f.rule_id, f.severity, f.coverage) for f in findings] == [(family + "_ENUM_CONSTRAINT_ADDED", "BREAKING", "LIMITED")]
    assert findings[0].pointer.endswith("/schema/enum")


@pytest.mark.parametrize("schema,witness", [({"type": "string", "enum": ["open"]}, "closed"), ({"enum": [True]}, 1), ({"enum": [None]}, "value"), ({"enum": []}, None)])
def test_removed_output_enum_admits_previously_invalid_witness(schema, witness):
    new = {key: value for key, value in schema.items() if key != "enum"}
    assert not Draft202012Validator(schema).is_valid(witness)
    assert Draft202012Validator(new).is_valid(witness)
    finding, = diff(schema, new, "response")
    assert (finding.rule_id, finding.severity, finding.coverage) == ("RESPONSE_ENUM_CONSTRAINT_REMOVED", "BREAKING", "LIMITED")


@pytest.mark.parametrize("surface", ["request", "parameter", "response"])
def test_safe_direction_does_not_report_presence_break(surface):
    restricted = {"type": "string", "enum": ["open"]}
    unrestricted = {"type": "string"}
    old, new = (unrestricted, restricted) if surface == "response" else (restricted, unrestricted)
    assert diff(old, new, surface) == []


@pytest.mark.parametrize("surface", ["request", "parameter", "response"])
def test_malformed_enum_is_not_silently_treated_as_absent(surface):
    with pytest.raises(ValueError, match="CONTRACT_ENUM_SHAPE_INVALID"):
        diff({"enum": "open"}, {}, surface)


def test_complex_enum_presence_requires_review():
    finding, = diff({}, {"enum": [{"status": "open"}]}, "request")
    assert (finding.severity, finding.coverage) == ("REVIEW", "UNSUPPORTED")


def test_nested_array_enum_pointer_is_escaped_and_digest_binds_sources():
    old = {"type": "object", "properties": {"a/b~c": {"type": "array", "items": {"type": "string"}}}}
    new = {"type": "object", "properties": {"a/b~c": {"type": "array", "items": {"type": "string", "enum": ["open"]}}}}
    finding, = diff(old, new, "request")
    assert finding.pointer.endswith("/properties/a~1b~0c/items/enum")
    assert diff(old, new, "request") == [finding]
    changed = {"type": "object", "description": "changed bytes", "properties": new["properties"]}
    assert diff(old, changed, "request")[0].evidence_digest != finding.evidence_digest
