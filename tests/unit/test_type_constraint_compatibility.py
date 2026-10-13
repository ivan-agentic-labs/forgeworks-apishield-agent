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
        operation["parameters"] = [{"name": "value", "in": "query", "schema": schema}]
    return {"openapi": "3.1.0", "paths": {"/items": {"post": operation}}}


def diff(old, new, surface):
    return deterministic_openapi_diff_bytes(json.dumps(contract(old, surface)).encode(), json.dumps(contract(new, surface)).encode())


@pytest.mark.parametrize("surface", ["request", "parameter", "response"])
@pytest.mark.parametrize("unrestricted,restricted,witness", [
    ({}, {"type": "string"}, 5),
    ({"type": ["string", "null"]}, {"type": "string"}, None),
    ({"type": "number"}, {"type": "integer"}, 1.5),
    ({"type": ["number", "boolean"]}, {"type": ["integer", "boolean"]}, 0.25),
])
def test_type_direction_matches_independent_counterexample(surface, unrestricted, restricted, witness):
    assert Draft202012Validator(unrestricted).is_valid(witness)
    assert not Draft202012Validator(restricted).is_valid(witness)
    old, new = (restricted, unrestricted) if surface == "response" else (unrestricted, restricted)
    finding, = diff(old, new, surface)
    family = {"response": "RESPONSE", "request": "REQUEST", "parameter": "REQUEST_PARAMETER"}[surface]
    assert (finding.rule_id, finding.severity, finding.coverage) == (family + "_SCHEMA_TYPE_CHANGED", "BREAKING", "LIMITED")
    assert finding.pointer.endswith("/schema/type")
    assert diff(new, old, surface) == []


@pytest.mark.parametrize("surface", ["request", "parameter", "response"])
@pytest.mark.parametrize("old,new", [
    ({"type": "number"}, {"type": ["integer", "number"]}),
    ({"type": "string"}, {"type": ["string"]}),
    ({"type": ["string", "null"]}, {"type": ["null", "string"]}),
    ({}, {"type": ["null", "boolean", "object", "array", "number", "string"]}),
])
def test_equivalent_type_sets_are_not_breaking(surface, old, new):
    assert diff(old, new, surface) == []


@pytest.mark.parametrize("value", [None, False, 5, {}, [], ["string", "string"], ["string", 5], "unknown"])
def test_malformed_type_is_not_ignored(value):
    with pytest.raises(ValueError, match="CONTRACT_SCHEMA_TYPE_INVALID"):
        diff({}, {"type": value}, "request")


def test_nested_type_union_pointer_escapes_property_name():
    old = {"properties": {"a/b~c": {"type": "array", "items": {"type": ["string", "null"]}}}}
    new = {"properties": {"a/b~c": {"type": "array", "items": {"type": "string"}}}}
    finding, = diff(old, new, "request")
    assert finding.pointer.endswith("/properties/a~1b~0c/items/type")


def test_boolean_instance_is_not_covered_by_number():
    assert not Draft202012Validator({"type": "number"}).is_valid(True)
    finding, = diff({"type": ["number", "boolean"]}, {"type": "number"}, "request")
    assert finding.rule_id == "REQUEST_SCHEMA_TYPE_CHANGED"


@pytest.mark.parametrize("value", [True, False])
def test_legacy_nullable_keyword_remains_explicitly_uncovered(value):
    finding, = diff({"type": "string", "nullable": value}, {"type": "string"}, "response")
    assert (finding.severity, finding.coverage) == ("REVIEW", "UNSUPPORTED")
    assert finding.pointer.endswith("/nullable")
