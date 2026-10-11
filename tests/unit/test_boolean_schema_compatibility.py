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
@pytest.mark.parametrize("unrestricted", [True, {}])
def test_false_schema_direction_has_independent_witness(surface, unrestricted):
    assert Draft202012Validator(unrestricted).is_valid({"id": 1})
    assert not Draft202012Validator(False).is_valid({"id": 1})
    old, new = (False, unrestricted) if surface == "response" else (unrestricted, False)
    finding, = diff(old, new, surface)
    family = {"request": "REQUEST", "parameter": "REQUEST_PARAMETER"}[surface] if surface != "response" else None
    rule = "RESPONSE_SCHEMA_NO_LONGER_FALSE" if surface == "response" else family + "_SCHEMA_BECAME_FALSE"
    assert (finding.rule_id, finding.severity, finding.coverage) == (rule, "BREAKING", "COVERED")
    assert finding.pointer.endswith("/schema")
    assert diff(new, old, surface) == []


@pytest.mark.parametrize("surface", ["request", "parameter", "response"])
@pytest.mark.parametrize("schema", [True, False])
def test_unchanged_boolean_schema_is_not_breaking(surface, schema):
    assert diff(schema, schema, surface) == []


@pytest.mark.parametrize("surface", ["request", "parameter", "response"])
def test_true_and_empty_object_are_equivalent(surface):
    assert diff(True, {}, surface) == diff({}, True, surface) == []


@pytest.mark.parametrize("surface", ["request", "parameter", "response"])
def test_object_false_comparison_is_limited(surface):
    old, new = (False, {"type": "string"}) if surface == "response" else ({"type": "string"}, False)
    finding, = diff(old, new, surface)
    assert (finding.severity, finding.coverage) == ("BREAKING", "LIMITED")


@pytest.mark.parametrize("surface", ["request", "parameter", "response"])
def test_true_schema_still_participates_in_type_comparison(surface):
    old, new = ({"type": "string"}, True) if surface == "response" else (True, {"type": "string"})
    finding, = diff(old, new, surface)
    assert finding.rule_id.endswith("_SCHEMA_TYPE_CHANGED")


@pytest.mark.parametrize("surface", ["request", "parameter", "response"])
def test_unresolved_schema_cannot_silently_pass(surface):
    result = diff({}, {"$ref": "#/components/schemas/Missing"}, surface)
    assert any(f.coverage == "UNSUPPORTED" and f.pointer.endswith("/schema") for f in result)


@pytest.mark.parametrize("surface", ["request", "parameter", "response"])
def test_local_schema_reference_can_resolve_to_false(surface):
    old = contract({}, surface)
    new = contract({"$ref": "#/components/schemas/Deny"}, surface)
    new["components"] = {"schemas": {"Deny": False}}
    if surface == "response":
        old, new = new, old
    result = deterministic_openapi_diff_bytes(json.dumps(old).encode(), json.dumps(new).encode())
    assert any(f.severity == "BREAKING" and f.rule_id.endswith(("_SCHEMA_BECAME_FALSE", "_SCHEMA_NO_LONGER_FALSE")) for f in result)
    assert any(f.coverage == "UNSUPPORTED" for f in result)  # Other ref semantics remain open.


def test_false_array_item_is_preserved_and_pointer_escaped():
    old = {"type": "object", "properties": {"a/b~c": {"type": "array", "items": True}}}
    new = {"type": "object", "properties": {"a/b~c": {"type": "array", "items": False}}}
    assert Draft202012Validator(old).is_valid({"a/b~c": [1]})
    assert not Draft202012Validator(new).is_valid({"a/b~c": [1]})
    finding, = diff(old, new, "request")
    assert finding.pointer.endswith("/properties/a~1b~0c/items")
    assert finding.coverage == "LIMITED"


def test_false_response_schema_does_not_invent_required_field_removal():
    result = diff({"type": "object", "required": ["id"]}, False, "response")
    assert not any(f.rule_id == "REQUIRED_RESPONSE_FIELD_REMOVED" for f in result)
