"""Nested contract fixtures; no client code execution is implied."""
import json
from copy import deepcopy
import pytest
from apishield_agent.domain.analysis import deterministic_openapi_diff_bytes


def contract(schema, request=False):
    media = {"content": {"application/json": {"schema": schema}}}
    operation = {"responses": {"200": {"description": "ok", **deepcopy(media)}}}
    if request: operation["requestBody"] = media
    return {"openapi": "3.1.0", "info": {"title": "synthetic", "version": "1"}, "paths": {"/items": {"post": operation}}}


def schema(doc, request=False):
    op = doc["paths"]["/items"]["post"]
    media = op["requestBody"] if request else op["responses"]["200"]
    return media["content"]["application/json"]["schema"]


def diff(old, new):
    return deterministic_openapi_diff_bytes(json.dumps(old).encode(), json.dumps(new).encode())


def test_nested_response_type_change():
    old = contract({"type": "object", "properties": {"a/b~c": {"type": "array", "items": {"type": "object", "properties": {"id": {"type": "integer"}}}}}})
    new = deepcopy(old)
    schema(new)["properties"]["a/b~c"]["items"]["properties"]["id"]["type"] = "string"
    assert any(f.rule_id == "RESPONSE_SCHEMA_TYPE_CHANGED" and f.severity == "BREAKING" and f.pointer.endswith("/properties/a~1b~0c/items/properties/id/type") for f in diff(old, new))


def test_nested_request_required_field():
    old = contract({"type": "object", "properties": {"address": {"type": "object", "properties": {"postcode": {"type": "string"}}}}}, True)
    new = deepcopy(old)
    schema(new, True)["properties"]["address"]["required"] = ["postcode"]
    assert any(f.rule_id == "REQUEST_BODY_FIELD_BECAME_REQUIRED" and f.pointer.endswith("/properties/address/required/0") for f in diff(old, new))


def test_nested_response_presence_loss():
    old = contract({"type": "array", "items": {"type": "object", "properties": {"id": {"type": "integer"}}, "required": ["id"]}})
    new = deepcopy(old)
    schema(new)["items"]["required"] = []
    assert any(f.rule_id == "REQUIRED_RESPONSE_FIELD_REMOVED" and f.pointer.endswith("/items/required/0") for f in diff(old, new))


def test_operation_parameter_pointer():
    old = contract({"type": "object"})
    old["paths"]["/items"]["parameters"] = [{"name": "tenant", "in": "header", "schema": {"type": "string"}}]
    old["paths"]["/items"]["post"]["parameters"] = [{"name": "limit", "in": "query", "schema": {"type": "integer"}}]
    new = deepcopy(old)
    new["paths"]["/items"]["post"]["parameters"][0]["required"] = True
    assert any(f.pointer == "/paths/~1items/post/parameters/0/required" for f in diff(old, new))


def test_removed_operation_override_uses_inherited_parameter():
    old = contract({"type": "object"})
    old["paths"]["/items"]["parameters"] = [{"name": "limit", "in": "query", "required": True, "schema": {"type": "integer"}}]
    old["paths"]["/items"]["post"]["parameters"] = [{"name": "limit", "in": "query", "required": False, "schema": {"type": "integer"}}]
    new = deepcopy(old)
    del new["paths"]["/items"]["post"]["parameters"]
    result = diff(old, new)
    assert any(f.rule_id == "REQUEST_PARAMETER_BECAME_REQUIRED" and f.pointer == "/paths/~1items/parameters/0/required" for f in result)
    assert not any(f.rule_id == "REQUEST_PARAMETER_REMOVED" for f in result)


@pytest.mark.parametrize("keyword,a,b", [("minimum", 0, 1), ("maximum", 10, 9), ("minLength", 0, 1), ("maxLength", 10, 9), ("minItems", 0, 1), ("maxItems", 10, 9)])
def test_request_constraint_tightening(keyword, a, b):
    old = contract({"type": "object", "properties": {"value": {keyword: a}}}, True)
    new = deepcopy(old)
    schema(new, True)["properties"]["value"][keyword] = b
    assert any(f.rule_id == "REQUEST_CONSTRAINT_TIGHTENED" and f.pointer.endswith("/properties/value/" + keyword) for f in diff(old, new))


def test_recursive_reference_is_bounded():
    old = contract({"$ref": "#/components/schemas/Node"})
    old["components"] = {"schemas": {"Node": {"type": "object", "properties": {"child": {"$ref": "#/components/schemas/Node"}}}}}
    result = diff(old, deepcopy(old))
    assert any(f.coverage == "UNSUPPORTED" for f in result)
    assert not any(f.severity == "BREAKING" for f in result)


@pytest.mark.parametrize("values", [[{"status": "ok"}], [[1, 2]]])
def test_complex_enum_does_not_crash(values):
    old = contract({"enum": values})
    assert any(f.coverage == "UNSUPPORTED" for f in diff(old, deepcopy(old)))


def test_boolean_enum_is_distinct_from_numeric():
    assert any(f.rule_id == "REQUEST_ENUM_VALUE_REMOVED" for f in diff(contract({"enum": [True]}, True), contract({"enum": [1]}, True)))


def test_equal_numeric_enum_values_are_not_breaking():
    assert not any(f.rule_id == "REQUEST_ENUM_VALUE_REMOVED" for f in diff(contract({"enum": [1]}, True), contract({"enum": [1.0]}, True)))


@pytest.mark.parametrize("keyword,a,b", [("minimum", 1, 0), ("maximum", 9, 10), ("minLength", 1, 0), ("maxLength", 9, 10), ("minItems", 1, 0), ("maxItems", 9, 10)])
def test_response_constraint_loosening(keyword, a, b):
    old = contract({keyword: a})
    new = contract({keyword: b})
    assert any(f.rule_id == "RESPONSE_CONSTRAINT_LOOSENED" for f in diff(old, new))


def test_response_enum_expansion_is_breaking():
    result = diff(contract({"enum": ["ok"]}), contract({"enum": ["ok", "pending"]}))
    assert any(f.rule_id == "RESPONSE_ENUM_VALUE_ADDED" and f.severity == "BREAKING" for f in result)


def test_response_enum_narrowing_requires_review_without_type_break():
    result = diff(contract({"enum": ["ok", "pending"]}), contract({"enum": ["ok"]}))
    assert any(f.rule_id == "RESPONSE_ENUM_VALUE_REMOVED" and f.severity == "REVIEW" for f in result)
    assert not any(f.severity == "BREAKING" for f in result)


@pytest.mark.parametrize("keyword", ["minLength", "minItems", "minProperties"])
def test_zero_lower_count_bound_is_not_a_restriction(keyword):
    result = diff(contract({}, True), contract({keyword: 0}, True))
    assert not any(f.rule_id == "REQUEST_CONSTRAINT_TIGHTENED" for f in result)


def test_nested_local_reference_type_change():
    old = contract({"type": "object", "properties": {"value": {"$ref": "#/components/schemas/Value"}}})
    old["components"] = {"schemas": {"Value": {"type": "integer"}}}
    new = deepcopy(old)
    new["components"]["schemas"]["Value"]["type"] = "string"
    assert any(f.rule_id == "RESPONSE_SCHEMA_TYPE_CHANGED" and f.pointer.endswith("/properties/value/type") for f in diff(old, new))


def test_wide_schema_traversal_limit_is_explicit_review():
    old = contract({"properties": {"value" + str(i): {"type": "string"} for i in range(520)}})
    assert any(f.rule_id == "SCHEMA_TRAVERSAL_LIMIT" and f.coverage == "UNSUPPORTED" for f in diff(old, deepcopy(old)))


def test_request_closed_object_is_breaking():
    result = diff(contract({"type": "object"}, True), contract({"type": "object", "additionalProperties": False}, True))
    assert any(f.rule_id == "REQUEST_ADDITIONAL_PROPERTIES_DISALLOWED" for f in result)


def test_operation_parameter_invalid_container_has_typed_failure():
    old = contract({})
    new = deepcopy(old)
    new["paths"]["/items"]["post"]["parameters"] = {"bad": "shape"}
    with pytest.raises(ValueError, match="CONTRACT_PARAMETER_SHAPE_INVALID"):
        diff(old, new)
