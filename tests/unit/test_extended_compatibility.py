import json
from copy import deepcopy
import pytest
from apishield_agent.domain.analysis import deterministic_openapi_diff_bytes


def document(schema=None):
    return {"paths": {"/items": {"get": {"responses": {"200": {"content": {"application/json": {"schema": schema or {"type": "object"}}}}}}}}}


def diff(old, new):
    return deterministic_openapi_diff_bytes(json.dumps(old).encode(), json.dumps(new).encode())


def test_removed_operation_without_required_response_fields_is_breaking():
    old = document(); new = deepcopy(old); new["paths"] = {}
    result = diff(old, new)
    assert [(f.rule_id, f.severity) for f in result] == [("OPERATION_REMOVED", "BREAKING")]
    assert result[0].pointer == "/paths/~1items/get"


def test_request_body_required_change_with_local_reference():
    old = document(); new = deepcopy(old)
    new["components"] = {"requestBodies": {"Input": {"required": True, "content": {}}}}
    new["paths"]["/items"]["get"]["requestBody"] = {"$ref": "#/components/requestBodies/Input"}
    assert any(f.rule_id == "REQUEST_BODY_BECAME_REQUIRED" and f.severity == "BREAKING" for f in diff(old, new))


def test_local_escaped_schema_reference_detects_lost_presence():
    old = document({"$ref": "#/components/schemas/A~1B~0C"})
    old["components"] = {"schemas": {"A/B~C": {"type": "object", "required": ["id"]}}}
    new = deepcopy(old); new["components"]["schemas"]["A/B~C"]["required"] = []
    result = diff(old, new)
    assert any(f.rule_id == "REQUIRED_RESPONSE_FIELD_REMOVED" for f in result)
    assert any(f.coverage == "UNSUPPORTED" for f in result)  # Other ref semantics remain open.


@pytest.mark.parametrize("reference", ["#/components/schemas/Missing", "#/components/schemas/Cycle", "#/components/schemas/A~2B"])
def test_unresolved_reference_never_becomes_empty_schema(reference):
    old = document({"type": "object", "required": ["id"]})
    new = document({"$ref": reference})
    new["components"] = {"schemas": {"Cycle": {"$ref": "#/components/schemas/Cycle"}}}
    result = diff(old, new)
    assert any(f.coverage == "UNSUPPORTED" for f in result)
    assert not any(f.rule_id == "REQUIRED_RESPONSE_FIELD_REMOVED" for f in result)


def test_reference_assertion_siblings_remain_unknown():
    old = document({"type": "object", "required": ["id"]})
    new = document({"$ref": "#/components/schemas/X", "type": "string"})
    new["components"] = {"schemas": {"X": {"required": []}}}
    assert not any(f.rule_id == "REQUIRED_RESPONSE_FIELD_REMOVED" for f in diff(old, new))


def test_invalid_response_shape_is_typed_failure():
    old = document(); new = deepcopy(old); new["paths"]["/items"]["get"]["responses"]["200"] = "invalid"
    with pytest.raises(ValueError, match="CONTRACT_RESPONSE_SHAPE_INVALID"):
        diff(old, new)


def test_required_request_parameter_addition_and_type_change_are_breaking():
    old = document()
    old["paths"]["/items"]["get"]["parameters"] = [{"name": "limit", "in": "query", "required": False, "schema": {"type": "integer"}}]
    new = deepcopy(old)
    new["paths"]["/items"]["get"]["parameters"] = [
        {"name": "limit", "in": "query", "required": True, "schema": {"type": "string"}},
        {"name": "cursor", "in": "query", "required": True, "schema": {"type": "string"}},
    ]
    result = diff(old, new)
    rules = {finding.rule_id for finding in result}
    assert "REQUEST_PARAMETER_BECAME_REQUIRED" in rules
    assert "REQUEST_PARAMETER_SCHEMA_TYPE_CHANGED" in rules
    assert "REQUEST_PARAMETER_ADDED_REQUIRED" in rules


def test_removed_request_parameter_and_enum_value_are_breaking():
    old = document()
    old["paths"]["/items"]["get"]["parameters"] = [{"name": "status", "in": "query", "schema": {"type": "string", "enum": ["open", "closed"]}}]
    new = document()
    result = diff(old, new)
    assert any(f.rule_id == "REQUEST_PARAMETER_REMOVED" for f in result)
    new = document()
    new["paths"]["/items"]["get"]["parameters"] = [{"name": "status", "in": "query", "schema": {"type": "string", "enum": ["open"]}}]
    assert any(f.rule_id == "REQUEST_PARAMETER_ENUM_VALUE_REMOVED" for f in diff(old, new))


def test_request_body_required_property_and_response_surface_changes_are_breaking():
    old = document()
    old["paths"]["/items"]["post"] = {"requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"name": {"type": "string"}}}}}}, "responses": {"200": {"content": {"application/json": {"schema": {"type": "string", "enum": ["ok", "error"]}}}}, "201": {"description": "created"}}}
    new = deepcopy(old)
    new["paths"]["/items"]["post"]["requestBody"]["content"]["application/json"]["schema"]["required"] = ["name"]
    new["paths"]["/items"]["post"]["responses"]["200"]["content"]["application/json"]["schema"] = {"type": "integer", "enum": [1]}
    del new["paths"]["/items"]["post"]["responses"]["201"]
    result = diff(old, new)
    rules = {finding.rule_id for finding in result}
    assert "REQUEST_BODY_FIELD_BECAME_REQUIRED" in rules
    assert "RESPONSE_SCHEMA_TYPE_CHANGED" in rules
    assert "RESPONSE_ENUM_VALUE_REMOVED" in rules
    assert "RESPONSE_STATUS_REMOVED" in rules


def test_removed_request_media_type_is_breaking_even_when_remaining_schema_is_same():
    before = document()
    old_operation = before["paths"]["/items"]["get"]
    old_operation["requestBody"] = {"content": {
        "application/json": {"schema": {"type": "object"}},
        "application/vnd.synthetic+json": {"schema": {"type": "object"}},
    }}
    after = deepcopy(before)
    del after["paths"]["/items"]["get"]["requestBody"]["content"]["application/vnd.synthetic+json"]
    results = diff(before, after)
    removed = [row for row in results if row.rule_id == "REQUEST_MEDIA_TYPE_REMOVED"]
    assert len(removed) == 1, results
    assert removed[0].severity == "BREAKING"
    assert removed[0].pointer == "/paths/~1items/get/requestBody/content/application~1vnd.synthetic+json"
    assert removed[0].evidence_digest == diff(before, after)[0].evidence_digest


def test_new_request_media_type_is_not_a_removed_media_break():
    old = document()
    old["paths"]["/items"]["get"]["requestBody"] = {
        "content": {"application/json": {"schema": {"type": "object"}}}
    }
    new = deepcopy(old)
    new["paths"]["/items"]["get"]["requestBody"]["content"]["application/xml"] = {
        "schema": {"type": "string"}
    }
    assert not any(result.rule_id == "REQUEST_MEDIA_TYPE_REMOVED" for result in diff(old, new))


def test_removing_entire_request_body_does_not_hide_lost_media_support():
    old = document()
    old["paths"]["/items"]["get"]["requestBody"] = {
        "content": {"application/json": {"schema": {"type": "object"}}}
    }
    new = deepcopy(old)
    del new["paths"]["/items"]["get"]["requestBody"]
    assert any(result.rule_id == "REQUEST_MEDIA_TYPE_REMOVED" for result in diff(old, new))
