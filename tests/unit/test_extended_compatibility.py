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
