from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from apishield_agent.domain.contract_input import load_contract, read_contract, unsupported_constructs


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    pointer: str
    evidence_digest: str
    coverage: str = "COVERED"


METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def _escape(value: object) -> str:
    return str(value).replace("~", "~0").replace("/", "~1")


def _operations(doc: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (route, method.lower()): operation
        for route, item in doc["paths"].items()
        if isinstance(route, str)
        and isinstance(item, dict)
        for method, operation in item.items()
        if isinstance(method, str)
        and method.lower() in METHODS
        and isinstance(operation, dict)
    }


def _local_reference(doc: dict[str, Any], value: Any) -> dict[str, Any] | None:
    """Resolve bounded pure local reference chains; never merge assertion siblings."""
    seen = set()
    for _ in range(32):
        if not isinstance(value, dict):
            return None
        if "$ref" not in value:
            return value
        if set(value) - {"$ref", "description", "summary"}:
            return None
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
            return None
        seen.add(ref)
        target: Any = doc
        for raw in ref[2:].split("/"):
            if re.search(r"~(?![01])", raw):
                return None
            token = raw.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or token not in target:
                return None
            target = target[token]
        value = target
    return None


def _schema_required(doc: dict[str, Any], path: str) -> dict[tuple, set[str] | None]:
    result: dict[tuple, set[str] | None] = {}
    for route, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if not isinstance(method, str) or method.lower() not in METHODS or not isinstance(operation, dict):
                continue
            responses = operation.get("responses") or {}
            if not isinstance(responses, dict):
                raise ValueError("CONTRACT_RESPONSE_SHAPE_INVALID")
            for code, response in responses.items():
                if not isinstance(response, dict):
                    raise ValueError("CONTRACT_RESPONSE_SHAPE_INVALID")
                response = _local_reference(doc, response)
                if response is None:
                    result[(path, route, method.lower(), str(code), None)] = None
                    continue
                content = response.get("content") or {}
                if not isinstance(content, dict):
                    raise ValueError("CONTRACT_CONTENT_SHAPE_INVALID")
                for media, media_def in content.items():
                    if not isinstance(media_def, dict):
                        raise ValueError("CONTRACT_MEDIA_SHAPE_INVALID")
                    schema = _local_reference(doc, media_def.get("schema") or {})
                    if schema is None:
                        result[(path, route, method.lower(), str(code), str(media))] = None
                        continue
                    raw_required = schema.get("required", [])
                    if not isinstance(raw_required, list) or any(not isinstance(field, str) for field in raw_required):
                        raise ValueError("CONTRACT_REQUIRED_SHAPE_INVALID")
                    result[(path, route, method.lower(), str(code), str(media))] = set(raw_required)
    return result


def _parameters(doc: dict[str, Any], route: str, operation: dict[str, Any]) -> dict[tuple[str, str], tuple[dict[str, Any], str]]:
    result: dict[tuple[str, str], tuple[dict[str, Any], str]] = {}
    path_item = (doc.get("paths") or {}).get(route) or {}
    entries = list(path_item.get("parameters") or []) + list(operation.get("parameters") or [])
    for index, raw in enumerate(entries):
        parameter = _local_reference(doc, raw)
        if parameter is None:
            continue
        location, name = parameter.get("in"), parameter.get("name")
        if not isinstance(location, str) or not isinstance(name, str):
            continue
        result[(location, name)] = (parameter, f"/paths/{_escape(route)}/parameters/{index}")
    return result


def _media_schemas(doc: dict[str, Any], response_or_body: Any) -> dict[str, tuple[dict[str, Any], str]]:
    resolved = _local_reference(doc, response_or_body)
    if not resolved or not isinstance(resolved.get("content"), dict):
        return {}
    result = {}
    for media, media_def in resolved["content"].items():
        if not isinstance(media_def, dict):
            continue
        schema = _local_reference(doc, media_def.get("schema") or {})
        if schema is not None:
            result[str(media)] = (schema, f"/content/{_escape(media)}/schema")
    return result


def _record_finding(findings: list[Finding], source_digests: dict[str, str], rule: str, pointer: str, severity: str = "BREAKING", coverage: str = "COVERED") -> None:
    evidence = hashlib.sha256(json.dumps({"rule": rule, "pointer": pointer, "source_digests": source_digests}, sort_keys=True).encode()).hexdigest()
    findings.append(Finding(rule, severity, pointer, evidence, coverage))


def _compare_schema_pair(findings: list[Finding], source_digests: dict[str, str], old: dict[str, Any], new: dict[str, Any], pointer: str, *, response: bool, family: str | None = None) -> None:
    old_type, new_type = old.get("type"), new.get("type")
    if isinstance(old_type, str) and isinstance(new_type, str) and old_type != new_type:
        _record_finding(findings, source_digests, (family or ("RESPONSE" if response else "REQUEST")) + "_SCHEMA_TYPE_CHANGED", pointer + "/type")
    old_enum, new_enum = old.get("enum"), new.get("enum")
    if isinstance(old_enum, list) and isinstance(new_enum, list) and set(old_enum) - set(new_enum):
        _record_finding(findings, source_digests, (family or ("RESPONSE" if response else "REQUEST")) + "_ENUM_VALUE_REMOVED", pointer + "/enum")


def _compare_request(findings: list[Finding], source_digests: dict[str, str], before: dict[str, Any], after: dict[str, Any], route: str, method: str, old: dict[str, Any], new: dict[str, Any]) -> None:
    old_params, new_params = _parameters(before, route, old), _parameters(after, route, new)
    for key in sorted(set(old_params) | set(new_params)):
        old_entry, new_entry = old_params.get(key), new_params.get(key)
        if old_entry is None:
            if new_entry and new_entry[0].get("required") is True:
                _record_finding(findings, source_digests, "REQUEST_PARAMETER_ADDED_REQUIRED", new_entry[1] + "/required")
            continue
        if new_entry is None:
            _record_finding(findings, source_digests, "REQUEST_PARAMETER_REMOVED", old_entry[1])
            continue
        old_param, old_pointer = old_entry
        new_param, new_pointer = new_entry
        if new_param.get("required") is True and old_param.get("required") is not True:
            _record_finding(findings, source_digests, "REQUEST_PARAMETER_BECAME_REQUIRED", new_pointer + "/required")
        old_schema = _local_reference(before, old_param.get("schema") or {})
        new_schema = _local_reference(after, new_param.get("schema") or {})
        if old_schema is not None and new_schema is not None:
            _compare_schema_pair(findings, source_digests, old_schema, new_schema, new_pointer + "/schema", response=False, family="REQUEST_PARAMETER")
    old_body = _local_reference(before, old.get("requestBody", {}))
    new_body = _local_reference(after, new.get("requestBody", {}))
    if old.get("requestBody") is not None and not isinstance(old.get("requestBody"), dict):
        raise ValueError("CONTRACT_REQUEST_BODY_SHAPE_INVALID")
    if new.get("requestBody") is not None and not isinstance(new.get("requestBody"), dict):
        raise ValueError("CONTRACT_REQUEST_BODY_SHAPE_INVALID")
    if old_body is not None and new_body is not None:
        if new_body.get("required") is True and old_body.get("required") is not True:
            _record_finding(findings, source_digests, "REQUEST_BODY_BECAME_REQUIRED", f"/paths/{_escape(route)}/{method}/requestBody/required")
        old_media, new_media = _media_schemas(before, old_body), _media_schemas(after, new_body)
        for media in sorted(set(old_media) & set(new_media)):
            old_schema, new_schema = old_media[media][0], new_media[media][0]
            pointer = f"/paths/{_escape(route)}/{method}/requestBody/content/{_escape(media)}/schema"
            _compare_schema_pair(findings, source_digests, old_schema, new_schema, pointer, response=False)
            old_required, new_required = set(old_schema.get("required") or []), set(new_schema.get("required") or [])
            for field in sorted(new_required - old_required):
                _record_finding(findings, source_digests, "REQUEST_BODY_FIELD_BECAME_REQUIRED", pointer + "/required/" + _escape(field))


def _compare_responses(findings: list[Finding], source_digests: dict[str, str], before: dict[str, Any], after: dict[str, Any], route: str, method: str, old: dict[str, Any], new: dict[str, Any]) -> None:
    old_responses, new_responses = old.get("responses") or {}, new.get("responses") or {}
    if not isinstance(old_responses, dict) or not isinstance(new_responses, dict):
        raise ValueError("CONTRACT_RESPONSE_SHAPE_INVALID")
    for code in sorted(set(old_responses) - set(new_responses), key=str):
        _record_finding(findings, source_digests, "RESPONSE_STATUS_REMOVED", f"/paths/{_escape(route)}/{method}/responses/{_escape(code)}")
    for code in sorted(set(old_responses) & set(new_responses), key=str):
        old_response, new_response = _local_reference(before, old_responses[code]), _local_reference(after, new_responses[code])
        if old_response is None or new_response is None:
            continue
        old_content, new_content = old_response.get("content") or {}, new_response.get("content") or {}
        if not isinstance(old_content, dict) or not isinstance(new_content, dict):
            raise ValueError("CONTRACT_CONTENT_SHAPE_INVALID")
        for media in sorted(set(old_content) - set(new_content), key=str):
            _record_finding(findings, source_digests, "RESPONSE_MEDIA_TYPE_REMOVED", f"/paths/{_escape(route)}/{method}/responses/{_escape(code)}/content/{_escape(media)}")
        for media in sorted(set(old_content) & set(new_content), key=str):
            old_media, new_media = old_content[media] if isinstance(old_content[media], dict) else {}, new_content[media] if isinstance(new_content[media], dict) else {}
            old_schema, new_schema = _local_reference(before, old_media.get("schema") or {}), _local_reference(after, new_media.get("schema") or {})
            if old_schema is not None and new_schema is not None:
                pointer = f"/paths/{_escape(route)}/{method}/responses/{_escape(code)}/content/{_escape(media)}/schema"
                _compare_schema_pair(findings, source_digests, old_schema, new_schema, pointer, response=True)


def deterministic_openapi_diff(before_path: str | None, after_path: str | None) -> list[Finding]:
    """Classify bounded request and response compatibility changes."""
    if not before_path or not after_path or not Path(before_path).exists() or not Path(after_path).exists():
        raise ValueError("CONTRACT_INPUT_UNAVAILABLE")
    return deterministic_openapi_diff_bytes(read_contract(before_path), read_contract(after_path))


def deterministic_openapi_diff_bytes(before_bytes: bytes, after_bytes: bytes) -> list[Finding]:
    before, after = load_contract(before_bytes), load_contract(after_bytes)
    source_digests = {"before": hashlib.sha256(before_bytes).hexdigest(), "after": hashlib.sha256(after_bytes).hexdigest()}
    before_required, after_required = _schema_required(before, "before"), _schema_required(after, "after")
    findings: list[Finding] = []
    old_operations, new_operations = _operations(before), _operations(after)
    for route, method in sorted(old_operations):
        pointer = f"/paths/{_escape(route)}/{method}"
        old, new = old_operations[(route, method)], new_operations.get((route, method))
        if new is None:
            _record_finding(findings, source_digests, "OPERATION_REMOVED", pointer)
            continue
        _compare_request(findings, source_digests, before, after, route, method, old, new)
        _compare_responses(findings, source_digests, before, after, route, method, old, new)
    for pointer in sorted(set(unsupported_constructs(before)) | set(unsupported_constructs(after))):
        _record_finding(findings, source_digests, "UNSUPPORTED_SCHEMA_CONSTRUCT", pointer, "REVIEW", "UNSUPPORTED")
    keys = {key[1:] for key in before_required} | {key[1:] for key in after_required}
    unknown_keys = {key[1:] for values in (before_required, after_required) for key, fields in values.items() if fields is None}
    unknown_responses = {key[:3] for key in unknown_keys if key[3] is None}
    for route, method, code, media in sorted(keys, key=lambda key: tuple(str(part) for part in key)):
        key = (route, method, code, media)
        if (route, method) not in new_operations or key in unknown_keys or key[:3] in unknown_responses:
            continue
        before_fields = before_required.get(("before",) + key, set())
        after_fields = after_required.get(("after",) + key, set())
        for field in sorted(after_fields - before_fields):
            pointer = f"/paths/{_escape(route)}/{method}/responses/{_escape(code)}/content/{_escape(media)}/schema/required/{_escape(field)}"
            _record_finding(findings, source_digests, "REQUIRED_RESPONSE_FIELD_ADDED", pointer, "REVIEW", "LIMITED")
        for field in sorted(before_fields - after_fields):
            pointer = f"/paths/{_escape(route)}/{method}/responses/{_escape(code)}/content/{_escape(media)}/schema/required/{_escape(field)}"
            _record_finding(findings, source_digests, "REQUIRED_RESPONSE_FIELD_REMOVED", pointer)
    return findings
