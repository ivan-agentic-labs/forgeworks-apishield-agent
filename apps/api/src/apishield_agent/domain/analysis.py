from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from apishield_agent.domain.contract_input import load_contract, unsupported_constructs, read_contract


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    pointer: str
    evidence_digest: str
    coverage: str = "COVERED"


METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def _operations(doc):
    return {(route, method.lower()): operation for route, item in doc["paths"].items() if isinstance(route, str) and isinstance(item, dict) for method, operation in item.items() if isinstance(method, str) and method.lower() in METHODS and isinstance(operation, dict)}


def _local_reference(doc, value):
    """Resolve bounded pure local reference chains; never merge schema assertions."""
    seen = set()
    for _ in range(32):
        if not isinstance(value, dict):
            return None
        if "$ref" not in value:
            return value
        if set(value) - {"$ref", "description", "summary"}:
            return None  # Assertion siblings require composition semantics.
        ref = value["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/") or ref in seen:
            return None
        seen.add(ref)
        target = doc
        for raw in ref[2:].split("/"):
            # JSON Pointer escaping is exact; do not accept malformed ~ escapes.
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
                    raw_required = schema.get("required", []) if schema is not None else []
                    if not isinstance(raw_required, list) or any(not isinstance(field, str) for field in raw_required):
                        raise ValueError("CONTRACT_REQUIRED_SHAPE_INVALID")
                    required = set(raw_required)
                    result[(path, route, method.lower(), str(code), str(media))] = required
    return result


def deterministic_openapi_diff(before_path: str | None, after_path: str | None) -> list[Finding]:
    """Classify inline required-response-field changes; additions need review, removals break the previous presence guarantee."""
    if not before_path or not after_path or not Path(before_path).exists() or not Path(after_path).exists():
        raise ValueError("CONTRACT_INPUT_UNAVAILABLE")
    before_bytes = read_contract(before_path)
    after_bytes = read_contract(after_path)
    return deterministic_openapi_diff_bytes(before_bytes, after_bytes)


def deterministic_openapi_diff_bytes(before_bytes: bytes, after_bytes: bytes) -> list[Finding]:
    before = load_contract(before_bytes)
    after = load_contract(after_bytes)
    source_digests = {"before": hashlib.sha256(before_bytes).hexdigest(), "after": hashlib.sha256(after_bytes).hexdigest()}
    before_required = _schema_required(before, "before")
    after_required = _schema_required(after, "after")
    findings: list[Finding] = []
    old_operations, new_operations = _operations(before), _operations(after)
    def record(rule, pointer, severity="BREAKING", coverage="COVERED"):
        evidence = hashlib.sha256(json.dumps({"rule": rule, "pointer": pointer, "source_digests": source_digests}, sort_keys=True).encode()).hexdigest()
        findings.append(Finding(rule, severity, pointer, evidence, coverage))
    for route, method in sorted(old_operations):
        escaped = route.replace("~", "~0").replace("/", "~1")
        pointer = f"/paths/{escaped}/{method}"
        old = old_operations[(route, method)]
        new = new_operations.get((route, method))
        if new is None:
            record("OPERATION_REMOVED", pointer)
            continue
        old_body, new_body = _local_reference(before, old.get("requestBody", {})), _local_reference(after, new.get("requestBody", {}))
        if any("requestBody" in operation and not isinstance(operation["requestBody"], dict) for operation in (old, new)):
            raise ValueError("CONTRACT_REQUEST_BODY_SHAPE_INVALID")
        if old_body is not None and new_body is not None and new_body.get("required") is True and old_body.get("required") is not True:
            record("REQUEST_BODY_BECAME_REQUIRED", pointer + "/requestBody/required")
    for pointer in sorted(set(unsupported_constructs(before)) | set(unsupported_constructs(after))):
        evidence = hashlib.sha256(json.dumps({'rule':'unsupported-schema-construct','pointer':pointer,'source_digests':source_digests},sort_keys=True).encode()).hexdigest()
        findings.append(Finding('UNSUPPORTED_SCHEMA_CONSTRUCT','REVIEW',pointer,evidence,'UNSUPPORTED'))
    keys = {key[1:] for key in before_required} | {key[1:] for key in after_required}
    unknown_keys = {name[1:] for values in (before_required, after_required) for name, fields in values.items() if fields is None}
    unknown_responses = {key[:3] for key in unknown_keys if key[3] is None}
    for route, method, code, media in sorted(keys, key=lambda key: tuple(str(part) for part in key)):
        key = (route, method, code, media)
        if (route, method) not in new_operations:
            continue  # Operation removal is the root cause, not a field edit.
        if key in unknown_keys or key[:3] in unknown_responses:
            continue  # An unresolved reference is unknown, not an empty schema.
        before_fields = before_required.get(("before",) + key, set())
        after_fields = after_required.get(("after",) + key, set())
        changes = [(field, "ADDED", "REVIEW", "LIMITED") for field in sorted(after_fields - before_fields)]
        changes += [(field, "REMOVED", "BREAKING", "COVERED") for field in sorted(before_fields - after_fields)]
        for field, direction, severity, coverage in changes:
            escape_pointer = lambda part: str(part).replace("~", "~0").replace("/", "~1")
            pointer = "/paths/" + escape_pointer(route) + "/" + method + "/responses/" + escape_pointer(code) + "/content/" + escape_pointer(media) + "/schema/required/" + escape_pointer(field)
            evidence = hashlib.sha256(json.dumps({"rule": "required-response-field-" + direction.lower(), "pointer": pointer, "field": field, "source_digests": source_digests}, sort_keys=True).encode()).hexdigest()
            findings.append(Finding("REQUIRED_RESPONSE_FIELD_" + direction, severity, pointer, evidence, coverage))
    return findings

