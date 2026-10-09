from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    pointer: str
    evidence_digest: str
    coverage: str = "COVERED"


def _schema_required(doc: dict[str, Any], path: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for route, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"} or not isinstance(operation, dict):
                continue
            for code, response in (operation.get("responses") or {}).items():
                content = (response or {}).get("content") or {}
                for media, media_def in content.items():
                    schema = (media_def or {}).get("schema") or {}
                    required = set(schema.get("required") or []) if isinstance(schema, dict) else set()
                    result[f"{path}:{route}:{method}:{code}:{media}"] = required
    return result


def deterministic_openapi_diff(before_path: str | None, after_path: str | None) -> list[Finding]:
    """Classify inline required-response-field changes; additions need review, removals break the previous presence guarantee."""
    if not before_path or not after_path or not Path(before_path).exists() or not Path(after_path).exists():
        raise ValueError("CONTRACT_INPUT_UNAVAILABLE")
    before = yaml.safe_load(Path(before_path).read_text()) or {}
    after = yaml.safe_load(Path(after_path).read_text()) or {}
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("CONTRACT_INPUT_INVALID")
    source_digests = {"before": hashlib.sha256(Path(before_path).read_bytes()).hexdigest(), "after": hashlib.sha256(Path(after_path).read_bytes()).hexdigest()}
    before_required = _schema_required(before, "before")
    after_required = _schema_required(after, "after")
    findings: list[Finding] = []
    for key in sorted(set(after_required) | {key.replace("before:", "after:", 1) for key in before_required}):
        before_key = key.replace("after:", "before:", 1)
        before_fields = before_required.get(before_key, set())
        after_fields = after_required.get(key, set())
        changes = [(field, "ADDED", "REVIEW", "LIMITED") for field in sorted(after_fields - before_fields)]
        changes += [(field, "REMOVED", "BREAKING", "COVERED") for field in sorted(before_fields - after_fields)]
        for field, direction, severity, coverage in changes:
            pointer = key.replace(":", "/", 1) + "/required/" + field
            evidence = hashlib.sha256(json.dumps({"rule": "required-response-field-" + direction.lower(), "pointer": pointer, "field": field, "source_digests": source_digests}, sort_keys=True).encode()).hexdigest()
            findings.append(Finding("REQUIRED_RESPONSE_FIELD_" + direction, severity, pointer, evidence, coverage))
    return findings

