from pathlib import Path

from apishield_agent.domain.analysis import deterministic_openapi_diff


def test_required_response_field_is_breaking():
    root = Path(__file__).parents[2] / "fixtures" / "golden"
    findings = deterministic_openapi_diff(str(root / "before.yaml"), str(root / "after.yaml"))
    assert len(findings) == 1
    assert findings[0].severity == "BREAKING"
    assert findings[0].rule_id == "REQUIRED_RESPONSE_FIELD_ADDED"
    assert len(findings[0].evidence_digest) == 64
