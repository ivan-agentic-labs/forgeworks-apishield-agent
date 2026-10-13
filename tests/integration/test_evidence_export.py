import hashlib
import json
import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from apishield_agent.infrastructure.store import REPOSITORY, TENANT, USER
from apishield_agent.main import create_app

SECRET = "forgeworks-development-secret-32-plus"
ISSUER = "https://issuer.synthetic.invalid"
AUDIENCE = "forgeworks-api"
BASE = "a" * 40
HEAD = "b" * 40


def headers(scope, key="evidence-test-key-000001", tenant=TENANT, user=USER):
    token = jwt.encode(
        {"sub": user, "tenant_id": tenant, "scope": scope, "iss": ISSUER,
         "aud": AUDIENCE, "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}", "Idempotency-Key": key}


def create_completed_analysis(client):
    started = client.post(
        f"/v1/installations/1/repositories/{REPOSITORY}/analyses",
        headers=headers("repo:analyze", "evidence-analysis-key-001"),
        json={"base_sha": BASE, "head_sha": HEAD, "capability_profile": "openapi31-typescript-v1"},
    )
    assert started.status_code == 202, started.text
    analysis = started.json()
    for _ in range(100):
        detail = client.get(
            f"/v1/analyses/{analysis['id']}",
            headers=headers("analysis:read", "evidence-analysis-read-001"),
        )
        assert detail.status_code == 200, detail.text
        if detail.json()["status"] in {"SUCCEEDED", "FAILED_TERMINAL", "CANCELLED"}:
            break
        time.sleep(0.02)
    assert detail.json()["status"] == "SUCCEEDED", detail.text
    return analysis


def assert_bundle_digest(bundle):
    supplied = bundle.pop("bundle_sha256")
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == supplied
    bundle["bundle_sha256"] = supplied


def test_export_contains_tenant_bound_digests_decisions_and_partiality(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        analysis = create_completed_analysis(client)
        proposal_response = client.post(
            f"/v1/analyses/{analysis['id']}/proposals",
            headers=headers("patch:create", "evidence-proposal-key-001"),
            json={"analysis_id": analysis["id"], "target_language": "typescript"},
        )
        assert proposal_response.status_code == 201, proposal_response.text
        proposal = proposal_response.json()
        approval_response = client.post(
            f"/v1/proposals/{proposal['id']}/approvals",
            headers=headers("patch:approve", "evidence-approval-key-001"),
            json={"patch_sha256": proposal["patch_sha256"], "base_sha": BASE,
                  "decision": "approve", "expected_version": 1},
        )
        assert approval_response.status_code == 201, approval_response.text
        approval = approval_response.json()

        with app.state.store.conn() as db:
            events_before = db.execute("SELECT COUNT(*) FROM events WHERE tenant_id=?", (TENANT,)).fetchone()[0]
        response = client.get(
            f"/v1/analyses/{analysis['id']}/evidence-export",
            headers=headers("evidence:read", "evidence-export-key-001"),
        )
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "attachment; filename=\"apishield-evidence-" in response.headers["content-disposition"]
        bundle = response.json()
        assert bundle["schema_version"] == "1"
        assert bundle["evidence_status"] == "PARTIAL"
        assert bundle["tenant_id"] == TENANT
        assert bundle["analysis"]["id"] == analysis["id"]
        assert bundle["analysis"]["actor_id"] == USER
        assert len(bundle["analysis"]["request_sha256"]) == 64
        assert all(len(value) == 64 for value in bundle["input_digests"].values())
        assert len(bundle["output"]["result_sha256"]) == 64
        assert bundle["decisions"]["findings"]
        exported_proposal = bundle["decisions"]["proposals"][0]
        assert exported_proposal["patch_sha256"] == proposal["patch_sha256"]
        assert exported_proposal["approval_records"][0]["id"] == approval["id"]
        assert exported_proposal["approval_records"][0]["reviewer_id"] == USER
        assert any(event["event_type"] == "analysis.completed" for event in bundle["audit_events"])
        assert "APPROVAL_DECISION_AUDIT_EVENT_NOT_PERSISTED" in bundle["missing_components"]
        assert "TWO_YEAR_RETENTION_NOT_IMPLEMENTED" in bundle["missing_components"]
        assert "EXPORT_ACCESS_NOT_AUDITED" in bundle["missing_components"]
        assert_bundle_digest(bundle)
        assert b"before_base64" not in response.content
        assert b"after_base64" not in response.content
        assert b"patch_text" not in response.content
        assert b"contracts/before.yaml" not in response.content

        repeated = client.get(
            f"/v1/analyses/{analysis['id']}/evidence-export",
            headers=headers("evidence:read", "evidence-export-key-002"),
        )
        assert repeated.status_code == 200
        assert repeated.content == response.content
        with app.state.store.conn() as db:
            events_after = db.execute("SELECT COUNT(*) FROM events WHERE tenant_id=?", (TENANT,)).fetchone()[0]
        assert events_after == events_before


def test_export_requires_scope_active_membership_and_repository_access(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        analysis = create_completed_analysis(client)
        url = f"/v1/analyses/{analysis['id']}/evidence-export"

        missing_scope = client.get(url, headers=headers("analysis:read", "evidence-no-scope-001"))
        assert missing_scope.status_code == 403
        assert missing_scope.json()["code"] == "INSUFFICIENT_SCOPE"
        assert missing_scope.headers["content-type"].startswith("application/problem+json")

        invalid_uuid = client.get("/v1/analyses/not-a-uuid/evidence-export", headers=headers("evidence:read", "evidence-invalid-uuid-001"))
        assert invalid_uuid.status_code == 422
        assert invalid_uuid.headers["content-type"].startswith("application/problem+json")
        assert invalid_uuid.json()["code"] == "INVALID_REQUEST"

        with app.state.store.conn() as db:
            db.execute("UPDATE memberships SET role='viewer' WHERE tenant_id=? AND user_id=?", (TENANT, USER))
        viewer = client.get(url, headers=headers("evidence:read", "evidence-viewer-key-001"))
        assert viewer.status_code == 200, viewer.text

        other_tenant = client.get(
            url,
            headers=headers("evidence:read", "evidence-other-tenant-001", tenant="00000000-0000-0000-0000-000000000099"),
        )
        assert other_tenant.status_code == 403

        with app.state.store.conn() as db:
            db.execute("UPDATE repositories SET permission_state='REVOKED' WHERE tenant_id=? AND id=?", (TENANT, REPOSITORY))
        revoked = client.get(url, headers=headers("evidence:read", "evidence-revoked-key-001"))
        assert revoked.status_code == 403
        assert revoked.json()["code"] == "REPOSITORY_ACCESS_REVOKED"


def test_export_retries_serialization_race_and_returns_revocation(tmp_path, monkeypatch):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        analysis = create_completed_analysis(client)
        original = app.state.store.analysis_evidence_snapshot
        attempts = 0

        def race_then_retry(tenant, aid):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                with app.state.store.conn() as db:
                    db.execute("UPDATE repositories SET permission_state='REVOKED' WHERE tenant_id=? AND id=?", (TENANT, REPOSITORY))
                conflict = RuntimeError("synthetic PostgreSQL serialization failure")
                conflict.sqlstate = "40001"
                raise conflict
            return original(tenant, aid)

        monkeypatch.setattr(app.state.store, "analysis_evidence_snapshot", race_then_retry)
        response = client.get(
            f"/v1/analyses/{analysis['id']}/evidence-export",
            headers=headers("evidence:read", "evidence-race-retry-key-001"),
        )
        assert attempts == 2
        assert response.status_code == 403
        assert response.json()["code"] == "REPOSITORY_ACCESS_REVOKED"
        assert response.headers["content-type"].startswith("application/problem+json")

        with app.state.store.conn() as db:
            db.execute("UPDATE repositories SET permission_state='READ' WHERE tenant_id=? AND id=?", (TENANT, REPOSITORY))
        attempts = 0

        def always_conflict(tenant, aid):
            nonlocal attempts
            attempts += 1
            conflict = RuntimeError("synthetic PostgreSQL serialization failure")
            conflict.sqlstate = "40001"
            raise conflict

        monkeypatch.setattr(app.state.store, "analysis_evidence_snapshot", always_conflict)
        repeated_conflict = client.get(
            f"/v1/analyses/{analysis['id']}/evidence-export",
            headers=headers("evidence:read", "evidence-race-conflict-key-01"),
        )
        assert attempts == 2
        assert repeated_conflict.status_code == 409
        assert repeated_conflict.json()["code"] == "EVIDENCE_SNAPSHOT_CONFLICT"
        assert repeated_conflict.headers["content-type"].startswith("application/problem+json")


def test_export_rejects_non_terminal_analysis(tmp_path, monkeypatch):
    monkeypatch.setenv("APISHIELD_EMBEDDED_WORKER", "0")
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        row = app.state.store.create_analysis(TENANT, USER, REPOSITORY, BASE, HEAD, "test-profile", "pending-evidence-key-001", "a" * 64)
        response = client.get(
            f"/v1/analyses/{row['id']}/evidence-export",
            headers=headers("evidence:read", "evidence-pending-key-001"),
        )
        assert response.status_code == 409
        assert response.json()["code"] == "ANALYSIS_NOT_TERMINAL"


def test_export_fails_closed_above_item_limit(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        analysis = create_completed_analysis(client)
        with app.state.store.conn() as db:
            db.executemany(
                "INSERT INTO findings VALUES(?,?,?,?,?,?,?,?)",
                [
                    (TENANT, f"33333333-3333-4333-8333-{index:012d}", analysis["id"],
                     f"SYNTHETIC_LIMIT_{index}", "REVIEW", f"/paths/{index}", "c" * 64, "BOUNDED")
                    for index in range(1000)
                ],
            )
        response = client.get(
            f"/v1/analyses/{analysis['id']}/evidence-export",
            headers=headers("evidence:read", "evidence-item-limit-key-001"),
        )
        assert response.status_code == 413
        assert response.json()["code"] == "EVIDENCE_EXPORT_TOO_LARGE"


def test_export_rejects_tampered_source_snapshot(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        analysis = create_completed_analysis(client)
        with app.state.store.conn() as db:
            db.execute(
                "UPDATE analysis_source_snapshots SET before_base64=? WHERE tenant_id=? AND analysis_id=?",
                ("not-base64!", TENANT, analysis["id"]),
            )
        response = client.get(
            f"/v1/analyses/{analysis['id']}/evidence-export",
            headers=headers("evidence:read", "evidence-integrity-key-001"),
        )
        assert response.status_code == 409
        assert response.json()["code"] == "EVIDENCE_SOURCE_INTEGRITY_FAILURE"
