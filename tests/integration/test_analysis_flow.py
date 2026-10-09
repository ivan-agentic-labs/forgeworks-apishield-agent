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


def token(tenant=TENANT, user=USER, scope="repo:analyze analysis:read job:read"):
    return jwt.encode({"sub": user, "tenant_id": tenant, "scope": scope, "iss": ISSUER, "aud": AUDIENCE, "exp": datetime.now(timezone.utc) + timedelta(minutes=5)}, SECRET, algorithm="HS256")


def headers(scope="repo:analyze analysis:read job:read", tenant=TENANT):
    return {"Authorization": f"Bearer {token(tenant=tenant, scope=scope)}", "Idempotency-Key": "analysis-key-000001"}


def test_analysis_worker_diff_and_reads(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        response = client.post(f"/v1/installations/1/repositories/{REPOSITORY}/analyses", headers=headers(), json={"base_sha": BASE, "head_sha": HEAD, "capability_profile": "openapi31-typescript-v1"})
        assert response.status_code == 202, response.text
        analysis = response.json()
        for _ in range(30):
            detail = client.get(f"/v1/analyses/{analysis['id']}", headers=headers()).json()
            if detail["status"] == "SUCCEEDED": break
            time.sleep(0.02)
        assert detail["finding_count"] == 1
        findings = client.get(f"/v1/analyses/{analysis['id']}/findings", headers=headers()).json()
        assert findings["items"][0]["rule_id"] == "REQUIRED_RESPONSE_FIELD_ADDED"
        job = client.get(f"/v1/jobs/{analysis['job_id']}", headers=headers()).json()
        assert job["state"] == "SUCCEEDED"


def test_idempotency_conflict_and_replay(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        h = headers()
        body = {"base_sha": BASE, "head_sha": HEAD, "capability_profile": "p"}
        first = client.post(f"/v1/installations/1/repositories/{REPOSITORY}/analyses", headers=h, json=body)
        replay = client.post(f"/v1/installations/1/repositories/{REPOSITORY}/analyses", headers=h, json=body)
        conflict = client.post(f"/v1/installations/1/repositories/{REPOSITORY}/analyses", headers=h, json={**body, "head_sha": "c" * 40})
        assert first.status_code == replay.status_code == 202
        assert first.json()["id"] == replay.json()["id"]
        assert conflict.status_code == 409


def test_auth_scope_and_cross_tenant_fail_closed(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        body = {"base_sha": BASE, "head_sha": HEAD, "capability_profile": "p"}
        no_scope = client.post(f"/v1/installations/1/repositories/{REPOSITORY}/analyses", headers={"Authorization": f"Bearer {token(scope='analysis:read')}", "Idempotency-Key":"analysis-key-000002"}, json=body)
        other_tenant = client.post(f"/v1/installations/1/repositories/{REPOSITORY}/analyses", headers=headers(tenant="00000000-0000-0000-0000-000000000099"), json=body)
        assert no_scope.status_code == 403
        assert other_tenant.status_code == 403


def test_revoked_repository_rejects_new_analysis_and_replay(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        body = {"base_sha": BASE, "head_sha": HEAD, "capability_profile": "p"}
        url = f"/v1/installations/1/repositories/{REPOSITORY}/analyses"
        assert client.post(url, headers=headers(), json=body).status_code == 202
        with app.state.store.conn() as db:
            db.execute("UPDATE repositories SET permission_state='REVOKED' WHERE tenant_id=? AND id=?", (TENANT, REPOSITORY))
        replay = client.post(url, headers=headers(), json=body)
        assert replay.status_code == 403
        assert replay.json()["code"] == "REPOSITORY_ACCESS_REVOKED"



def test_findings_cursor_is_signed_and_query_bound(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        response = client.post(f"/v1/installations/1/repositories/{REPOSITORY}/analyses", headers=headers(), json={"base_sha": BASE, "head_sha": HEAD, "capability_profile": "p"})
        analysis = response.json()
        for _ in range(30):
            if client.get(f"/v1/analyses/{analysis['id']}", headers=headers()).json()["status"] == "SUCCEEDED":
                break
            time.sleep(0.02)
        with app.state.store.conn() as db:
            db.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?)", (TENANT, "22222222-2222-2222-2222-222222222222", analysis["id"], "SYNTHETIC_SECOND_FINDING", "REVIEW", "/paths/~1synthetic", "b" * 64, "BOUNDED"))
        first = client.get(f"/v1/analyses/{analysis['id']}/findings?limit=1", headers=headers())
        cursor = first.json()["next_cursor"]
        assert first.status_code == 200 and cursor
        tampered = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
        assert client.get(f"/v1/analyses/{analysis['id']}/findings?cursor={tampered}&limit=1", headers=headers()).json()["code"] == "INVALID_CURSOR"
        assert client.get(f"/v1/analyses/{analysis['id']}/findings?cursor={cursor}&limit=2", headers=headers()).json()["code"] == "INVALID_CURSOR"
