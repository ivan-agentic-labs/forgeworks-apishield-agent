import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from apishield_agent.infrastructure.store import REPOSITORY, TENANT, USER, Store
from apishield_agent.main import create_app

SECRET = "forgeworks-development-secret-32-plus"
ISSUER = "https://issuer.synthetic.invalid"
AUDIENCE = "forgeworks-api"
BASE = "a" * 40
HEAD = "b" * 40


def headers(scope, key):
    token = jwt.encode(
        {"sub": USER, "tenant_id": TENANT, "scope": scope, "iss": ISSUER, "aud": AUDIENCE,
         "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
        SECRET,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}", "Idempotency-Key": key}


def test_worker_lease_fences_stale_job(tmp_path):
    store = Store(str(tmp_path / "db.sqlite"))
    store.seed_demo("before.yaml", "after.yaml")
    row = store.create_analysis(TENANT, USER, REPOSITORY, BASE, HEAD, "p", "lease-key-000001", "request")
    with store.lock, store.conn() as db:
        db.execute("UPDATE analyses SET status='RUNNING', lease_until=? WHERE tenant_id=? AND id=?", ("2000-01-01T00:00:00Z", TENANT, row["id"]))
    assert store.claim_pending() is None
    assert store.get_analysis(TENANT, row["id"])["status"] == "FAILED_TERMINAL"
    assert store.get_analysis(TENANT, row["id"])["last_error_code"] == "STALE_LEASE"


def test_proposal_approval_idempotency_stale_version_and_artifact_digest(tmp_path):
    with TestClient(create_app(str(tmp_path / "db.sqlite"), seed=True)) as client:
        analysis = client.post(
            f"/v1/installations/1/repositories/{REPOSITORY}/analyses",
            headers=headers("repo:analyze analysis:read job:read", "analysis-key-000010"),
            json={"base_sha": BASE, "head_sha": HEAD, "capability_profile": "p"},
        ).json()
        for _ in range(100):
            detail = client.get(f"/v1/analyses/{analysis['id']}", headers=headers("analysis:read", "read-key-000010")).json()
            if detail["status"] == "SUCCEEDED":
                break
            time.sleep(0.01)
        proposal_response = client.post(
            f"/v1/analyses/{analysis['id']}/proposals",
            headers=headers("patch:create", "proposal-key-000010"),
            json={"analysis_id": analysis["id"], "target_language": "typescript"},
        )
        assert proposal_response.status_code == 201
        proposal = proposal_response.json()
        approval_body = {"patch_sha256": proposal["patch_sha256"], "base_sha": BASE, "decision": "approve", "expected_version": 1}
        approval = client.post(f"/v1/proposals/{proposal['id']}/approvals", headers=headers("patch:approve", "approval-key-000010"), json=approval_body)
        assert approval.status_code == 201
        replay = client.post(f"/v1/proposals/{proposal['id']}/approvals", headers=headers("patch:approve", "approval-key-000010"), json=approval_body)
        assert replay.status_code == 201 and replay.json()["id"] == approval.json()["id"]
        stale = client.post(f"/v1/proposals/{proposal['id']}/approvals", headers=headers("patch:approve", "approval-key-000011"), json=approval_body)
        assert stale.status_code == 409 and stale.json()["code"] == "STALE_VERSION"

        digest = "a" * 64
        intent = client.post(
            "/v1/artifacts/upload-intents",
            headers=headers("artifact:create", "artifact-key-000010"),
            json={"kind": "contract", "filename": "contract.yaml", "size_bytes": 12, "sha256": digest},
        )
        assert intent.status_code == 201
        artifact_id = intent.json()["artifact_id"]
        mismatch = client.post(
            f"/v1/artifacts/{artifact_id}/commit",
            headers=headers("artifact:commit", "commit-key-000010"),
            json={"sha256": "b" * 64, "size_bytes": 12, "object_generation": "1"},
        )
        assert mismatch.status_code == 409 and mismatch.json()["code"] == "ARTIFACT_DIGEST_MISMATCH"

        github = client.post(
            f"/v1/proposals/{proposal['id']}/pull-requests",
            headers=headers("github:write", "github-key-000010"),
            json={"approval_id": approval.json()["id"], "target_branch": "main"},
        )
        assert github.status_code == 403 and github.json()["code"] == "GITHUB_WRITE_DISABLED"
