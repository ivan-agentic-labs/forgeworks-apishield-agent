import hashlib
import hmac
import json
from uuid import uuid4

from fastapi.testclient import TestClient

from apishield_agent.main import create_app


SECRET = "synthetic-github-webhook-secret-32-bytes-minimum"


def signed(payload: dict, delivery=None, event="installation"):
    body = json.dumps(payload, separators=(",", ":")).encode()
    signature = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return body, {
        "X-Hub-Signature-256": f"sha256={signature}",
        "X-GitHub-Delivery": str(delivery or uuid4()),
        "X-GitHub-Event": event,
        "Content-Type": "application/json",
    }


def test_verified_installation_revocation_and_exact_replay(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("APISHIELD_GITHUB_WEBHOOK_DB_PATH", str(tmp_path / "webhooks.sqlite"))
    with TestClient(create_app(str(tmp_path / "app.sqlite"), seed=True)) as client:
        delivery = uuid4()
        body, headers = signed({"action": "suspend", "installation": {"id": 1}}, delivery)
        first = client.post("/internal/github/webhooks", content=body, headers=headers)
        replay = client.post("/internal/github/webhooks", content=body, headers=headers)
        assert first.status_code == 202
        assert first.json() == {"delivery_id": str(delivery), "accepted": True, "installation_state": "SUSPENDED"}
        assert replay.status_code == 202
        assert replay.json()["accepted"] is False
        assert replay.json()["installation_state"] == "SUSPENDED"


def test_webhook_fails_closed_on_tamper_conflict_and_unsupported_action(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("APISHIELD_GITHUB_WEBHOOK_DB_PATH", str(tmp_path / "webhooks.sqlite"))
    with TestClient(create_app(str(tmp_path / "app.sqlite"))) as client:
        delivery = uuid4()
        body, headers = signed({"action": "deleted", "installation": {"id": 7}}, delivery)
        tampered = client.post("/internal/github/webhooks", content=body + b" ", headers=headers)
        assert tampered.status_code == 401
        assert tampered.json()["code"] == "INVALID_WEBHOOK_SIGNATURE"

        assert client.post("/internal/github/webhooks", content=body, headers=headers).status_code == 202
        changed, changed_headers = signed({"action": "suspend", "installation": {"id": 7}}, delivery)
        conflict = client.post("/internal/github/webhooks", content=changed, headers=changed_headers)
        assert conflict.status_code == 409
        assert conflict.json()["code"] == "WEBHOOK_REPLAY_CONFLICT"

        unsupported, unsupported_headers = signed({"action": "transfer", "installation": {"id": 7}})
        rejected = client.post("/internal/github/webhooks", content=unsupported, headers=unsupported_headers)
        assert rejected.status_code == 422
        assert rejected.json()["code"] == "UNSUPPORTED_INSTALLATION_ACTION"


def test_webhook_requires_dedicated_configuration_and_bounded_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    monkeypatch.delenv("APISHIELD_GITHUB_WEBHOOK_DB_PATH", raising=False)
    monkeypatch.delenv("APISHIELD_GITHUB_WEBHOOK_DATABASE_URL", raising=False)
    with TestClient(create_app(str(tmp_path / "app.sqlite"))) as client:
        body, headers = signed({"zen": "synthetic"}, event="ping")
        missing = client.post("/internal/github/webhooks", content=body, headers=headers)
        assert missing.status_code == 503
        assert missing.json()["code"] == "WEBHOOK_NOT_CONFIGURED"

    monkeypatch.setenv("APISHIELD_GITHUB_WEBHOOK_DB_PATH", str(tmp_path / "webhooks.sqlite"))
    with TestClient(create_app(str(tmp_path / "second.sqlite"))) as client:
        oversized = b"x" * (1024 * 1024 + 1)
        headers = {
            "X-Hub-Signature-256": "sha256=" + "0" * 64,
            "X-GitHub-Delivery": str(uuid4()),
            "X-GitHub-Event": "ping",
        }
        response = client.post("/internal/github/webhooks", content=oversized, headers=headers)
        assert response.status_code == 413
        assert response.json()["code"] == "WEBHOOK_TOO_LARGE"
