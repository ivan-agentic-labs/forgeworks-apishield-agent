import hashlib
import hmac
import json
import pytest
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


@pytest.mark.parametrize("body", [
    b'{"action":"suspend","action":"created","installation":{"id":1}}',
    b'{"action":"suspend","installation":{"id":1,"id":2}}',
    b'{"action":"suspend","installation":{"id":1},"value":NaN}',
    b'{"action":"suspend","installation":{"id":1},"value":Infinity}',
    b'{"action":[],"installation":{"id":1}}',
    b'{"action":{"nested":"suspend"},"installation":{"id":1}}',
    b'{"action":"suspend","installation":{"id":true}}',
    b'{"action":"suspend","installation":{"id":false}}',
])
def test_signed_invalid_webhook_never_changes_installation_state(tmp_path, monkeypatch, body):
    """A valid HMAC never permits ambiguous JSON to change tenant revocation."""
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("APISHIELD_GITHUB_WEBHOOK_DB_PATH", str(tmp_path / "webhook.sqlite"))
    delivery = uuid4()
    signature = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    headers = {
        "X-Hub-Signature-256": "sha256=" + signature,
        "X-GitHub-Delivery": str(delivery),
        "X-GitHub-Event": "installation",
        "Content-Type": "application/json",
    }
    with TestClient(create_app(str(tmp_path / "product.sqlite"))) as client:
        rejected = client.post("/internal/github/webhooks", content=body, headers=headers)
        assert rejected.status_code == 422, rejected.text
        assert rejected.json()["code"] in {
            "INVALID_WEBHOOK_JSON", "INVALID_INSTALLATION_EVENT", "UNSUPPORTED_INSTALLATION_ACTION",
        }
        # Failed validation does not consume the delivery UUID or mutate state.
        valid_body, valid_headers = signed(
            {"action": "suspend", "installation": {"id": 1}}, delivery
        )
        accepted = client.post("/internal/github/webhooks", content=valid_body, headers=valid_headers)
        assert accepted.status_code == 202, accepted.text
        assert accepted.json()["accepted"] is True
        assert accepted.json()["installation_state"] == "SUSPENDED"


def test_excessively_nested_signed_webhook_returns_typed_422(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("APISHIELD_GITHUB_WEBHOOK_DB_PATH", str(tmp_path / "webhook.sqlite"))
    nested = b"[" * 1100 + b"0" + b"]" * 1100
    body = b'{"action":"suspend","installation":{"id":1},"nested":' + nested + b"}"
    signature = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    headers = {
        "X-Hub-Signature-256": "sha256=" + signature,
        "X-GitHub-Delivery": str(uuid4()),
        "X-GitHub-Event": "installation",
    }
    with TestClient(create_app(str(tmp_path / "product.sqlite"))) as client:
        result = client.post("/internal/github/webhooks", content=body, headers=headers)
        assert result.status_code == 422, result.text
        assert result.json()["code"] == "INVALID_WEBHOOK_JSON"
