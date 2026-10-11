"""Synthetic HTTP regression: a signed URL cannot bypass revocation."""
import hashlib
from uuid import uuid4
from urllib.parse import parse_qs, urlsplit

import jwt
from fastapi.testclient import TestClient

from apishield_agent.main import create_app
from apishield_agent.infrastructure.store import TENANT, USER
from test_hardening import headers


def make_intent(client, content, suffix):
    return client.post(
        "/v1/artifacts/upload-intents",
        headers=headers("artifact:create", "revocation-create-" + suffix),
        json={"kind": "contract", "filename": "synthetic.yaml",
              "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()},
    ).json()


def committed_download(client, suffix):
    content = b'openapi: 3.1.0\ninfo: {title: Synthetic, version: "1"}\npaths: {}\n'
    created = make_intent(client, content, suffix)
    assert client.put(created["upload_url"], content=content).status_code == 201
    aid = created["artifact_id"]
    uploaded = client.put(created["upload_url"], content=content).json()
    committed = client.post(
        f"/v1/artifacts/{aid}/commit",
        headers=headers("artifact:commit", "revocation-commit-" + suffix),
        json={"sha256": hashlib.sha256(content).hexdigest(),
              "size_bytes": len(content), "object_generation": uploaded["object_generation"]},
    )
    assert committed.status_code == 202, committed.text
    issued = client.post(
        f"/v1/artifacts/{aid}/download-intents",
        headers=headers("artifact:download", "revocation-download-" + suffix),
    )
    assert issued.status_code == 201, issued.text
    return issued.json()["download_url"], content


def test_signed_download_and_upload_capabilities_are_invalid_after_membership_revocation(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        download, expected = committed_download(client, "a")
        assert client.get(download).content == expected
        pending = make_intent(client, b"synthetic pending", "b")
        with app.state.store.conn() as db:
            db.execute("UPDATE memberships SET status='REVOKED' WHERE tenant_id=? AND user_id=?", (TENANT, USER))
        downloaded = client.get(download)
        assert downloaded.status_code == 403
        assert downloaded.json()["code"] == "MEMBERSHIP_REVOKED"
        uploaded = client.put(pending["upload_url"], content=b"synthetic pending")
        assert uploaded.status_code == 403
        assert uploaded.json()["code"] == "MEMBERSHIP_REVOKED"


def test_unsigned_or_legacy_ownerless_capability_cannot_be_reused(tmp_path):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    with TestClient(app) as client:
        issued = make_intent(client, b"synthetic", "legacy")
        url = issued["upload_url"]
        token = parse_qs(urlsplit(url).query)["token"][0]
        payload = jwt.decode(
            token, app.state.artifacts.secret(), algorithms=["HS256"],
            audience="artifact-transfer", issuer="forgeworks-artifacts",
        )
        assert payload["actor"] == USER
        payload.pop("actor")
        forged = jwt.encode(payload, app.state.artifacts.secret(), algorithm="HS256")
        response = client.put(url.split("?")[0] + "?token=" + forged, content=b"synthetic")
        assert response.status_code == 403
        assert response.json()["code"] == "INVALID_ARTIFACT_CAPABILITY"


def test_supabase_signed_transfer_session_is_rechecked_online(tmp_path, monkeypatch):
    app = create_app(str(tmp_path / "db.sqlite"), seed=True)
    store = app.state.store
    session_id = str(uuid4())
    # Staging requires session-bound capability, and checks revocation at use.
    with TestClient(app) as client:
        issued = make_intent(client, b"synthetic", "session")
        token = parse_qs(urlsplit(issued["upload_url"]).query)["token"][0]
        claims = jwt.decode(token, app.state.artifacts.secret(), algorithms=["HS256"],
                            audience="artifact-transfer", issuer="forgeworks-artifacts")
        claims["session_id"] = session_id
        patched = jwt.encode(claims, app.state.artifacts.secret(), algorithm="HS256")
        url = issued["upload_url"].split("?")[0] + "?token=" + patched
        monkeypatch.setenv("AUTH_MODE", "supabase")
        monkeypatch.setattr(store, "session_active", lambda tenant, actor, sid: False, raising=False)
        denied = client.put(url, content=b"synthetic")
        assert denied.status_code == 401 and denied.json()["code"] == "SESSION_REVOKED"
        monkeypatch.setattr(store, "session_active", lambda tenant, actor, sid: True)
        accepted = client.put(url, content=b"synthetic")
        assert accepted.status_code == 201, accepted.text
        without_sid = client.put(issued["upload_url"], content=b"synthetic")
        assert without_sid.status_code == 403
        assert without_sid.json()["code"] == "ARTIFACT_SESSION_REQUIRED"
