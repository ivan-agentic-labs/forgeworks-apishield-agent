"""Public console configuration must never disclose a privileged API key."""
from fastapi.testclient import TestClient
from apishield_agent.main import create_app


def test_public_login_config_and_console(tmp_path,monkeypatch):
    monkeypatch.setenv("SUPABASE_PUBLISHABLE_KEY","sb_secret_misconfigured")
    app=create_app(str(tmp_path/"console.db"),seed=True)
    with TestClient(app) as client:
        value=client.get("/v1/auth/config").json()
        assert value["publishable_key"]=="" and value["enabled"] is False
        assert "sb_secret" not in str(value)
        assert client.get("/").status_code==200
        assert client.get('/ui/'+"auth-panel.js").status_code==200
        monkeypatch.setenv("AUTH_MODE","supabase")
        monkeypatch.setenv("SUPABASE_PUBLISHABLE_KEY","sb_publishable_synthetic")
        value=client.get("/v1/auth/config").json()
        assert value["enabled"] is True
        assert value["publishable_key"]=="sb_publishable_synthetic"


def test_cursor_rejects_alternative_base64_spelling(monkeypatch):
    import base64
    import pytest
    from apishield_agent.main import _encode_cursor, _decode_cursor
    monkeypatch.setenv("APISHIELD_CURSOR_SECRET","synthetic-cursor-signing-secret-32-bytes")
    canonical=_encode_cursor("tenant","analysis",1,0)
    raw=base64.urlsafe_b64decode(canonical+"="*(-len(canonical)%4))
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    alternatives=[canonical[:-1]+letter for letter in alphabet if letter!=canonical[-1]]
    alias=next(value for value in alternatives if base64.urlsafe_b64decode(value+"="*(-len(value)%4))==raw)
    with pytest.raises(ValueError,match="noncanonical"):
        _decode_cursor(alias,"tenant","analysis",1)
