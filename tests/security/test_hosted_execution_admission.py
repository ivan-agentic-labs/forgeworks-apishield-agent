"""Synthetic admission tests; these do not assert a live GitHub App exists."""
from types import SimpleNamespace

import pytest

from apishield_agent.application.execution_readiness import hosted_execution_error


@pytest.mark.parametrize('environment', ['staging', 'production'])
def test_hosted_missing_execution_path_rejects_queue_admission(monkeypatch, environment):
    monkeypatch.setenv('APP_ENV', environment)
    store = SimpleNamespace(worker_tenants=lambda: ['tenant-a'])
    assert hosted_execution_error('tenant-a', store, None) == 'SOURCE_PROVIDER_NOT_CONFIGURED'
    monkeypatch.setenv('APISHIELD_EMBEDDED_WORKER', '0')
    assert hosted_execution_error('tenant-a', store, object()) == 'WORKER_NOT_AVAILABLE'
    monkeypatch.setenv('APISHIELD_EMBEDDED_WORKER', '1')
    assert hosted_execution_error('tenant-b', store, object()) == 'TENANT_WORKER_NOT_ENROLLED'
    assert hosted_execution_error('tenant-a', store, object()) is None


def test_invalid_worker_configuration_is_not_queue_readiness(monkeypatch):
    monkeypatch.setenv('APP_ENV', 'staging')
    monkeypatch.setenv('APISHIELD_EMBEDDED_WORKER', '1')
    def malformed():
        raise ValueError('sensitive configuration')
    assert hosted_execution_error('tenant-a', SimpleNamespace(worker_tenants=malformed), object()) == 'WORKER_CONFIGURATION_INVALID'


def test_development_fixture_execution_still_allowed(monkeypatch):
    monkeypatch.setenv('APP_ENV', 'test')
    assert hosted_execution_error('synthetic-tenant', object(), None) is None


def test_http_unconfigured_hosted_write_is_not_accepted_or_persisted(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from apishield_agent.main import create_app
    from apishield_agent.presentation.auth import claims
    from apishield_agent.infrastructure.store import TENANT, USER, REPOSITORY
    import sqlite3

    monkeypatch.setenv('APP_ENV', 'test')
    monkeypatch.setenv('AUTH_MODE', 'development')
    monkeypatch.setenv('AUTH_ISSUER', 'https://issuer.synthetic.invalid')
    monkeypatch.setenv('AUTH_AUDIENCE', 'synthetic-admission')
    monkeypatch.setenv('DEV_AUTH_SECRET', 'synthetic-development-only-' * 2)
    monkeypatch.setenv('ARTIFACT_SIGNING_SECRET', 'synthetic-artifact-only-' * 2)
    monkeypatch.setenv('APISHIELD_EMBEDDED_WORKER', '0')
    monkeypatch.delenv('APISHIELD_DATABASE_URL', raising=False)
    monkeypatch.delenv('APISHIELD_GITHUB_READS_ENABLED', raising=False)
    path = tmp_path / 'admission.sqlite'
    app = create_app(str(path), seed=True)
    # This is a mocked CI identity, explicitly not a hosted authentication proof.
    app.dependency_overrides[claims] = lambda: {'tenant_id': TENANT, 'sub': USER, 'scope': 'repo:analyze'}
    endpoint = f'/v1/installations/1/repositories/{REPOSITORY}/analyses'
    payload = {'base_sha': 'a' * 40, 'head_sha': 'b' * 40, 'capability_profile': 'synthetic'}
    with TestClient(app) as client:
        monkeypatch.setenv('APP_ENV', 'staging')
        response = client.post(endpoint, json=payload, headers={'Idempotency-Key': 'hosted-not-ready-001'})
        assert response.status_code == 503
        assert response.json()['code'] == 'SOURCE_PROVIDER_NOT_CONFIGURED'
        with sqlite3.connect(path) as db:
            assert db.execute('SELECT count(*) FROM analyses').fetchone()[0] == 0
        # A durable earlier command remains replayable after readiness changes.
        monkeypatch.setenv('APP_ENV', 'test')
        original = client.post(endpoint, json=payload, headers={'Idempotency-Key': 'earlier-command-001'})
        assert original.status_code == 202
        monkeypatch.setenv('APP_ENV', 'staging')
        replay = client.post(endpoint, json=payload, headers={'Idempotency-Key': 'earlier-command-001'})
        assert replay.status_code == 202
        assert replay.json()['id'] == original.json()['id']
