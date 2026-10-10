import hashlib
import pytest
from fastapi.testclient import TestClient
from apishield_agent.infrastructure.store import TENANT, USER, REPOSITORY
from apishield_agent.main import create_app
from apishield_agent.application.analysis_worker import AnalysisWorker


def prepare(store):
    row = store.create_analysis(TENANT, USER, REPOSITORY, "a"*40, "b"*40, "p", "patch-source-key-001", "request")
    assert AnalysisWorker(store).run_once()
    return store.create_proposal(TENANT, row["id"], "typescript")
from test_hardening import headers


@pytest.mark.parametrize('permission', ['REVOKED', 'NONE', 'SUSPENDED'])
def test_existing_patch_is_denied_after_permission_loss(tmp_path, permission):
    app = create_app(str(tmp_path/'patch.db'), seed=True)
    proposal = prepare(app.state.store)
    url = f"/v1/proposals/{proposal['id']}/patch"
    with TestClient(app) as client:
        response = client.get(url, headers=headers('patch:read','patch-read-key-0001'))
        assert response.status_code == 200
        assert response.headers['X-Patch-SHA256'] == hashlib.sha256(response.content).hexdigest()
        with app.state.store.conn() as db:
            db.execute('UPDATE repositories SET permission_state=? WHERE tenant_id=? AND id=?', (permission,TENANT,REPOSITORY))
        denied = client.get(url, headers=headers('patch:read','patch-read-key-0001'))
        assert denied.status_code == 403 and denied.json()['code'] == 'REPOSITORY_ACCESS_REVOKED'
        with pytest.raises(ValueError, match='REPOSITORY_ACCESS_REVOKED'):
            app.state.store.authorized_patch_bytes(TENANT,proposal['id'])


@pytest.mark.parametrize('mutation', ['tamper', 'delete'])
def test_patch_integrity_prevents_new_approval(tmp_path, mutation):
    app = create_app(str(tmp_path/'tamper.db'), seed=True)
    store = app.state.store
    proposal = prepare(store)
    with store.conn() as db:
        if mutation == 'tamper':
            db.execute('UPDATE proposal_patch_content SET patch_text=? WHERE tenant_id=? AND id=?', ('changed',TENANT,proposal['id']))
        else:
            db.execute('DELETE FROM proposal_patch_content WHERE tenant_id=? AND id=?', (TENANT,proposal['id']))
    with TestClient(app) as client:
        response = client.post(f"/v1/proposals/{proposal['id']}/approvals", headers=headers('patch:approve','integrity-approve-001'),
            json={'patch_sha256':proposal['patch_sha256'],'base_sha':proposal['base_sha'],'decision':'approve','expected_version':1})
        assert response.status_code == 409 and response.json()['code'] == 'PATCH_INTEGRITY_FAILURE'
    assert store.proposal(TENANT,proposal['id'])['version'] == 1
    with store.conn() as db:
        assert db.execute('SELECT count(*) FROM approvals').fetchone()[0] == 0


def test_patch_never_visible_to_other_tenant_or_without_scope(tmp_path):
    app = create_app(str(tmp_path/'tenant.db'), seed=True)
    proposal = prepare(app.state.store)
    with pytest.raises(ValueError, match='RESOURCE_NOT_FOUND'):
        app.state.store.authorized_patch_bytes('00000000-0000-0000-0000-000000000099', proposal['id'])
    with TestClient(app) as client:
        assert client.get(f"/v1/proposals/{proposal['id']}/patch", headers=headers('analysis:read','scope-read-key-0001')).status_code == 403
