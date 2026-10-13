from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from apishield_agent.application.analysis_worker import AnalysisWorker
from apishield_agent.infrastructure.store import Store, TENANT, USER, REPOSITORY
from apishield_agent.main import create_app
from test_hardening import headers

ROOT = Path(__file__).resolve().parents[2]


def prepare(store):
    row=store.create_analysis(TENANT,USER,REPOSITORY,'a'*40,'b'*40,'p','approval-source-key-001','request')
    assert AnalysisWorker(store).run_once()
    return store.create_proposal(TENANT,row['id'],'typescript')


def test_independent_store_approval_commands_have_one_winner(tmp_path):
    path=str(tmp_path/'db.sqlite')
    store=Store(path)
    store.seed_demo(str(ROOT/'fixtures/golden/before.yaml'),str(ROOT/'fixtures/golden/after.yaml'))
    p=prepare(store)
    peers=[Store(path),Store(path)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda i:peers[i].approve(TENANT,p['id'],p['patch_sha256'],p['base_sha'],'approve',1,USER)[1],range(2)))
    assert results.count(None)==1 and results.count('STALE_VERSION')==1
    with store.conn() as db:
        assert db.execute('SELECT count(*) FROM approvals WHERE proposal_id=?',(p['id'],)).fetchone()[0]==1


def test_approval_replay_is_proposal_bound_and_revocation_checked(tmp_path):
    app=create_app(str(tmp_path/'db.sqlite'),seed=True)
    p=prepare(app.state.store)
    other=app.state.store.create_proposal(TENANT,p['analysis_id'],'typescript')
    body={'patch_sha256':p['patch_sha256'],'base_sha':p['base_sha'],'decision':'approve','expected_version':1}
    key=headers('patch:approve','approval-replay-key-001')
    with TestClient(app) as client:
        url=f"/v1/proposals/{p['id']}/approvals"
        assert client.post(url,headers=key,json=body).status_code==201
        replay=client.post(f"/v1/proposals/{other['id']}/approvals",headers=key,json=body)
        assert replay.status_code==409 and replay.json()['code']=='IDEMPOTENCY_CONFLICT'
        with app.state.store.conn() as db:
            db.execute("UPDATE repositories SET permission_state='REVOKED' WHERE tenant_id=? AND id=?",(TENANT,REPOSITORY))
        assert client.post(url,headers=key,json=body).status_code==403
        row,error=app.state.store.approve(TENANT,other['id'],other['patch_sha256'],other['base_sha'],'approve',1,USER)
        assert error=='REPOSITORY_ACCESS_REVOKED'


def test_approval_rejects_changed_base_sha_without_recording_approval(tmp_path):
    store = Store(str(tmp_path / 'db.sqlite'))
    store.seed_demo(str(ROOT / 'fixtures/golden/before.yaml'), str(ROOT / 'fixtures/golden/after.yaml'))
    proposal = prepare(store)

    row, error = store.approve(
        TENANT, proposal['id'], proposal['patch_sha256'], 'c' * 40,
        'approve', 1, USER,
    )

    assert row['id'] == proposal['id']
    assert error == 'STALE_ARTIFACT'
    with store.conn() as db:
        assert db.execute('SELECT count(*) FROM approvals WHERE proposal_id=?', (proposal['id'],)).fetchone()[0] == 0


def test_revoked_approved_proposal_cannot_be_authorized_for_write(tmp_path):
    store = Store(str(tmp_path / 'db.sqlite'))
    store.seed_demo(str(ROOT / 'fixtures/golden/before.yaml'), str(ROOT / 'fixtures/golden/after.yaml'))
    proposal = prepare(store)
    approval, error = store.approve(
        TENANT, proposal['id'], proposal['patch_sha256'], proposal['base_sha'],
        'approve', 1, USER,
    )
    assert error is None and approval['status'] == 'APPROVED'

    with store.conn() as db:
        db.execute("UPDATE repositories SET permission_state='REVOKED' WHERE tenant_id=? AND id=?", (TENANT, REPOSITORY))

    with pytest.raises(ValueError, match='REPOSITORY_ACCESS_REVOKED'):
        store.authorized_patch_bytes(TENANT, proposal['id'])


def test_artifact_commit_replay_is_resource_bound(tmp_path):
    import hashlib
    app=create_app(str(tmp_path/'db.sqlite'),seed=True)
    content=(ROOT/'fixtures/golden/before.yaml').read_bytes()
    sha=hashlib.sha256(content).hexdigest()
    with TestClient(app) as client:
        intent=client.post('/v1/artifacts/upload-intents',headers=headers('artifact:create','binding-upload-key-001'),json={'kind':'contract','filename':'synthetic.yaml','size_bytes':len(content),'sha256':sha}).json()
        uploaded=client.put(intent['upload_url'],content=content)
        body={'sha256':sha,'size_bytes':len(content),'object_generation':uploaded.json()['object_generation']}
        key=headers('artifact:commit','binding-commit-key-001')
        assert client.post(f"/v1/artifacts/{intent['artifact_id']}/commit",headers=key,json=body).status_code==202
        result=client.post('/v1/artifacts/33333333-3333-3333-3333-333333333333/commit',headers=key,json=body)
        assert result.status_code==409 and result.json()['code']=='IDEMPOTENCY_CONFLICT'


def test_invalid_git_sha_length_is_rejected(tmp_path):
    app=create_app(str(tmp_path/'db.sqlite'),seed=True)
    with TestClient(app) as client:
        result=client.post(f'/v1/installations/1/repositories/{REPOSITORY}/analyses',headers=headers('repo:analyze','invalid-sha-key-001'),json={'base_sha':'a'*41,'head_sha':'b'*40,'capability_profile':'p'})
        assert result.status_code==422
