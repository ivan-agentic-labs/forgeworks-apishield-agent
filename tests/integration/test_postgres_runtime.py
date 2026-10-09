"""Runs only against an explicitly opted-in disposable localhost PostgreSQL instance."""
import os
import hashlib
import hmac
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from apishield_agent.infrastructure.postgres_store import PostgresStore, ROLE
from apishield_agent.infrastructure.store import TENANT, USER, REPOSITORY
from apishield_agent.main import create_app
from test_hardening import headers

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def postgres(monkeypatch):
    owner = os.getenv('APISHIELD_DISPOSABLE_OWNER_DSN')
    if not owner:
        pytest.skip('Disposable PostgreSQL is unavailable; this is NOT a runtime pass')
    from psycopg.conninfo import conninfo_to_dict
    info=conninfo_to_dict(owner)
    if os.getenv('G1_DISPOSABLE_DB')!='yes' or info.get('host') not in {'127.0.0.1','localhost'} or info.get('dbname')!='forgeworks_runtime':
        pytest.fail('Refusing non-disposable PostgreSQL configuration')
    with psycopg.connect(owner) as db:
        # The CI service is fresh and dedicated. Never drop an existing schema.
        if db.execute("SELECT to_regclass('analysis_jobs')").fetchone()[0]:
            pytest.fail('Runtime proof requires a fresh empty database')
        for name in ['001_apishield_mvp.sql','002_apishield_runtime.sql','003_github_webhook_inbox.sql','004_analysis_source_snapshots.sql']:
            db.execute((ROOT/'migrations/versions'/name).read_text())
        db.execute("CREATE ROLE fw_runtime_test LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'synthetic-local-runtime-test-only'")
        db.execute("CREATE ROLE fw_webhook_test LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'synthetic-local-webhook-test-only'")
        db.execute('GRANT fw_apishield_agent_rw TO fw_runtime_test')
        db.execute('GRANT fw_apishield_webhook TO fw_webhook_test')
        db.execute('INSERT INTO tenants VALUES (%s,%s,%s)',(TENANT,'synthetic-demo','ACTIVE'))
        db.execute('INSERT INTO memberships VALUES (%s,%s,%s,%s)',(TENANT,USER,'editor','ACTIVE'))
        db.execute('INSERT INTO repositories VALUES (%s,%s,%s,%s,%s,%s,%s)',(TENANT,REPOSITORY,1,'main','READ',str(ROOT/'fixtures/golden/before.yaml'),str(ROOT/'fixtures/golden/after.yaml')))
        other=str(uuid4())
        db.execute('INSERT INTO tenants VALUES (%s,%s,%s)',(other,'synthetic-other','ACTIVE'))
        db.execute('INSERT INTO repositories VALUES (%s,%s,%s,%s,%s,%s,%s)',(other,str(uuid4()),1,'main','READ','',''))
    info.update(user='fw_runtime_test',password='synthetic-local-runtime-test-only')
    from psycopg.conninfo import make_conninfo
    runtime=make_conninfo(**info)
    info.update(user='fw_webhook_test',password='synthetic-local-webhook-test-only')
    webhook=make_conninfo(**info)
    monkeypatch.setenv('APISHIELD_WORKER_TENANTS',TENANT)
    return owner,runtime,webhook,other


def test_actual_postgres_api_worker_and_full_rls_boundaries(postgres, monkeypatch,tmp_path):
    owner,runtime,webhook,other=postgres
    with pytest.raises(ValueError,match='superuser'):
        PostgresStore(owner)
    store=PostgresStore(runtime)
    assert not store.member(TENANT, "unmapped-oidc-subject")
    # Runtime login and its group cannot own tenant/provisioning tables either.
    for table, new_owner in [('memberships','fw_runtime_test'),('tenants',ROLE)]:
        with psycopg.connect(owner) as db:
            db.execute(psycopg.sql.SQL('ALTER TABLE {} OWNER TO {}').format(psycopg.sql.Identifier(table),psycopg.sql.Identifier(new_owner)))
        try:
            with pytest.raises(ValueError,match='own product tables'):
                PostgresStore(runtime)
        finally:
            with psycopg.connect(owner) as db:
                db.execute(psycopg.sql.SQL('ALTER TABLE {} OWNER TO postgres').format(psycopg.sql.Identifier(table)))
                db.execute(psycopg.sql.SQL('REVOKE ALL ON {} FROM {}').format(psycopg.sql.Identifier(table),psycopg.sql.Identifier(new_owner)))

    with pytest.raises(ValueError,match='tenant context'):
        with store.conn():
            pass
    # Missing context defaults to deny, on a real non-owner connection.
    with psycopg.connect(runtime) as db:
        db.execute('SET LOCAL ROLE fw_apishield_agent_rw')
        assert db.execute('SELECT count(*) FROM repositories').fetchone()[0]==0
    with store.conn(TENANT) as db:
        assert len(db.execute('SELECT * FROM repositories').fetchall())==1
        assert db.execute('UPDATE repositories SET default_branch=? WHERE tenant_id=?',('changed',other)).rowcount==0
        assert db.execute('DELETE FROM repositories WHERE tenant_id=?',(other,)).rowcount==0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute('INSERT INTO repositories(tenant_id,id,installation_id,default_branch,permission_state) VALUES(?,?,?,?,?)',(other,str(uuid4()),1,'main','READ'))
    # Fresh context in a separate transaction can see only its own tenant.
    with store.conn(other) as db:
        assert len(db.execute('SELECT * FROM repositories').fetchall())==1
    monkeypatch.setenv('APISHIELD_DATABASE_URL',runtime)
    monkeypatch.setenv('APISHIELD_GITHUB_WEBHOOK_DATABASE_URL',webhook)
    monkeypatch.setenv('GITHUB_WEBHOOK_SECRET','synthetic-postgres-webhook-secret-32-bytes')
    with TestClient(create_app(str(tmp_path/'unused.sqlite'))) as client:
        result=client.post(f'/v1/installations/1/repositories/{REPOSITORY}/analyses',headers=headers('repo:analyze','pg-analysis-key-001'),json={'base_sha':'a'*40,'head_sha':'b'*40,'capability_profile':'openapi31-typescript-v1'})
        assert result.status_code==202,result.text
        aid=result.json()['id']
        for _ in range(100):
            detail=client.get(f'/v1/analyses/{aid}',headers=headers('analysis:read','pg-read-key-00001'))
            if detail.json().get('status')=='SUCCEEDED':break
            time.sleep(.05)
        assert detail.json()['status']=='SUCCEEDED',detail.text
        findings=client.get(f'/v1/analyses/{aid}/findings',headers=headers('analysis:read','pg-read-key-00002'))
        assert findings.status_code==200 and findings.json()['items']
        proposal=client.post(f'/v1/analyses/{aid}/proposals',headers=headers('patch:create','pg-proposal-key-001'),json={'analysis_id':aid,'target_language':'typescript'})
        assert proposal.status_code==201,proposal.text
        proposed=proposal.json()
        patch=client.get(f"/v1/proposals/{proposed['id']}/patch",headers=headers('patch:read','pg-patch-read-00001'))
        assert patch.status_code==200 and hashlib.sha256(patch.content).hexdigest()==proposed['patch_sha256']
        approved=client.post(f"/v1/proposals/{proposed['id']}/approvals",headers=headers('patch:approve','pg-approve-key-001'),json={'patch_sha256':proposed['patch_sha256'],'base_sha':'a'*40,'decision':'approve','expected_version':1})
        assert approved.status_code==201,approved.text
        blocked=client.post(f"/v1/proposals/{proposed['id']}/pull-requests",headers=headers('github:write','pg-github-key-001'),json={'approval_id':approved.json()['id'],'target_branch':'main'})
        assert blocked.status_code==403 and blocked.json()['code']=='GITHUB_WRITE_DISABLED'
        content=(ROOT/'fixtures/golden/before.yaml').read_bytes()
        digest=hashlib.sha256(content).hexdigest()
        created=client.post('/v1/artifacts/upload-intents',headers=headers('artifact:create','pg-artifact-key-001'),json={'kind':'contract','filename':'synthetic.yaml','size_bytes':len(content),'sha256':digest})
        assert created.status_code==201,created.text
        intent=created.json();artifact_id=intent['artifact_id']
        uploaded=client.put(intent['upload_url'],content=content)
        assert uploaded.status_code==201,uploaded.text
        committed=client.post(f'/v1/artifacts/{artifact_id}/commit',headers=headers('artifact:commit','pg-artifact-commit-01'),json={'sha256':digest,'size_bytes':len(content),'object_generation':uploaded.json()['object_generation']})
        assert committed.status_code==202 and committed.json()['status']=='AVAILABLE',committed.text
        download=client.post(f'/v1/artifacts/{artifact_id}/download-intents',headers=headers('artifact:download','pg-artifact-read-001'))
        response=client.get(download.json()['download_url'])
        assert response.status_code==200 and response.content==content

        webhook_body=json.dumps({'action':'suspend','installation':{'id':1}},separators=(',',':')).encode()
        signature=hmac.new(os.environ['GITHUB_WEBHOOK_SECRET'].encode(),webhook_body,hashlib.sha256).hexdigest()
        hook=client.post('/internal/github/webhooks',content=webhook_body,headers={'X-Hub-Signature-256':f'sha256={signature}','X-GitHub-Delivery':str(uuid4()),'X-GitHub-Event':'installation'})
        assert hook.status_code==202 and hook.json()['installation_state']=='SUSPENDED',hook.text
        revoked=client.post(f'/v1/installations/1/repositories/{REPOSITORY}/analyses',headers=headers('repo:analyze','pg-revoked-key-001'),json={'base_sha':'a'*40,'head_sha':'b'*40,'capability_profile':'p'})
        assert revoked.status_code==403 and revoked.json()['code']=='REPOSITORY_ACCESS_REVOKED'
        revoked_proposal=client.post(f"/v1/analyses/{aid}/proposals",headers=headers('patch:create','pg-revoked-proposal-001'),json={'analysis_id':aid,'target_language':'typescript'})
        assert revoked_proposal.status_code==403,revoked_proposal.text
        with psycopg.connect(owner) as db:
            assert db.execute('SELECT permission_state FROM repositories WHERE tenant_id=%s AND id=%s',(TENANT,REPOSITORY)).fetchone()[0]=='REVOKED'
            assert db.execute('SELECT count(*) FROM github_webhook_deliveries').fetchone()[0]==1

    # Explicit fixture re-provisioning for independent concurrency tests below.
    # A received unsuspend event does not automatically re-grant product access.
    with psycopg.connect(owner) as db:
        db.execute("UPDATE repositories SET permission_state='READ' WHERE tenant_id=%s AND id=%s",(TENANT,REPOSITORY))

    # Two independent adapters must converge on one durable analysis/lease.
    peers=[PostgresStore(runtime),PostgresStore(runtime)]
    def submit(index):
        return peers[index%2].create_analysis(TENANT,USER,REPOSITORY,'a'*40,'b'*40,'p','pg-concurrent-key-001','request')['id']
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert len(set(pool.map(submit,range(8))))==1
    with ThreadPoolExecutor(max_workers=2) as pool:
        leases=list(pool.map(lambda peer:peer.claim_pending(),peers))
    assert sum(row is not None for row in leases)==1
    lease=next(row for row in leases if row is not None)
    assert store.finish(TENANT,lease['id'],[],lease['lease_token'],source_bytes=((ROOT/'fixtures/golden/before.yaml').read_bytes(),(ROOT/'fixtures/golden/after.yaml').read_bytes()))
    proposal=store.create_proposal(TENANT,lease['id'],'typescript')
    def approve(index):
        return peers[index].approve(TENANT,proposal['id'],proposal['patch_sha256'],proposal['base_sha'],'approve',1,USER)[1]
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes=list(pool.map(approve,range(2)))
    assert outcomes.count(None)==1 and outcomes.count('STALE_VERSION')==1
    with store.conn(TENANT) as db:
        assert db.execute('SELECT count(*) FROM approvals WHERE proposal_id=?',(proposal['id'],)).fetchone()[0]==1
        assert db.execute('SELECT count(*) FROM analysis_source_snapshots').fetchone()[0]>=2
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            db.execute("UPDATE analysis_source_snapshots SET before_base64='tampered'")
    with store.conn(other) as db:
        assert db.execute('SELECT count(*) FROM analysis_source_snapshots').fetchone()[0]==0
