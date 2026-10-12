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
        db.execute((ROOT/'infra/environments/staging/003_fk_lookup_index.sql').read_text())
        definition = db.execute("SELECT pg_get_indexdef('idx_analysis_jobs_tenant_repository'::regclass)").fetchone()[0]
        assert 'analysis_jobs USING btree (tenant_id, repository_id)' in definition
        db.execute((ROOT/'infra/environments/staging/004_tenant_rls_initplan.sql').read_text())
        policy = db.execute("SELECT qual, with_check FROM pg_policies WHERE schemaname=current_schema() AND tablename='repositories' AND policyname='repositories_tenant'").fetchone()
        assert policy and all('SELECT current_setting' in expression for expression in policy)
        db.execute((ROOT/'infra/environments/staging/005_drop_duplicate_runtime_policies.sql').read_text())
        db.execute((ROOT/'infra/environments/staging/006_remaining_tenant_rls_initplans.sql').read_text())
        for table, policy_name, role in [['analysis_findings','analysis_findings_tenant','public'],['analysis_jobs','analysis_jobs_tenant','public'],['analysis_source_snapshots','tenant_boundary','public'],['approvals','runtime_tenant','fw_apishield_agent_rw'],['artifacts','runtime_tenant','fw_apishield_agent_rw'],['audit_events','runtime_tenant','fw_apishield_agent_rw'],['commands','runtime_tenant','fw_apishield_agent_rw'],['idempotency','runtime_tenant','fw_apishield_agent_rw'],['memberships','runtime_tenant','fw_apishield_agent_rw'],['proposal_patch_content','patch_content_tenant','fw_apishield_agent_rw'],['proposals','runtime_tenant','fw_apishield_agent_rw'],['pull_requests','runtime_tenant','fw_apishield_agent_rw']]:
            row = db.execute("SELECT qual, with_check, cmd, roles FROM pg_policies WHERE schemaname=current_schema() AND tablename=%s AND policyname=%s", (table, policy_name)).fetchone()
            assert row and row[2] == 'ALL' and row[3] == [role]
            assert all('SELECT current_setting' in clause for clause in row[:2])

        for table, required in [('analysis_findings', 'analysis_findings_tenant'), ('analysis_jobs', 'analysis_jobs_tenant'), ('repositories', 'repositories_tenant')]:
            policies = db.execute("SELECT policyname, roles, cmd FROM pg_policies WHERE schemaname=current_schema() AND tablename=%s", (table,)).fetchall()
            assert all(name != 'runtime_tenant' for name, _, _ in policies)
            assert any(name == required and roles == ['public'] and cmd == 'ALL' for name, roles, cmd in policies)
            flags = db.execute('SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid=%s::regclass', (table,)).fetchone()
            assert flags[0] is True and flags[1] is True
        # Run twice to prove replay safety, then inspect actual catalog definitions.
        for _ in range(2):
            db.execute((ROOT/'infra/environments/staging/007_remaining_fk_indexes.sql').read_text())
        definition = db.execute("SELECT pg_get_indexdef('idx_approvals_tenant_proposal'::regclass)").fetchone()[0]
        assert 'approvals USING btree (tenant_id, proposal_id)' in definition
        definition = db.execute("SELECT pg_get_indexdef('idx_idempotency_tenant_analysis'::regclass)").fetchone()[0]
        assert 'idempotency USING btree (tenant_id, analysis_id)' in definition
        definition = db.execute("SELECT pg_get_indexdef('idx_proposals_tenant_analysis'::regclass)").fetchone()[0]
        assert 'proposals USING btree (tenant_id, analysis_id)' in definition
        definition = db.execute("SELECT pg_get_indexdef('idx_pull_requests_tenant_proposal'::regclass)").fetchone()[0]
        assert 'pull_requests USING btree (tenant_id, proposal_id)' in definition
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
    # Force one backend so reuse, rollback and tenant/JWT cleanup are tested,
    # rather than accidentally receiving a fresh connection for each tenant.
    store._pool.resize(1, 1)
    with store.conn(TENANT) as db:
        backend = db.execute('SELECT pg_backend_pid()').fetchone()[0]
        db.execute("SELECT set_config('request.jwt.claim.sub', ?, true)", (USER,))
    with store.conn(other) as db:
        assert db.execute('SELECT pg_backend_pid()').fetchone()[0] == backend
        assert db.execute("SELECT nullif(current_setting('request.jwt.claim.sub', true), '')").fetchone()[0] is None
        assert len(db.execute('SELECT * FROM repositories').fetchall()) == 1
    with store._pool.connection() as db:
        assert db.execute('SELECT current_user').fetchone()['current_user'] == 'fw_runtime_test'
        assert db.execute("SELECT nullif(current_setting('app.tenant_id', true), '') AS tenant").fetchone()['tenant'] is None
        assert db.execute('SELECT count(*) AS count FROM repositories').fetchone()['count'] == 0
    with pytest.raises(RuntimeError, match='rollback fixture'):
        with store.conn(TENANT) as db:
            db.execute("UPDATE repositories SET default_branch='must-rollback'")
            raise RuntimeError('rollback fixture')
    with store.conn(TENANT) as db:
        assert db.execute('SELECT default_branch FROM repositories').fetchone()[0] == 'main'
    with pytest.raises(psycopg.errors.DivisionByZero):
        with store.conn(TENANT) as db:
            db.execute('SELECT 1/0')
    with store.conn(other) as db:
        assert db.execute('SELECT pg_backend_pid()').fetchone()[0] == backend
        assert len(db.execute('SELECT * FROM repositories').fetchall()) == 1
    assert store.member_role(TENANT, USER) == 'editor'
    # Verify an actual status change revokes authorization immediately.
    # This runs against the explicitly disposable localhost PostgreSQL fixture.
    with psycopg.connect(owner) as provisioning:
        result = provisioning.execute(
            "UPDATE memberships SET status='REVOKED' WHERE tenant_id=%s AND user_id=%s",
            (TENANT, USER),
        )
        assert result.rowcount == 1
    assert store.member_role(TENANT, USER) is None
    with psycopg.connect(owner) as provisioning:
        result = provisioning.execute(
            "UPDATE memberships SET status='ACTIVE' WHERE tenant_id=%s AND user_id=%s",
            (TENANT, USER),
        )
        assert result.rowcount == 1
    assert store.member_role(TENANT, USER) == 'editor'

    assert store.member_role(TENANT, 'malformed-subject') is None
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
        # A late, differently signed delivery must not revive an installation.
        late_body=json.dumps({'action':'created','installation':{'id':1}},separators=(',',':')).encode()
        late_sig=hmac.new(os.environ['GITHUB_WEBHOOK_SECRET'].encode(),late_body,hashlib.sha256).hexdigest()
        late=client.post('/internal/github/webhooks',content=late_body,headers={
            'X-Hub-Signature-256':f'sha256={late_sig}',
            'X-GitHub-Delivery':str(uuid4()),
            'X-GitHub-Event':'installation'})
        assert late.status_code==202 and late.json()['installation_state']=='SUSPENDED',late.text

        revoked=client.post(f'/v1/installations/1/repositories/{REPOSITORY}/analyses',headers=headers('repo:analyze','pg-revoked-key-001'),json={'base_sha':'a'*40,'head_sha':'b'*40,'capability_profile':'p'})
        assert revoked.status_code==403 and revoked.json()['code']=='REPOSITORY_ACCESS_REVOKED'
        revoked_proposal=client.post(f"/v1/analyses/{aid}/proposals",headers=headers('patch:create','pg-revoked-proposal-001'),json={'analysis_id':aid,'target_language':'typescript'})
        assert revoked_proposal.status_code==403,revoked_proposal.text
        revoked_patch=client.get(f"/v1/proposals/{proposed['id']}/patch",headers=headers('patch:read','pg-revoked-patch-001'))
        assert revoked_patch.status_code==403 and revoked_patch.json()['code']=='REPOSITORY_ACCESS_REVOKED'
        with pytest.raises(ValueError,match='REPOSITORY_ACCESS_REVOKED'):
            store.authorized_patch_bytes(TENANT,proposed['id'])
        with psycopg.connect(owner) as db:
            assert db.execute('SELECT permission_state FROM repositories WHERE tenant_id=%s AND id=%s',(TENANT,REPOSITORY)).fetchone()[0]=='REVOKED'
            assert db.execute('SELECT count(*) FROM github_webhook_deliveries').fetchone()[0]==2

    # A webhook connection cannot re-grant access even when it sets a valid
    # tenant context. PUBLIC policies are ORed, so this catches the old bypass.
    with psycopg.connect(owner) as db:
        for _ in range(2):
            db.execute((ROOT/'infra/environments/staging/008_repository_policy_role_fence.sql').read_text())
        row = db.execute("SELECT roles FROM pg_policies WHERE schemaname=current_schema() AND tablename='repositories' AND policyname='repositories_tenant'").fetchone()
        assert row[0] == ['fw_apishield_agent_rw']
    for tenant_context in ('', TENANT, other):
        for permission in ('READ', 'WRITE'):
            with psycopg.connect(webhook) as db:
                db.execute("SELECT set_config('app.tenant_id',%s,true)", (tenant_context,))
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    db.execute("UPDATE repositories SET permission_state=%s WHERE installation_id=1", (permission,))
    with psycopg.connect(webhook) as db:
        # Revoke remains possible across tenants, without broader SELECT grants.
        assert db.execute("UPDATE repositories SET permission_state='REVOKED' WHERE installation_id=1").rowcount == 2
    with store.conn(TENANT) as db:
        assert len(db.execute('SELECT * FROM repositories').fetchall()) == 1
    with store.conn(other) as db:
        assert len(db.execute('SELECT * FROM repositories').fetchall()) == 1

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
    for peer in peers:
        peer.close()
    store.close()
