"""Runs only against an explicitly opted-in disposable localhost PostgreSQL instance."""
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from apishield_agent.infrastructure.postgres_store import PostgresStore
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
        for name in ['001_apishield_mvp.sql','002_apishield_runtime.sql']:
            db.execute((ROOT/'migrations/versions'/name).read_text())
        db.execute("CREATE ROLE fw_runtime_test LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'synthetic-local-runtime-test-only'")
        db.execute('GRANT fw_apishield_agent_rw TO fw_runtime_test')
        db.execute('INSERT INTO tenants VALUES (%s,%s,%s)',(TENANT,'synthetic-demo','ACTIVE'))
        db.execute('INSERT INTO memberships VALUES (%s,%s,%s,%s)',(TENANT,USER,'editor','ACTIVE'))
        db.execute('INSERT INTO repositories VALUES (%s,%s,%s,%s,%s,%s,%s)',(TENANT,REPOSITORY,1,'main','READ',str(ROOT/'fixtures/golden/before.yaml'),str(ROOT/'fixtures/golden/after.yaml')))
        other=str(uuid4())
        db.execute('INSERT INTO tenants VALUES (%s,%s,%s)',(other,'synthetic-other','ACTIVE'))
        db.execute('INSERT INTO repositories VALUES (%s,%s,%s,%s,%s,%s,%s)',(other,str(uuid4()),1,'main','READ','',''))
    info.update(user='fw_runtime_test',password='synthetic-local-runtime-test-only')
    from psycopg.conninfo import make_conninfo
    runtime=make_conninfo(**info)
    monkeypatch.setenv('APISHIELD_WORKER_TENANTS',TENANT)
    return owner,runtime,other


def test_actual_postgres_api_worker_and_full_rls_boundaries(postgres, monkeypatch,tmp_path):
    owner,runtime,other=postgres
    with pytest.raises(ValueError,match='superuser'):
        PostgresStore(owner)
    store=PostgresStore(runtime)
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
    # Two independent adapters must converge on one durable analysis/lease.
    peers=[PostgresStore(runtime),PostgresStore(runtime)]
    def submit(index):
        return peers[index%2].create_analysis(TENANT,USER,REPOSITORY,'a'*40,'b'*40,'p','pg-concurrent-key-001','request')['id']
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert len(set(pool.map(submit,range(8))))==1
    with ThreadPoolExecutor(max_workers=2) as pool:
        leases=list(pool.map(lambda peer:peer.claim_pending(),peers))
    assert sum(row is not None for row in leases)==1
