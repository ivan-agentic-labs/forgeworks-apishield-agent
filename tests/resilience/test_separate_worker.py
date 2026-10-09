import os
import subprocess
import sys
from pathlib import Path

from apishield_agent.infrastructure.store import Store, TENANT, USER, REPOSITORY

ROOT=Path(__file__).resolve().parents[2]


def test_separate_worker_recovers_durable_job_for_non_default_installation(tmp_path):
    path=tmp_path/'durable.sqlite'
    store=Store(str(path))
    store.seed_demo(str(ROOT/'fixtures/golden/before.yaml'),str(ROOT/'fixtures/golden/after.yaml'))
    with store.conn() as db:
        db.execute('UPDATE repositories SET installation_id=17 WHERE tenant_id=?',(TENANT,))
    row=store.create_analysis(TENANT,USER,REPOSITORY,'a'*40,'b'*40,'p','separate-worker-key-001','request')
    assert row['status']=='PENDING'
    environment={**os.environ,'APISHIELD_DB_PATH':str(path),'PYTHONPATH':str(ROOT/'apps/api/src')}
    environment.pop('APISHIELD_DATABASE_URL',None)
    result=subprocess.run([sys.executable,'-m','apishield_agent.application.analysis_worker','--once'],env=environment,capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    reopened=Store(str(path))
    assert reopened.get_analysis(TENANT,row['id'])['status']=='SUCCEEDED'
    assert reopened.finding_count(TENANT,row['id'])==1
    result=subprocess.run([sys.executable,'-m','apishield_agent.application.analysis_worker','--once'],env=environment,capture_output=True,text=True,timeout=15)
    assert result.returncode==0
    assert reopened.finding_count(TENANT,row['id'])==1
