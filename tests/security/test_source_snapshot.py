import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from apishield_agent.application.analysis_worker import AnalysisWorker
from apishield_agent.infrastructure.store import TENANT,USER,REPOSITORY
from apishield_agent.main import create_app
from test_hardening import headers

ROOT=Path(__file__).resolve().parents[2]


def analyzed_source(tmp_path):
    app=create_app(str(tmp_path/'db.sqlite'),seed=True)
    before=tmp_path/'before.yaml';after=tmp_path/'after.yaml'
    before.write_bytes((ROOT/'fixtures/golden/before.yaml').read_bytes())
    after.write_bytes((ROOT/'fixtures/golden/after.yaml').read_bytes())
    with app.state.store.conn() as db:
        db.execute('UPDATE repositories SET before_contract=?,after_contract=? WHERE tenant_id=? AND id=?',(str(before),str(after),TENANT,REPOSITORY))
    analysis=app.state.store.create_analysis(TENANT,USER,REPOSITORY,'a'*40,'b'*40,'p','snapshot-analysis-key-001','request')
    assert AnalysisWorker(app.state.store).run_once()
    return app,analysis,before,after


def test_proposal_is_immutable_after_source_files_change(tmp_path):
    app,analysis,before,after=analyzed_source(tmp_path)
    first=app.state.store.create_proposal(TENANT,analysis['id'],'typescript')
    patch=app.state.store.proposal_patch(TENANT,first['id'])['patch_text']
    before.write_text('paths: {}\n');after.write_text('paths: {}\n')
    second=app.state.store.create_proposal(TENANT,analysis['id'],'typescript')
    assert first['patch_sha256']==second['patch_sha256']==hashlib.sha256(patch.encode()).hexdigest()
    assert app.state.store.proposal_patch(TENANT,second['id'])['patch_text']==patch
    assert 'next_cursor' in patch


@pytest.mark.parametrize('mode',['tamper','missing'])
def test_invalid_snapshot_blocks_proposal_without_partial_writes(tmp_path,mode):
    app,analysis,_,_=analyzed_source(tmp_path)
    with app.state.store.conn() as db:
        if mode=='tamper':
            db.execute("UPDATE analysis_source_snapshots SET before_base64='dGFtcGVy' WHERE tenant_id=? AND analysis_id=?",(TENANT,analysis['id']))
        else:
            db.execute('DELETE FROM analysis_source_snapshots WHERE tenant_id=? AND analysis_id=?',(TENANT,analysis['id']))
    with TestClient(app) as client:
        result=client.post(f"/v1/analyses/{analysis['id']}/proposals",headers=headers('patch:create','snapshot-proposal-key-001'),json={'analysis_id':analysis['id'],'target_language':'typescript'})
        assert result.status_code==409,result.text
        assert result.json()['code'] in {'ANALYSIS_SOURCE_INTEGRITY_FAILURE','ANALYSIS_SOURCE_SNAPSHOT_REQUIRED'}
    with app.state.store.conn() as db:
        assert db.execute('SELECT count(*) FROM proposals').fetchone()[0]==0
