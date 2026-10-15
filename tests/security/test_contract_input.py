import json
import os

import pytest
from fastapi.testclient import TestClient
from apishield_agent.application.analysis_worker import AnalysisWorker
from apishield_agent.domain.contract_input import load_contract, read_contract, MAX_CONTRACT_BYTES
from apishield_agent.infrastructure.store import TENANT, USER, REPOSITORY
from apishield_agent.main import create_app
from test_hardening import headers


@pytest.mark.parametrize('body',[
    b'paths: {}\npaths: {}\n',
    b'paths: &a {}\nother: *a\n',
    b'paths: {}\nx: {"$ref": "https://example.invalid/schema"}\n',
    b'paths: {}\nx: .nan\n',
    b'paths: []\n',
    b'paths: {}\nx: !!python/object/apply:os.system ["false"]',
])
def test_unsafe_contracts_are_rejected_offline(body):
    with pytest.raises(ValueError):
        load_contract(body)


def test_contract_byte_limit():
    with pytest.raises(ValueError,match='CONTRACT_TOO_LARGE'):
        load_contract(b'x'*(MAX_CONTRACT_BYTES+1))


def test_symlink_and_fifo_sources_are_rejected(tmp_path):
    real=tmp_path/'real.yaml';real.write_text('paths: {}\n')
    link=tmp_path/'link.yaml';link.symlink_to(real)
    with pytest.raises(ValueError):
        read_contract(str(link))
    fifo=tmp_path/'fifo';os.mkfifo(fifo)
    with pytest.raises(ValueError,match='NOT_REGULAR_FILE'):
        read_contract(str(fifo))


def test_unsupported_reference_is_counted_in_api_and_event(tmp_path):
    app=create_app(str(tmp_path/'db.sqlite'),seed=True)
    doc={'paths':{'/x':{'get':{'responses':{'200':{'content':{'application/json':{'schema':{'$ref':'#/components/schemas/X'}}}}}}}},'components':{'schemas':{'X':{'type':'object'}}}}
    path=tmp_path/'contract.json';path.write_text(json.dumps(doc))
    with app.state.store.conn() as db:
        db.execute('UPDATE repositories SET before_contract=?,after_contract=? WHERE tenant_id=? AND id=?',(str(path),str(path),TENANT,REPOSITORY))
    row=app.state.store.create_analysis(TENANT,USER,REPOSITORY,'a'*40,'b'*40,'p','unsupported-input-key-001','request')
    assert AnalysisWorker(app.state.store).run_once()
    with TestClient(app) as client:
        result=client.get(f"/v1/analyses/{row['id']}",headers=headers('analysis:read','unsupported-read-key-001'))
        assert result.status_code==200 and result.json()['unsupported_count']==1
    with app.state.store.conn() as db:
        event=db.execute("SELECT payload FROM events WHERE aggregate_id=?",(row['id'],)).fetchone()
        assert json.loads(event['payload'])['unsupported_count']==1


@pytest.mark.parametrize('body', [
    b'paths:\n  1: {get: {}}\n',
    b'paths:\n  relative/path: {get: {}}\n',
    b'paths:\n  /valid: []\n',
])
def test_malformed_path_cannot_disappear_from_impact_analysis(body):
    with pytest.raises(ValueError, match='CONTRACT_PATH_INVALID'):
        load_contract(body)


def test_well_formed_path_item_remains_accepted():
    assert '/valid' in load_contract(b'paths:\n  /valid:\n    get: {}\n')['paths']
