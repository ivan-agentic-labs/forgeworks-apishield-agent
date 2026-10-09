from copy import deepcopy
import json
import pytest
from apishield_agent.domain.analysis import deterministic_openapi_diff


def contract(required):
    return {'openapi':'3.1.0','info':{'title':'Synthetic corpus','version':'1'},'paths':{'/items':{'get':{'responses':{'200':{'description':'ok','content':{'application/json':{'schema':{'type':'object','required':required,'properties':{'id':{'type':'string'},'cursor':{'type':'string'}}}}}}}}}}}


@pytest.mark.parametrize('before_required,after_required,expected',[
    (['id'],['id'],[]),
    ([],['id'],[('REQUIRED_RESPONSE_FIELD_ADDED','REVIEW','LIMITED')]),
    (['id'],[],[('REQUIRED_RESPONSE_FIELD_REMOVED','BREAKING','COVERED')]),
    (['id'],['cursor'],[('REQUIRED_RESPONSE_FIELD_ADDED','REVIEW','LIMITED'),('REQUIRED_RESPONSE_FIELD_REMOVED','BREAKING','COVERED')]),
    (['id','cursor'],['cursor','id'],[]),
])
def test_inline_response_presence_corpus(tmp_path,before_required,after_required,expected):
    before,after=tmp_path/'before.json',tmp_path/'after.json'
    before.write_text(json.dumps(contract(before_required)))
    after.write_text(json.dumps(contract(after_required)))
    findings=deterministic_openapi_diff(str(before),str(after))
    assert [(f.rule_id,f.severity,f.coverage) for f in findings]==expected


def test_removed_operation_loses_response_presence_guarantees(tmp_path):
    before,after=tmp_path/'before.json',tmp_path/'after.json'
    old=contract(['id']);new=deepcopy(old);new['paths']={}
    before.write_text(json.dumps(old));after.write_text(json.dumps(new))
    findings=deterministic_openapi_diff(str(before),str(after))
    assert len(findings)==1 and findings[0].severity=='BREAKING'
