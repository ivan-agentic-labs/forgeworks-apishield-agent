import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from apishield_agent.application.analysis_worker import AnalysisWorker
from apishield_agent.infrastructure.github_sources import GitHubSources, SourceError, NoRedirect
from apishield_agent.infrastructure.store import Store,TENANT,USER,REPOSITORY

ROOT=Path(__file__).resolve().parents[2]


@pytest.fixture
def key():
    return rsa.generate_private_key(public_exponent=65537,key_size=2048)


class MockGitHub:
    def __init__(self,key):
        self.key=key;self.calls=[];self.bad_blob=False;self.write_token=False
    def __call__(self,method,url,headers,body):
        self.calls.append((method,url))
        assert url.startswith('https://api.github.com/')
        assert headers['X-GitHub-Api-Version']=='2026-03-10'
        if method=='POST':
            claims=jwt.decode(headers['Authorization'].removeprefix('Bearer '),self.key.public_key(),algorithms=['RS256'],issuer='123')
            assert 0 < claims['exp']-claims['iat'] <= 600
            assert json.loads(body)=={'repository_ids':[456],'permissions':{'contents':'read'}}
            return 201,{'token':'synthetic-installation-token','expires_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),'permissions':{'contents':'write' if self.write_token else 'read','metadata':'read'}}
        assert headers['Authorization']=='Bearer synthetic-installation-token'
        if '/contents/' not in url:
            return 200,{'id':456,'full_name':'synthetic-owner/synthetic-repo'}
        name='before' if url.endswith('a'*40) else 'after'
        content=(ROOT/f'fixtures/golden/{name}.yaml').read_bytes()
        sha=hashlib.sha1(b'blob '+str(len(content)).encode()+b'\0'+content).hexdigest()
        return 200,{'type':'file','encoding':'base64','path':'contracts/openapi.yaml','size':len(content),'sha':'0'*40 if self.bad_blob else sha,'content':base64.b64encode(content).decode()}


def mapping():
    return {TENANT+':'+REPOSITORY:{'installation_id':1,'repository_id':456,'full_name':'synthetic-owner/synthetic-repo','contract_path':'contracts/openapi.yaml'}}


def analysis():
    return {'tenant_id':TENANT,'repository_id':REPOSITORY,'base_sha':'a'*40,'head_sha':'b'*40}


def test_read_only_adapter_signs_scoped_token_and_verifies_exact_blobs(key):
    server=MockGitHub(key);reader=GitHubSources('123',key,mapping(),server)
    before,after=reader.snapshot(analysis(),{'installation_id':1})
    assert before==(ROOT/'fixtures/golden/before.yaml').read_bytes()
    assert after==(ROOT/'fixtures/golden/after.yaml').read_bytes()
    assert len(server.calls)==4
    assert sum(method=='POST' for method,_ in server.calls)==1  # token mint only, no repo writes


@pytest.mark.parametrize('change',[{'contract_path':'../secret'},{'contract_path':'https://example.invalid/x'},{'full_name':'../secret'},{'installation_id':2}])
def test_invalid_provisioned_mapping_fails_before_network(key,change):
    server=MockGitHub(key);values=mapping();values[TENANT+':'+REPOSITORY].update(change)
    with pytest.raises(SourceError):
        GitHubSources('123',key,values,server).snapshot(analysis(),{'installation_id':1})
    assert server.calls==[]


def test_mutable_reference_and_missing_tenant_mapping_fail_before_network(key):
    server=MockGitHub(key);reader=GitHubSources('123',key,mapping(),server)
    values=analysis();values['base_sha']='main'
    with pytest.raises(SourceError,match='IMMUTABLE_REVISION'):
        reader.snapshot(values,{'installation_id':1})
    values=analysis();values['tenant_id']='00000000-0000-0000-0000-000000000099'
    with pytest.raises(SourceError,match='MAPPING_REQUIRED'):
        reader.snapshot(values,{'installation_id':1})
    assert server.calls==[]


@pytest.mark.parametrize('failure',['blob','permission'])
def test_integrity_and_excessive_token_permissions_are_rejected(key,failure):
    server=MockGitHub(key);server.bad_blob=failure=='blob';server.write_token=failure=='permission'
    with pytest.raises(SourceError):
        GitHubSources('123',key,mapping(),server).snapshot(analysis(),{'installation_id':1})


def test_worker_uses_remote_adapter_bytes_not_local_fixture_paths(tmp_path,key):
    store=Store(str(tmp_path/'db.sqlite'));store.seed_demo('must-not-read-before','must-not-read-after')
    row=store.create_analysis(TENANT,USER,REPOSITORY,'a'*40,'b'*40,'p','github-read-analysis-001','request')
    reader=GitHubSources('123',key,mapping(),MockGitHub(key))
    assert AnalysisWorker(store,reader).run_once()
    assert store.get_analysis(TENANT,row['id'])['status']=='SUCCEEDED'
    proposal=store.create_proposal(TENANT,row['id'],'typescript')
    assert 'next_cursor' in store.proposal_patch(TENANT,proposal['id'])['patch_text']


def test_redirect_handler_never_follows_response_location():
    with pytest.raises(SourceError,match='REDIRECT_DISABLED'):
        NoRedirect().redirect_request(None,None,302,None,None,'https://example.invalid/')


def test_live_read_mode_requires_external_configuration(monkeypatch):
    monkeypatch.setenv('APISHIELD_GITHUB_READS_ENABLED','1')
    monkeypatch.delenv('APISHIELD_GITHUB_SOURCE_MAP_JSON',raising=False)
    with pytest.raises(SourceError,match='CONFIGURATION_REQUIRED'):
        GitHubSources.from_environment()


def test_malformed_installation_expiry_is_typed_failure(key):
    class InvalidExpiry(MockGitHub):
        def __call__(self, method, url, headers, body):
            status, result = super().__call__(method, url, headers, body)
            if method == "POST":
                result["expires_at"] = {"not": "an ISO timestamp"}
            return status, result

    with pytest.raises(SourceError, match="GITHUB_TOKEN_RESPONSE_INVALID"):
        GitHubSources("123", key, mapping(), InvalidExpiry(key)).snapshot(
            analysis(), {"installation_id": 1}
        )


def test_corrupt_base64_file_is_typed_failure(key):
    class BrokenContent(MockGitHub):
        def __call__(self, method, url, headers, body):
            status, result = super().__call__(method, url, headers, body)
            if "/contents/" in url:
                result["content"] = "not-valid-@-base64"
            return status, result

    with pytest.raises(SourceError, match="GITHUB_SOURCE_ENCODING_INVALID"):
        GitHubSources("123", key, mapping(), BrokenContent(key)).snapshot(
            analysis(), {"installation_id": 1}
        )


@pytest.mark.parametrize("field,value", [
    ("base_sha", None),
    ("head_sha", 42),
    ("base_sha", {}),
])
def test_malformed_commit_identity_fails_before_network(key, field, value):
    server = MockGitHub(key)
    request = analysis()
    request[field] = value
    with pytest.raises(SourceError, match="GITHUB_IMMUTABLE_REVISION_REQUIRED"):
        GitHubSources("123", key, mapping(), server).snapshot(request, {"installation_id": 1})
    assert server.calls == []
