"""S3 integrity, tenant separation, request signing and redirect protection."""
import hashlib
import io
from datetime import datetime, timezone
from uuid import uuid4
import pytest
from fastapi import HTTPException
from apishield_agent.infrastructure.object_storage import ObjectStorage, NoRedirect

@pytest.fixture
def objects(monkeypatch):
    for key,value in {"S3_ENDPOINT":"https://storage.example.invalid","S3_BUCKET":"private-bucket","S3_REGION":"auto","S3_ACCESS_KEY_ID":"synthetic-access-key","S3_SECRET_ACCESS_KEY":"synthetic-secret-for-offline-tests"}.items():
        monkeypatch.setenv(key,value)
    store=ObjectStorage("apishield-agent");data={}
    def transfer(method,key,body=None):
        if method=="PUT":data[key]=body;return b""
        if key not in data:raise HTTPException(409,detail={"code":"ARTIFACT_BYTES_MISSING"})
        return data[key]
    monkeypatch.setattr(store,"transfer",transfer)
    return store,data

def test_content_generation_tenant_boundary_and_tampering(objects):
    store,data=objects;tenant,artifact=str(uuid4()),str(uuid4());body=b"real bounded bytes"
    digest=hashlib.sha256(body).hexdigest();result=store.put(tenant,artifact,body,digest,len(body))
    assert store.read(tenant,artifact,result["generation"],digest,len(body))==body
    with pytest.raises(HTTPException):store.read(str(uuid4()),artifact,result["generation"],digest,len(body))
    with pytest.raises(HTTPException):store.read(tenant,artifact,"wrong-generation",digest,len(body))
    data[store.key(tenant,artifact,digest)]=b"tampered"
    with pytest.raises(HTTPException) as error:store.read(tenant,artifact,result["generation"],digest,len(body))
    assert error.value.detail["code"]=="ARTIFACT_INTEGRITY_FAILURE"

def test_bad_bytes_never_reach_storage(objects):
    store,data=objects
    with pytest.raises(HTTPException):store.put(str(uuid4()),str(uuid4()),b"wrong","a"*64,5)
    assert not data

def test_signing_and_no_redirects(objects):
    store,_=objects;request=store.signed_request("PUT","apishield-agent/path",b"payload",datetime(2026,10,10,tzinfo=timezone.utc))
    assert request.full_url=="https://private-bucket.storage.example.invalid/apishield-agent/path"
    assert request.get_header("X-amz-content-sha256")==hashlib.sha256(b"payload").hexdigest()
    assert "20261010/auto/s3/aws4_request" in request.get_header("Authorization")
    assert "host;x-amz-content-sha256;x-amz-date" in request.get_header("Authorization")
    assert NoRedirect().redirect_request(None,None,302,"redirect",{},"https://attacker.invalid") is None

@pytest.mark.parametrize("endpoint",["http://unsafe.invalid","https://user:pass@storage.invalid","https://storage.invalid/prefix","https://storage.invalid?query=x"])
def test_unsafe_endpoint_rejected(monkeypatch,endpoint):
    monkeypatch.setenv("S3_ENDPOINT",endpoint)
    with pytest.raises(HTTPException):ObjectStorage("apishield-agent")
