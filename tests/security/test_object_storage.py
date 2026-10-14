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

@pytest.mark.parametrize("endpoint",["http://unsafe.invalid","https://user:pass"+chr(64)+"storage.invalid","https://storage.invalid/prefix","https://storage.invalid?query=x"],ids=["scheme","userinfo","path","query"])
def test_unsafe_endpoint_rejected(monkeypatch,endpoint):
    monkeypatch.setenv("S3_ENDPOINT",endpoint)
    with pytest.raises(HTTPException):ObjectStorage("apishield-agent")


@pytest.mark.parametrize("endpoint", [
    "https://storage.examp\tle.invalid",
    "https://storage.example.invalid\r\n",
    "https://storage.example.invalid\x7f",
    "https://storage.example.invalid\\evil.invalid",
])
def test_storage_origin_must_not_be_silently_normalized(monkeypatch, endpoint):
    # urllib.parse.urlsplit can silently remove ASCII control characters
    # from the authority. Never sign requests to a modified destination.
    for key, value in {
        "S3_BUCKET": "private-bucket",
        "S3_REGION": "auto",
        "S3_ACCESS_KEY_ID": "synthetic-access-key",
        "S3_SECRET_ACCESS_KEY": "synthetic-secret-for-offline-tests",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("S3_ENDPOINT", endpoint)
    with pytest.raises(HTTPException) as error:
        ObjectStorage("apishield-agent")
    assert error.value.status_code == 503
    assert error.value.detail["code"] == "STORAGE_NOT_CONFIGURED"


@pytest.mark.parametrize("userinfo", ["@", ":@"])
def test_s3_empty_userinfo_cannot_be_silently_discarded(monkeypatch, userinfo):
    # Python URL parsing yields empty username/password values for these forms.
    # Ensure this fails because of authority validation, not missing credentials.
    for key, value in {
        "S3_BUCKET": "private-bucket",
        "S3_REGION": "auto",
        "S3_ACCESS_KEY_ID": "synthetic-access-key",
        "S3_SECRET_ACCESS_KEY": "synthetic-secret-for-offline-tests",
        "S3_URL_STYLE": "virtual-host",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("S3_ENDPOINT", "https://" + userinfo + "storage.example.invalid")
    with pytest.raises(HTTPException) as error:
        ObjectStorage("apishield-agent")
    assert error.value.status_code == 503
    assert error.value.detail["code"] == "STORAGE_NOT_CONFIGURED"


def test_canonical_s3_endpoint_remains_valid(monkeypatch):
    for key, value in {
        "S3_BUCKET": "private-bucket",
        "S3_REGION": "auto",
        "S3_ACCESS_KEY_ID": "synthetic-access-key",
        "S3_SECRET_ACCESS_KEY": "synthetic-secret-for-offline-tests",
        "S3_URL_STYLE": "virtual-host",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("S3_ENDPOINT", "https://storage.example.invalid")
    assert ObjectStorage("apishield-agent").host == "storage.example.invalid"


def test_supabase_s3_hosted_path_prefix_is_signed_exactly(monkeypatch):
    values = {
        "S3_ENDPOINT": "https://fljekuwplgkrpdoajyhn.storage.supabase.co/storage/v1/s3",
        "S3_BUCKET": "fw-staging-apishield-agent",
        "S3_REGION": "ap-northeast-2",
        "S3_URL_STYLE": "path",
        "S3_ACCESS_KEY_ID": "synthetic-access-key",
        "S3_SECRET_ACCESS_KEY": "synthetic-secret-for-offline-tests",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    store = ObjectStorage("apishield-agent")
    request = store.signed_request("PUT", "apishield-agent/abc", b"payload",
                                   datetime(2026,10,14,tzinfo=timezone.utc))
    assert request.full_url == (
        "https://fljekuwplgkrpdoajyhn.storage.supabase.co/storage/v1/s3/"
        "fw-staging-apishield-agent/apishield-agent/abc"
    )
    assert "20261014/ap-northeast-2/s3/aws4_request" in request.get_header("Authorization")
    assert request.get_header("X-amz-content-sha256") == hashlib.sha256(b"payload").hexdigest()


@pytest.mark.parametrize("endpoint,style", [
    ("https://storage.example.invalid/storage/v1/s3", "path"),
    ("https://fljekuwplgkrpdoajyhn.storage.supabase.co/storage/v1/s3/evil", "path"),
    ("https://fljekuwplgkrpdoajyhn.storage.supabase.co/storage/v1/s3", "virtual-host"),
    ("https://fljekuwplgkrpdoajyhn.storage.supabase.co/%73torage/v1/s3", "path"),
    ("https://x.supabase.co/storage/v1/s3", "path"),
])
def test_supabase_s3_path_rejects_untrusted_destinations(monkeypatch, endpoint, style):
    for key, value in {
        "S3_BUCKET": "fw-staging-apishield-agent",
        "S3_REGION": "ap-northeast-2",
        "S3_ACCESS_KEY_ID": "synthetic-access-key",
        "S3_SECRET_ACCESS_KEY": "synthetic-secret-for-offline-tests",
        "S3_URL_STYLE": style,
        "S3_ENDPOINT": endpoint,
    }.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(HTTPException) as err:
        ObjectStorage("apishield-agent")
    assert err.value.status_code == 503
