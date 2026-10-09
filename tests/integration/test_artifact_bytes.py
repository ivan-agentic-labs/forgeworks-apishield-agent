import hashlib
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient
from apishield_agent.main import create_app
from test_hardening import headers


def intent(client, content, key="artifact-byte-key-001"):
    return client.post('/v1/artifacts/upload-intents', headers=headers('artifact:create',key), json={'kind':'contract','filename':'contract.yaml','size_bytes':len(content),'sha256':hashlib.sha256(content).hexdigest()}).json()


def test_real_upload_quarantine_commit_and_download(tmp_path):
    content=b'openapi: 3.1.0\ninfo: {title: Synthetic, version: "1"}\npaths: {}\n'
    with TestClient(create_app(str(tmp_path/'db.sqlite'),seed=True)) as client:
        created=intent(client,content)
        aid=created['artifact_id']
        assert client.get(created['upload_url']).status_code==403
        assert client.put(created['upload_url'].replace(aid,str(uuid4())),content=content).status_code==403
        assert client.post(f'/v1/artifacts/{aid}/download-intents',headers=headers('artifact:download','download-key-001')).status_code==409
        missing=client.post(f'/v1/artifacts/{aid}/commit',headers=headers('artifact:commit','commit-byte-key-001'),json={'sha256':hashlib.sha256(content).hexdigest(),'size_bytes':len(content),'object_generation':'missing'})
        assert missing.status_code==409 and missing.json()['code']=='ARTIFACT_BYTES_MISSING'
        uploaded=client.put(created['upload_url'],content=content)
        assert uploaded.status_code==201
        generation=uploaded.json()['object_generation']
        assert client.put(created['upload_url'],content=content).json()['object_generation']==generation
        committed=client.post(f'/v1/artifacts/{aid}/commit',headers=headers('artifact:commit','commit-byte-key-002'),json={'sha256':hashlib.sha256(content).hexdigest(),'size_bytes':len(content),'object_generation':generation})
        assert committed.status_code==202 and committed.json()['status']=='AVAILABLE'
        download=client.post(f'/v1/artifacts/{aid}/download-intents',headers=headers('artifact:download','download-byte-key-001')).json()
        response=client.get(download['download_url'])
        assert response.status_code==200 and response.content==content
        assert response.headers['cache-control']=='no-store'
        assert client.put(created['upload_url'],content=content).status_code==409
        for file in (tmp_path/'artifacts').glob('*.object'):
            file.write_bytes(b'tampered')
        assert client.get(download['download_url']).status_code==409


def test_remote_refs_remain_quarantined(tmp_path):
    content=b'openapi: 3.1.0\ninfo: {title: Synthetic, version: "1"}\npaths: {}\ncomponents:\n  schemas:\n    X: {$ref: "http://169.254.169.254/latest/meta-data/"}\n'
    with TestClient(create_app(str(tmp_path/'db.sqlite'),seed=True)) as client:
        created=intent(client,content)
        uploaded=client.put(created['upload_url'],content=content).json()
        result=client.post(f"/v1/artifacts/{created['artifact_id']}/commit",headers=headers('artifact:commit','commit-invalid-key-001'),json={'sha256':hashlib.sha256(content).hexdigest(),'size_bytes':len(content),'object_generation':uploaded['object_generation']})
        assert result.status_code==422
        metadata=client.get(f"/v1/artifacts/{created['artifact_id']}",headers=headers('artifact:read','metadata-key-00001')).json()
        assert metadata['status']=='INTENT_ISSUED'
