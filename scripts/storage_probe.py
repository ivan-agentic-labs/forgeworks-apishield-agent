"""Bounded S3 probe for deployment, with cleanup of its own disposable object."""
from uuid import uuid4
import hashlib
from apishield_agent.infrastructure.object_storage import ObjectStorage

objects=ObjectStorage("apishield-agent",2097152 if "apishield-agent"=="apishield-agent" else 1048576)
tenant,artifact=str(uuid4()),str(uuid4())
body=b"ForgeWorks disposable storage readiness probe\n"
digest=hashlib.sha256(body).hexdigest()
key=objects.key(tenant,artifact,digest)
try:
    result=objects.put(tenant,artifact,body,digest,len(body))
    assert objects.read(tenant,artifact,result["generation"],digest,len(body))==body
    print("STORAGE_PROBE_PASS: signed upload, persisted read, digest and size verified",flush=True)
finally:
    objects.transfer("DELETE",key)
