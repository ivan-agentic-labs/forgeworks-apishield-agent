"""Durable S3 provider using existing bounded artifact capabilities."""
import os
from uuid import UUID
from apishield_agent.infrastructure.local_artifacts import LocalArtifacts, MAX_BYTES, reject
from apishield_agent.infrastructure.object_storage import ObjectStorage

class S3Artifacts(LocalArtifacts):
    def __init__(self):
        self.objects=ObjectStorage("apishield-agent",MAX_BYTES)
    def secret(self):
        secret=os.getenv("ARTIFACT_SIGNING_SECRET","")
        if len(secret.encode())<32 or secret==os.getenv("DEV_AUTH_SECRET"):
            reject("STORAGE_NOT_CONFIGURED","A separate artifact signing secret is required",503)
        return secret
    def path(self,tenant,artifact_id):
        return str(UUID(str(tenant)))+"/"+str(UUID(str(artifact_id)))
    def put(self,tenant,artifact_id,body,expected_sha,expected_size):
        return self.objects.put(tenant,artifact_id,body,expected_sha,expected_size)
    def verify(self,tenant,artifact_id,generation,sha,size):
        return self.objects.read(tenant,artifact_id,generation,sha,size)
