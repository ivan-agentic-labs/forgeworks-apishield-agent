"""Opt-in disposable S3 upload/read/delete proof; never operates on customer IDs.

A PASS requires a persisted read and demonstrated deletion of the randomly
generated probe object. No tokens, request URLs, object keys or secrets printed.
"""
from __future__ import annotations

import hashlib
from uuid import uuid4

from fastapi import HTTPException
from apishield_agent.infrastructure.object_storage import ObjectStorage

PRODUCT = "apishield-agent"
MAX_BYTES = 2097152 if PRODUCT == "apishield-agent" else 1048576
PROBE_BYTES = b"ForgeWorks disposable storage readiness probe\n"


class StorageProbeFailure(RuntimeError):
    """An end-to-end storage operation was not proved."""


def verify_storage(factory=ObjectStorage) -> None:
    store = factory(PRODUCT, MAX_BYTES)
    tenant, artifact = str(uuid4()), str(uuid4())
    body = PROBE_BYTES
    digest = hashlib.sha256(body).hexdigest()
    key = store.key(tenant, artifact, digest)
    roundtrip_verified = False
    try:
        try:
            receipt = store.put(tenant, artifact, body, digest, len(body))
            if not isinstance(receipt, dict) or receipt.get("generation") != digest:
                raise StorageProbeFailure("STORAGE_WRITE_NOT_VERIFIED")
            if store.read(tenant, artifact, digest, digest, len(body)) != body:
                raise StorageProbeFailure("STORAGE_READ_NOT_VERIFIED")
            roundtrip_verified = True
        except Exception:
            # Cleanup even when a PUT result is ambiguous; the remote write
            # might have succeeded before a timed-out integrity check.
            roundtrip_verified = False
    finally:
        try:
            store.transfer("DELETE", key)
        except Exception:
            raise StorageProbeFailure("STORAGE_DISPOSABLE_DELETE_NOT_VERIFIED") from None
    try:
        store.read(tenant, artifact, digest, digest, len(body))
    except HTTPException as error:
        code = error.detail.get("code") if isinstance(error.detail, dict) else None
        if error.status_code != 409 or code != "ARTIFACT_BYTES_MISSING":
            raise StorageProbeFailure("STORAGE_DISPOSABLE_ABSENCE_NOT_VERIFIED") from None
    except Exception:
        raise StorageProbeFailure("STORAGE_DISPOSABLE_ABSENCE_NOT_VERIFIED") from None
    else:
        raise StorageProbeFailure("STORAGE_DISPOSABLE_ABSENCE_NOT_VERIFIED")
    if not roundtrip_verified:
        raise StorageProbeFailure("STORAGE_WRITE_READ_NOT_VERIFIED")
    print("STORAGE_PROBE_PASS: upload, integrity, deletion and verified absence", flush=True)


if __name__ == "__main__":
    verify_storage()
