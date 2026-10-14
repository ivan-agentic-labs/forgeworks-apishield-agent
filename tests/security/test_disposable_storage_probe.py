"""Offline tests for the real S3 readiness probe's negative and cleanup paths."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("disposable_storage_probe", ROOT/"scripts/storage_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class FakeStorage:
    def __init__(self, product, max_bytes, *, write_fail=False,
                 delete_fail=False, stale_read=False, missing_code="ARTIFACT_BYTES_MISSING"):
        assert product == probe.PRODUCT
        assert max_bytes == probe.MAX_BYTES
        self.present = False
        self.writes = 0
        self.deletes = 0
        self.write_fail = write_fail
        self.delete_fail = delete_fail
        self.stale_read = stale_read
        self.missing_code = missing_code

    def key(self, tenant, artifact, digest):
        return f"{tenant}/{artifact}/{digest}"

    def put(self, tenant, artifact, body, digest, size):
        self.writes += 1
        self.present = True
        if self.write_fail:
            raise RuntimeError("backend PUT acknowledged but verification timed out")
        return {"generation": digest}

    def read(self, tenant, artifact, generation, digest, size):
        if self.present or self.stale_read:
            return probe.PROBE_BYTES
        raise HTTPException(409, detail={"code": self.missing_code})

    def transfer(self, method, key):
        assert method == "DELETE" and key
        self.deletes += 1
        if self.delete_fail:
            raise RuntimeError("remote cleanup failure")
        self.present = False
        return b""


def test_disposable_roundtrip_cleanup_is_verified_before_pass(capsys):
    storage = FakeStorage(probe.PRODUCT, probe.MAX_BYTES)
    probe.verify_storage(factory=lambda *_: storage)
    assert storage.writes == 1 and storage.deletes == 1
    assert storage.present is False
    assert "STORAGE_PROBE_PASS" in capsys.readouterr().out


@pytest.mark.parametrize("settings,code",[
    ({"write_fail":True}, "STORAGE_WRITE_READ_NOT_VERIFIED"),
    ({"delete_fail":True}, "STORAGE_DISPOSABLE_DELETE_NOT_VERIFIED"),
    ({"stale_read":True}, "STORAGE_DISPOSABLE_ABSENCE_NOT_VERIFIED"),
    ({"missing_code":"STORAGE_UNAVAILABLE"}, "STORAGE_DISPOSABLE_ABSENCE_NOT_VERIFIED"),
])
def test_disposable_failures_never_report_pass(settings,code,capsys):
    storage = FakeStorage(probe.PRODUCT,probe.MAX_BYTES,**settings)
    with pytest.raises(probe.StorageProbeFailure,match=code):
        probe.verify_storage(factory=lambda *_:storage)
    assert storage.deletes == 1
    assert "STORAGE_PROBE_PASS" not in capsys.readouterr().out
