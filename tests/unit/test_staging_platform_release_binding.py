"""Ensure staging release identity follows the real Railway commit with fail-closed pins."""
from pathlib import Path

import pytest

from apishield_agent.presentation import operations


@pytest.fixture
def staging_binding(monkeypatch):
    monkeypatch.setenv("APP_ENV", "staging")
    monkeypatch.setattr(
        operations, "deployed_manifest",
        lambda _root: {"profile": "unit-runtime-manifest", "sha256": "b" * 64},
    )


@pytest.mark.parametrize("operator_sha", ["", "a" * 40])
def test_platform_commit_is_reported_without_stale_operator_pin(staging_binding, monkeypatch, operator_sha):
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "a" * 40)
    monkeypatch.setenv("FORGEWORKS_RELEASE_SHA", operator_sha)
    identity = operations.runtime_identity(Path("."), "apishield-agent")
    assert identity["revision_sha"] == "a" * 40
    assert identity["environment"] == "staging"


def test_stale_operator_pin_is_rejected(staging_binding, monkeypatch):
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", "a" * 40)
    monkeypatch.setenv("FORGEWORKS_RELEASE_SHA", "c" * 40)
    with pytest.raises(ValueError, match="RUNTIME_REVISION_BINDING_MISMATCH"):
        operations.runtime_identity(Path("."), "apishield-agent")


def test_staging_requires_platform_or_operator_provenance(staging_binding, monkeypatch):
    monkeypatch.delenv("RAILWAY_GIT_COMMIT_SHA", raising=False)
    monkeypatch.delenv("FORGEWORKS_RELEASE_SHA", raising=False)
    with pytest.raises(ValueError, match="RUNTIME_REVISION_REQUIRED"):
        operations.runtime_identity(Path("."), "apishield-agent")


@pytest.mark.parametrize("bad_sha", ["not-a-sha", "A" * 40, "a" * 39])
def test_staging_rejects_invalid_platform_revision(staging_binding, monkeypatch, bad_sha):
    monkeypatch.setenv("RAILWAY_GIT_COMMIT_SHA", bad_sha)
    monkeypatch.delenv("FORGEWORKS_RELEASE_SHA", raising=False)
    with pytest.raises(ValueError, match="RUNTIME_REVISION_INVALID"):
        operations.runtime_identity(Path("."), "apishield-agent")
