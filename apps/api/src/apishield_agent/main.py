from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from apishield_agent.application.analysis_worker import AnalysisWorker
from apishield_agent.infrastructure.store import Store, stable_uuid
from apishield_agent.infrastructure.local_artifacts import LocalArtifacts, MAX_BYTES
from apishield_agent.presentation.auth import require_scope

ROOT = Path(__file__).resolve().parents[4]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateAnalysis(StrictModel):
    base_sha: str = Field(pattern=r"^[0-9a-fA-F]{40,64}$")
    head_sha: str = Field(pattern=r"^[0-9a-fA-F]{40,64}$")
    capability_profile: str = Field(min_length=1)


class CreateProposal(StrictModel):
    analysis_id: UUID
    target_language: str = Field(min_length=1)


class ApproveProposal(StrictModel):
    patch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    base_sha: str = Field(pattern=r"^[0-9a-fA-F]{40,64}$")
    decision: str = Field(pattern=r"^(approve|reject)$")
    expected_version: int = Field(ge=1)


class CreatePullRequest(StrictModel):
    approval_id: UUID
    target_branch: str = Field(min_length=1)


class CreateUploadIntent(StrictModel):
    kind: str = Field(min_length=1)
    filename: str = Field(min_length=1)
    size_bytes: int = Field(ge=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    declared_media_type: str | None = None


class CommitUpload(StrictModel):
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1)
    object_generation: str = Field(min_length=1)


def _problem(status: int, code: str, detail: str):
    return JSONResponse(status_code=status, content={"type": "about:blank", "title": "Request rejected", "status": status, "code": code, "detail": detail, "request_id": "runtime"})


def _key(key: str | None):
    if not key or not 16 <= len(key) <= 128:
        return _problem(400, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key must be 16-128 characters")
    return None


def _sha(payload) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _analysis(row):
    return {"id": row["id"], "status": row["status"], "created_at": row["created_at"], "repository_id": row["repository_id"], "base_sha": row["base_sha"], "head_sha": row["head_sha"], "capability_profile": row["capability_profile"], "job_id": row["job_id"]}


def _artifact(row):
    return {"id": row["id"], "status": row["status"], "kind": row["kind"], "sha256": row["sha256"], "size_bytes": row["size_bytes"], "created_at": row["created_at"], "rejected_reason": row["rejected_reason"]}


def _proposal(row):
    return {"id": row["id"], "status": row["status"], "created_at": row["created_at"], "analysis_id": row["analysis_id"], "base_sha": row["base_sha"], "patch_sha256": row["patch_sha256"], "sandbox_status": row["sandbox_status"], "approval_status": row["approval_status"], "version": row["version"]}


def _approval(row):
    return {"id": row["id"], "status": row["status"], "created_at": row["created_at"], "proposal_id": row["proposal_id"], "patch_sha256": row["patch_sha256"], "base_sha": row["base_sha"], "reviewer_id": row["reviewer_id"], "expires_at": row["expires_at"]}


def _reviewer(value: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, AttributeError):
        return stable_uuid(f"reviewer:{value}")


def create_app(db_path: str | None = None, seed: bool = False) -> FastAPI:
    path = db_path or os.getenv("APISHIELD_DB_PATH", str(ROOT / ".runtime" / "apishield.db"))
    dsn = os.getenv("APISHIELD_DATABASE_URL")
    if dsn:
        from apishield_agent.infrastructure.postgres_store import PostgresStore
        store = PostgresStore(dsn)
    else:
        if os.getenv("APP_ENV", "development") not in {"development", "test"}:
            raise ValueError("SQLite runtime is restricted to synthetic development/test")
        store = Store(path)
    artifacts = LocalArtifacts(Path(os.getenv("APISHIELD_ARTIFACT_ROOT", str(Path(path).parent / "artifacts"))))
    if seed:
        store.seed_demo(str(ROOT / "fixtures/golden/before.yaml"), str(ROOT / "fixtures/golden/after.yaml"))
    stop = threading.Event()

    analysis_worker = AnalysisWorker(store)
    def worker():
        analysis_worker.serve(stop)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        t = threading.Thread(target=worker, name="apishield-worker", daemon=True)
        embedded = os.getenv("APISHIELD_EMBEDDED_WORKER", "1") == "1"
        if embedded:
            t.start()
        try:
            yield
        finally:
            stop.set()
            if embedded:
                t.join(timeout=5)

    app = FastAPI(title="APIShield Agent MVP", version="0.2.0", lifespan=lifespan)
    cors_origins = [origin.strip() for origin in os.getenv("APISHIELD_CORS_ORIGINS", "").split(",") if origin.strip()]
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "OPTIONS"],
            allow_headers=["Authorization", "Accept", "Content-Type"],
        )
    app.state.store = store

    @app.exception_handler(HTTPException)
    async def http_error(_, exc: HTTPException):
        if isinstance(exc.detail, dict):
            return JSONResponse(status_code=exc.status_code, content=exc.detail)
        return _problem(exc.status_code, "REQUEST_REJECTED", str(exc.detail))

    @app.get("/healthz")
    def health():
        return {"status": "ok", "service": "apishield-agent"}

    @app.post("/v1/installations/{installation_id}/repositories/{repository_id}/analyses", status_code=202)
    def start_analysis(installation_id: int, repository_id: UUID, body: CreateAnalysis, idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None, c: dict = Depends(require_scope("repo:analyze", store))):
        bad = _key(idempotency_key)
        if bad:
            return bad
        repo = store.get_repo(c["tenant_id"], installation_id, str(repository_id))
        if repo is None:
            return _problem(404, "RESOURCE_NOT_FOUND", "Repository is not visible")
        request_sha = _sha({"installation_id": installation_id, "repository_id": str(repository_id), "body": body.model_dump()})
        previous = store.get_idempotent(c["tenant_id"], c["sub"], idempotency_key)
        if previous:
            if previous["request_sha"] != request_sha:
                return _problem(409, "IDEMPOTENCY_CONFLICT", "Idempotency key was used with a different request")
            row = store.get_analysis(c["tenant_id"], previous["analysis_id"])
        else:
            try:
                row = store.create_analysis(c["tenant_id"], c["sub"], str(repository_id), body.base_sha, body.head_sha, body.capability_profile, idempotency_key, request_sha)
            except ValueError as error:
                if str(error) == "IDEMPOTENCY_CONFLICT":
                    return _problem(409, "IDEMPOTENCY_CONFLICT", "Idempotency key was used with a different request")
                raise
        return _analysis(row)

    @app.get("/v1/analyses/{analysis_id}")
    def read_analysis(analysis_id: UUID, c: dict = Depends(require_scope("analysis:read", store))):
        row = store.get_analysis(c["tenant_id"], str(analysis_id))
        if not row:
            return _problem(404, "RESOURCE_NOT_FOUND", "Analysis is not visible")
        return {"id": row["id"], "status": row["status"], "created_at": row["created_at"], "repository_id": row["repository_id"], "base_sha": row["base_sha"], "head_sha": row["head_sha"], "finding_count": store.finding_count(c["tenant_id"], str(analysis_id)), "unsupported_count": 0, **({"completed_at": row["completed_at"]} if row["completed_at"] else {})}

    @app.get("/v1/analyses/{analysis_id}/findings")
    def read_findings(analysis_id: UUID, cursor: Annotated[str | None, Query(max_length=1024)] = None, limit: Annotated[int, Query(ge=1, le=100)] = 50, c: dict = Depends(require_scope("analysis:read", store))):
        if not store.get_analysis(c["tenant_id"], str(analysis_id)):
            return _problem(404, "RESOURCE_NOT_FOUND", "Analysis is not visible")
        try:
            offset = int(base64.urlsafe_b64decode(cursor.encode()).decode()) if cursor else 0
            if offset < 0:
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            return _problem(400, "INVALID_CURSOR", "Cursor is invalid")
        items = store.findings(c["tenant_id"], str(analysis_id), offset, limit)
        total = store.finding_count(c["tenant_id"], str(analysis_id))
        next_cursor = base64.urlsafe_b64encode(str(offset + len(items)).encode()).decode() if offset + len(items) < total else None
        return {"items": [{"id": f["id"], "rule_id": f["rule_id"], "severity": f["severity"], "openapi_pointer": f["openapi_pointer"], "evidence_digest": f["evidence_digest"], "coverage": f["coverage"]} for f in items], "next_cursor": next_cursor, "has_more": next_cursor is not None}

    @app.post("/v1/analyses/{analysis_id}/proposals", status_code=201)
    def create_proposal(analysis_id: UUID, body: CreateProposal, idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None, c: dict = Depends(require_scope("patch:create", store))):
        bad = _key(idempotency_key)
        if bad:
            return bad
        if body.analysis_id != analysis_id:
            return _problem(400, "ANALYSIS_ID_MISMATCH", "Body analysis_id must match path")
        analysis = store.get_analysis(c["tenant_id"], str(analysis_id))
        if not analysis:
            return _problem(404, "RESOURCE_NOT_FOUND", "Analysis is not visible")
        if analysis["status"] != "SUCCEEDED":
            return _problem(409, "ANALYSIS_NOT_READY", "Analysis must succeed before proposal creation")
        request_sha = _sha(body.model_dump(mode="json"))
        old = store.command(c["tenant_id"], c["sub"], "proposal.create", idempotency_key)
        if old:
            if old["request_sha"] != request_sha:
                return _problem(409, "IDEMPOTENCY_CONFLICT", "Idempotency key was used with a different request")
            return _proposal(store.proposal(c["tenant_id"], old["resource_id"]))
        row = store.create_proposal(c["tenant_id"], str(analysis_id), body.target_language)
        store.create_command(c["tenant_id"], c["sub"], "proposal.create", idempotency_key, request_sha, row["id"])
        return _proposal(row)

    @app.get("/v1/proposals/{proposal_id}/patch")
    def read_patch(proposal_id: UUID, c: dict = Depends(require_scope("patch:read", store))):
        proposal = store.proposal(c["tenant_id"], str(proposal_id))
        content = store.proposal_patch(c["tenant_id"], str(proposal_id))
        if not proposal or not content:
            return _problem(404, "RESOURCE_NOT_FOUND", "Proposal patch bytes are not visible")
        body = content["patch_text"].encode()
        if hashlib.sha256(body).hexdigest() != proposal["patch_sha256"]:
            return _problem(409, "PATCH_INTEGRITY_FAILURE", "Proposal bytes do not match the approved digest")
        return Response(body, media_type="text/plain", headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    @app.post("/v1/proposals/{proposal_id}/approvals", status_code=201)
    def approve_proposal(proposal_id: UUID, body: ApproveProposal, idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None, c: dict = Depends(require_scope("patch:approve", store))):
        bad = _key(idempotency_key)
        if bad:
            return bad
        request_sha = _sha(body.model_dump())
        old = store.command(c["tenant_id"], c["sub"], "proposal.approve", idempotency_key)
        if old:
            if old["request_sha"] != request_sha:
                return _problem(409, "IDEMPOTENCY_CONFLICT", "Idempotency key was used with a different request")
            return _approval(store.approval(c["tenant_id"], old["resource_id"]))
        row, error = store.approve(c["tenant_id"], str(proposal_id), body.patch_sha256, body.base_sha, body.decision, body.expected_version, _reviewer(c["sub"]))
        if error == "NOT_FOUND":
            return _problem(404, "RESOURCE_NOT_FOUND", "Proposal is not visible")
        if error == "STALE_VERSION":
            return _problem(409, "STALE_VERSION", "Proposal version is stale")
        if error == "STALE_ARTIFACT":
            return _problem(409, "STALE_ARTIFACT", "Approval does not match the current patch or base")
        store.create_command(c["tenant_id"], c["sub"], "proposal.approve", idempotency_key, request_sha, row["id"])
        return _approval(row)

    @app.post("/v1/proposals/{proposal_id}/pull-requests", status_code=202)
    def create_pull_request(proposal_id: UUID, body: CreatePullRequest, idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None, c: dict = Depends(require_scope("github:write", store))):
        return _problem(403, "GITHUB_WRITE_DISABLED", "GitHub writes are not enabled in this MVP")

    @app.post("/v1/artifacts/upload-intents", status_code=201)
    def upload_intent(body: CreateUploadIntent, idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None, c: dict = Depends(require_scope("artifact:create", store))):
        bad = _key(idempotency_key)
        if bad:
            return bad
        request_sha = _sha(body.model_dump())
        old = store.command(c["tenant_id"], c["sub"], "artifact.intent", idempotency_key)
        if old:
            if old["request_sha"] != request_sha:
                return _problem(409, "IDEMPOTENCY_CONFLICT", "Idempotency key was used with a different request")
            row = store.artifact(c["tenant_id"], old["resource_id"])
        else:
            row = store.create_artifact(c["tenant_id"], body.kind, body.filename, body.declared_media_type, body.sha256, body.size_bytes)
            store.create_command(c["tenant_id"], c["sub"], "artifact.intent", idempotency_key, request_sha, row["id"])
        url, expires = artifacts.intent(c["tenant_id"], row["id"], "upload")
        return {"artifact_id": row["id"], "status": "INTENT_ISSUED", "upload_url": url, "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat().replace("+00:00", "Z"), "required_headers": {"x-artifact-sha256": row["sha256"]}}

    @app.post("/v1/artifacts/{artifact_id}/commit", status_code=202)
    def commit_artifact(artifact_id: UUID, body: CommitUpload, idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None, c: dict = Depends(require_scope("artifact:commit", store))):
        bad = _key(idempotency_key)
        if bad:
            return bad
        request_sha = _sha(body.model_dump())
        old = store.command(c["tenant_id"], c["sub"], "artifact.commit", idempotency_key)
        if old:
            if old["request_sha"] != request_sha:
                return _problem(409, "IDEMPOTENCY_CONFLICT", "Idempotency key was used with a different request")
            return _artifact(store.artifact(c["tenant_id"], old["resource_id"]))
        intent = store.artifact(c["tenant_id"], str(artifact_id))
        if intent and intent["sha256"] == body.sha256 and intent["size_bytes"] == body.size_bytes:
            content = artifacts.verify(c["tenant_id"], str(artifact_id), body.object_generation, body.sha256, body.size_bytes)
            artifacts.validate_contract(content, intent["kind"])
        row, error = store.commit_artifact(c["tenant_id"], str(artifact_id), body.sha256, body.size_bytes, body.object_generation)
        if error == "NOT_FOUND":
            return _problem(404, "RESOURCE_NOT_FOUND", "Artifact is not visible")
        if error == "DIGEST_MISMATCH":
            return _problem(409, "ARTIFACT_DIGEST_MISMATCH", "Committed object digest or size does not match the intent")
        if error:
            return _problem(409, "INVALID_ARTIFACT_STATE", "Artifact cannot be committed in its current state")
        store.create_command(c["tenant_id"], c["sub"], "artifact.commit", idempotency_key, request_sha, str(artifact_id))
        return _artifact(row)

    @app.get("/v1/artifacts/{artifact_id}")
    def get_artifact(artifact_id: UUID, c: dict = Depends(require_scope("artifact:read", store))):
        row = store.artifact(c["tenant_id"], str(artifact_id))
        return _artifact(row) if row else _problem(404, "RESOURCE_NOT_FOUND", "Artifact is not visible")

    @app.post("/v1/artifacts/{artifact_id}/download-intents", status_code=201)
    def download_intent(artifact_id: UUID, idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None, c: dict = Depends(require_scope("artifact:download", store))):
        bad = _key(idempotency_key)
        if bad:
            return bad
        row = store.artifact(c["tenant_id"], str(artifact_id))
        if not row:
            return _problem(404, "RESOURCE_NOT_FOUND", "Artifact is not visible")
        if row["status"] != "AVAILABLE":
            return _problem(409, "ARTIFACT_NOT_AVAILABLE", "Artifact is not available for download")
        artifacts.verify(c["tenant_id"], row["id"], row["object_generation"], row["sha256"], row["size_bytes"])
        url, expires = artifacts.intent(c["tenant_id"], row["id"], "download", row["object_generation"])
        return {"artifact_id": row["id"], "download_url": url, "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat().replace("+00:00", "Z"), "object_generation": row["object_generation"]}

    @app.put("/v1/artifact-transfers/{artifact_id}", status_code=201)
    async def upload_bytes(artifact_id: UUID, request: Request, token: str = Query(max_length=4096)):
        claims = artifacts.capability(token, artifact_id, "upload")
        row = store.artifact(claims["tenant_id"], str(artifact_id))
        if not row or row["status"] != "INTENT_ISSUED":
            return _problem(409, "ARTIFACT_NOT_PENDING", "Artifact is not pending upload")
        if datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) <= datetime.now(timezone.utc):
            return _problem(410, "ARTIFACT_INTENT_EXPIRED", "Upload intent has expired")
        if row["size_bytes"] > MAX_BYTES:
            return _problem(413, "ARTIFACT_TOO_LARGE", "Artifact exceeds the local provider limit")
        content = bytearray()
        async for chunk in request.stream():
            content.extend(chunk)
            if len(content) > min(MAX_BYTES, row["size_bytes"]):
                return _problem(413, "ARTIFACT_TOO_LARGE", "Uploaded body exceeds declared size")
        metadata = artifacts.put(claims["tenant_id"], str(artifact_id), bytes(content), row["sha256"], row["size_bytes"])
        return {"artifact_id": str(artifact_id), "object_generation": metadata["generation"], "sha256": metadata["sha256"], "size_bytes": metadata["size"]}

    @app.get("/v1/artifact-transfers/{artifact_id}")
    def download_bytes(artifact_id: UUID, token: str = Query(max_length=4096)):
        claims = artifacts.capability(token, artifact_id, "download")
        row = store.artifact(claims["tenant_id"], str(artifact_id))
        if not row or row["status"] != "AVAILABLE":
            return _problem(409, "ARTIFACT_NOT_AVAILABLE", "Artifact is not available")
        body = artifacts.verify(claims["tenant_id"], str(artifact_id), claims["generation"], row["sha256"], row["size_bytes"])
        return Response(body, media_type="application/octet-stream", headers={"Content-Disposition": "attachment", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})

    @app.get("/v1/jobs/{job_id}")
    def read_job(job_id: UUID, c: dict = Depends(require_scope("job:read", store))):
        with store.conn(c["tenant_id"]) as db:
            row = db.execute("SELECT * FROM analyses WHERE tenant_id=? AND job_id=?", (c["tenant_id"], str(job_id))).fetchone()
        if not row:
            return _problem(404, "RESOURCE_NOT_FOUND", "Job is not visible")
        return {"id": row["job_id"], "kind": "analysis", "state": row["status"] if row["status"] in {"PENDING", "RUNNING", "SUCCEEDED", "FAILED_TERMINAL"} else "FAILED_TERMINAL", "created_at": row["created_at"], "state_version": row["version"], "attempt_count": row["attempt_count"], "last_error_code": row["last_error_code"]}

    return app


app = create_app(seed=os.getenv("APISHIELD_SEED_FIXTURE", "0") == "1")

