from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Path as PathParam, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from apishield_agent.domain.analysis import deterministic_openapi_diff
from apishield_agent.infrastructure.store import Store
from apishield_agent.presentation.auth import claims, require_scope

ROOT = Path(__file__).resolve().parents[4]


class CreateAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_sha: str = Field(pattern=r"^[0-9a-fA-F]{40,64}$")
    head_sha: str = Field(pattern=r"^[0-9a-fA-F]{40,64}$")
    capability_profile: str = Field(min_length=1)


def _iso(v): return v

def _problem(status: int, code: str, detail: str):
    return JSONResponse(status_code=status, content={"type":"about:blank","title":"Request rejected","status":status,"code":code,"detail":detail,"request_id":"runtime"})


def create_app(db_path: str | None = None, seed: bool = False) -> FastAPI:
    path = db_path or os.getenv("APISHIELD_DB_PATH", str(ROOT / ".runtime" / "apishield.db"))
    store = Store(path)
    if seed:
        store.seed_demo(str(ROOT / "fixtures/golden/before.yaml"), str(ROOT / "fixtures/golden/after.yaml"))
    stop = threading.Event()

    def worker():
        while not stop.is_set():
            for row in store.pending():
                repo = store.get_repo(row["tenant_id"], 1, row["repository_id"])
                findings = deterministic_openapi_diff(repo["before_contract"], repo["after_contract"]) if repo else []
                store.finish(row["tenant_id"], row["id"], findings)
            stop.wait(0.05)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        t = threading.Thread(target=worker, name="apishield-worker", daemon=True); t.start()
        yield
        stop.set(); t.join(timeout=1)

    app = FastAPI(title="APIShield Agent MVP", version="0.1.0", lifespan=lifespan)
    app.state.store = store

    @app.exception_handler(HTTPException)
    async def http_error(_, exc: HTTPException):
        if isinstance(exc.detail, dict): return JSONResponse(status_code=exc.status_code, content=exc.detail)
        return _problem(exc.status_code, "REQUEST_REJECTED", str(exc.detail))

    @app.get("/healthz")
    def health(): return {"status":"ok","service":"apishield-agent"}

    @app.post("/v1/installations/{installation_id}/repositories/{repository_id}/analyses", status_code=202)
    def start_analysis(installation_id: int, repository_id: UUID, body: CreateAnalysis, idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None, c: dict = Depends(require_scope("repo:analyze", store))):
        if not idempotency_key or not 16 <= len(idempotency_key) <= 128:
            return _problem(400, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key must be 16-128 characters")
        repo = store.get_repo(c["tenant_id"], installation_id, str(repository_id))
        if repo is None:
            return _problem(404, "RESOURCE_NOT_FOUND", "Repository is not visible")
        payload = body.model_dump(); request_sha = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        previous = store.get_idempotent(c["tenant_id"], c["sub"], idempotency_key)
        if previous:
            if previous["request_sha"] != request_sha: return _problem(409, "IDEMPOTENCY_CONFLICT", "Idempotency key was used with a different request")
            row = store.get_analysis(c["tenant_id"], previous["analysis_id"])
        else:
            row = store.create_analysis(c["tenant_id"], c["sub"], str(repository_id), body.base_sha, body.head_sha, body.capability_profile, idempotency_key, request_sha)
        return {"id":row["id"],"status":row["status"],"created_at":row["created_at"],"repository_id":row["repository_id"],"base_sha":row["base_sha"],"head_sha":row["head_sha"],"capability_profile":row["capability_profile"],"job_id":row["job_id"]}

    def get_analysis(analysis_id: UUID, c: dict):
        row = store.get_analysis(c["tenant_id"], str(analysis_id))
        if not row: return _problem(404, "RESOURCE_NOT_FOUND", "Analysis is not visible")
        fs = store.findings(c["tenant_id"], str(analysis_id))
        return {"id":row["id"],"status":row["status"],"created_at":row["created_at"],"repository_id":row["repository_id"],"base_sha":row["base_sha"],"head_sha":row["head_sha"],"finding_count":len(fs),"unsupported_count":0,**({"completed_at":row["completed_at"]} if row["completed_at"] else {})}

    @app.get("/v1/analyses/{analysis_id}")
    def read_analysis(analysis_id: UUID, c: dict = Depends(require_scope("analysis:read", store))): return get_analysis(analysis_id, c)

    @app.get("/v1/analyses/{analysis_id}/findings")
    def read_findings(analysis_id: UUID, c: dict = Depends(require_scope("analysis:read", store)), cursor: Annotated[str | None, Query()] = None):
        if not store.get_analysis(c["tenant_id"], str(analysis_id)): return _problem(404, "RESOURCE_NOT_FOUND", "Analysis is not visible")
        items = [{"id":f["id"],"rule_id":f["rule_id"],"severity":f["severity"],"openapi_pointer":f["openapi_pointer"],"evidence_digest":f["evidence_digest"],"coverage":f["coverage"]} for f in store.findings(c["tenant_id"], str(analysis_id))]
        return {"items":items,"next_cursor":None,"has_more":False}

    @app.get("/v1/jobs/{job_id}")
    def read_job(job_id: UUID, c: dict = Depends(require_scope("job:read", store))):
        row = None
        with store.conn() as db: row = db.execute("SELECT * FROM analyses WHERE tenant_id=? AND job_id=?", (c["tenant_id"],str(job_id))).fetchone()
        if not row: return _problem(404, "RESOURCE_NOT_FOUND", "Job is not visible")
        states={"PENDING":"PENDING","SUCCEEDED":"SUCCEEDED"}
        return {"id":row["job_id"],"kind":"analysis","state":states.get(row["status"],"FAILED_TERMINAL"),"created_at":row["created_at"],"state_version":row["version"],"attempt_count":1,"last_error_code":None}

    return app


app = create_app(seed=os.getenv("APISHIELD_SEED_FIXTURE", "0") == "1")
