"""Private local artifact provider for synthetic development, with bounded capabilities.

This is an actual byte store, not an S3 or malware-scanning certification.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path
from uuid import UUID, uuid4

import jwt
import yaml
from fastapi import HTTPException
from openapi_spec_validator import validate
from apishield_agent.domain.contract_input import load_contract

MAX_BYTES = 2 * 1024 * 1024
TTL = 300


def reject(code: str, detail: str, status: int = 409):
    raise HTTPException(status_code=status, detail={"type": "about:blank", "title": "Artifact rejected", "status": status, "code": code, "detail": detail, "request_id": "runtime"})


class LocalArtifacts:
    def __init__(self, root: Path):
        if root.is_symlink():
            raise ValueError("Artifact root cannot be a symlink")
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.database = self.root / "objects.sqlite"
        with self.connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS objects(tenant TEXT, id TEXT, generation TEXT, sha256 TEXT, size INTEGER, PRIMARY KEY(tenant,id))")

    def connection(self):
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def secret(self):
        if os.getenv("APP_ENV", "development") not in {"development", "test"}:
            reject("LOCAL_STORAGE_FORBIDDEN", "Local storage is only enabled for synthetic test/development", 503)
        secret = os.getenv("ARTIFACT_SIGNING_SECRET", "")
        if len(secret.encode()) < 32 or secret == os.getenv("DEV_AUTH_SECRET"):
            reject("STORAGE_NOT_CONFIGURED", "A separate artifact signing secret of at least 32 bytes is required", 503)
        return secret

    def path(self, tenant: str, artifact_id: str):
        name = f"{UUID(tenant)}_{UUID(artifact_id)}.object"
        target = self.root / name
        if target.is_symlink():
            reject("ARTIFACT_INTEGRITY_FAILURE", "Unsafe object path")
        return target

    def intent(self, tenant, artifact_id, action, generation=None, *, actor=None, session_id=None):
        # Transfer URLs are bearer capabilities, but a valid signature must not
        # outlive revocation of the principal that requested the capability.
        # Require an actor even in synthetic development mode.
        if not isinstance(actor, str) or not actor:
            reject("ARTIFACT_ACTOR_REQUIRED", "Artifact capability requires an owner", 403)
        claims = {"iss": "forgeworks-artifacts", "aud": "artifact-transfer",
                  "sub": str(artifact_id), "tenant_id": str(tenant), "actor": actor,
                  "action": action, "generation": generation,
                  "jti": str(uuid4()), "exp": int(time.time()) + TTL}
        if session_id is not None:
            claims["session_id"] = str(session_id)
        token = jwt.encode(claims, self.secret(), algorithm="HS256")
        return f"/v1/artifact-transfers/{artifact_id}?token={token}", claims["exp"]

    def capability(self, token, artifact_id, action):
        try:
            claims = jwt.decode(token, self.secret(), algorithms=["HS256"], issuer="forgeworks-artifacts", audience="artifact-transfer", options={"require": ["exp", "sub", "tenant_id", "action", "jti"]})
            if claims["sub"] != str(artifact_id) or claims["action"] != action:
                raise jwt.InvalidTokenError("Wrong capability binding")
            if not isinstance(claims.get("actor"), str) or not claims["actor"]:
                raise jwt.InvalidTokenError("Missing capability owner")
            if "session_id" in claims and (not isinstance(claims["session_id"], str) or not claims["session_id"]):
                raise jwt.InvalidTokenError("Invalid session binding")
            self.path(claims["tenant_id"], claims["sub"])
            return claims
        except (jwt.PyJWTError, ValueError):
            reject("INVALID_ARTIFACT_CAPABILITY", "Artifact capability is invalid or expired", 403)

    def put(self, tenant, artifact_id, body: bytes, expected_sha: str, expected_size: int):
        self.secret()
        sha = hashlib.sha256(body).hexdigest()
        if len(body) > MAX_BYTES:
            reject("ARTIFACT_TOO_LARGE", "Artifact exceeds the local provider limit", 413)
        if sha != expected_sha or len(body) != expected_size:
            reject("ARTIFACT_DIGEST_MISMATCH", "Uploaded bytes do not match declared digest and size")
        path = self.path(tenant, artifact_id)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM objects WHERE tenant=? AND id=?", (tenant, artifact_id)).fetchone()
            if old:
                if old["sha256"] != sha or old["size"] != len(body):
                    reject("ARTIFACT_IMMUTABLE", "An object cannot be replaced")
                self.verify(tenant, artifact_id, old["generation"], sha, len(body))
                return dict(old)
            generation = str(uuid4())
            fd, temporary = tempfile.mkstemp(dir=self.root, prefix="quarantine-")
            try:
                with os.fdopen(fd, "wb") as file:
                    file.write(body)
                    file.flush()
                    os.fsync(file.fileno())
                # Link is atomic and cannot replace a previously written object.
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    reject("ARTIFACT_IMMUTABLE", "An existing object cannot be replaced")
                db.execute("INSERT INTO objects VALUES(?,?,?,?,?)", (tenant, artifact_id, generation, sha, len(body)))
            finally:
                os.unlink(temporary)
        return {"generation": generation, "sha256": sha, "size": len(body)}

    def verify(self, tenant, artifact_id, generation, sha, size):
        with self.connection() as db:
            row = db.execute("SELECT * FROM objects WHERE tenant=? AND id=?", (tenant, artifact_id)).fetchone()
        if not row:
            reject("ARTIFACT_BYTES_MISSING", "Upload bytes before committing metadata")
        if row["generation"] != generation or row["sha256"] != sha or row["size"] != size:
            reject("ARTIFACT_GENERATION_MISMATCH", "Object generation, digest or size does not match")
        path = self.path(tenant, artifact_id)
        try:
            flags = os.O_RDONLY | os.O_NOFOLLOW
            fd = os.open(path, flags)
            with os.fdopen(fd, "rb") as file:
                body = file.read(MAX_BYTES + 1)
        except OSError:
            reject("ARTIFACT_INTEGRITY_FAILURE", "Stored object is missing or unsafe")
        if len(body) != size or hashlib.sha256(body).hexdigest() != sha:
            reject("ARTIFACT_INTEGRITY_FAILURE", "Stored bytes fail integrity verification")
        return body

    def validate_contract(self, body: bytes, kind: str):
        if kind not in {"contract", "openapi", "openapi-contract"}:
            reject("ARTIFACT_KIND_UNSUPPORTED", "Only OpenAPI contract artifacts are enabled in the local provider", 422)
        try:
            if any(isinstance(event, yaml.events.AliasEvent) for event in yaml.parse(body)):
                raise ValueError("YAML aliases are disabled")
            document = load_contract(body)
            pending = [document]
            visited = 0
            while pending:
                value = pending.pop()
                visited += 1
                if visited > 20000:
                    raise ValueError("Document exceeds structural limits")
                if isinstance(value, dict):
                    if "$ref" in value and not str(value["$ref"]).startswith("#/"):
                        raise ValueError("External references are disabled")
                    pending.extend(value.values())
                elif isinstance(value, list):
                    pending.extend(value)
            validate(document)
        except Exception:
            reject("ARTIFACT_VALIDATION_FAILED", "Contract failed offline OpenAPI validation; remote references and aliases are disabled", 422)
