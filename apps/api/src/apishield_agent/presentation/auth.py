from __future__ import annotations

import os
from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException

from apishield_agent.infrastructure.store import Store


def _problem(status: int, code: str, detail: str):
    raise HTTPException(status_code=status, detail={"type":"about:blank","title":"Request rejected","status":status,"code":code,"detail":detail,"request_id":"runtime"})


def claims(authorization: Annotated[str | None, Header()] = None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        _problem(401, "UNAUTHENTICATED", "Bearer token is required")
    token = authorization[7:]
    secret = os.getenv("DEV_AUTH_SECRET", "forgeworks-development-secret-32-plus")
    if os.getenv("APP_ENV", "development") == "production" and secret == "forgeworks-development-secret-32-plus":
        _problem(500, "AUTH_NOT_CONFIGURED", "Production issuer secret is not configured")
    try:
        return jwt.decode(token, secret, algorithms=["HS256"], issuer=os.getenv("AUTH_ISSUER", "https://issuer.synthetic.invalid"), audience=os.getenv("AUTH_AUDIENCE", "forgeworks-api"))
    except jwt.PyJWTError:
        _problem(401, "INVALID_TOKEN", "Token signature, issuer, audience, or expiry is invalid")


def require_scope(scope: str, store: Store):
    def dependency(c: dict = Depends(claims)) -> dict:
        scopes = set(str(c.get("scope", "")).split())
        tenant, user = c.get("tenant_id"), c.get("sub")
        if not tenant or not user or not store.member(tenant, user):
            _problem(403, "TENANT_CONTEXT_INVALID", "Verified membership is required")
        if scope not in scopes:
            _problem(403, "INSUFFICIENT_SCOPE", f"Scope {scope} is required")
        return c
    return dependency
