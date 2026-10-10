from __future__ import annotations
from apishield_agent.presentation.authentication import decode_bearer, verify_session
from apishield_agent.presentation.role_policy import role_scope_allowed

import os
from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException

from apishield_agent.infrastructure.store import Store


def _problem(status: int, code: str, detail: str):
    raise HTTPException(status_code=status, detail={"type":"about:blank","title":"Request rejected","status":status,"code":code,"detail":detail,"request_id":"runtime"})


def claims(authorization: Annotated[str | None, Header()] = None):
    return decode_bearer(authorization)


def require_scope(scope: str, store: Store):
    def dependency(c: dict = Depends(claims)) -> dict:
        verify_session(store, c)
        scopes = set(str(c.get("scope", "")).split())
        tenant, user = c.get("tenant_id"), c.get("sub")
        if not tenant or not user:
            _problem(403, "TENANT_CONTEXT_INVALID", "Verified membership is required")
        role = store.member_role(tenant, user)
        if role is None:
            _problem(403, "TENANT_CONTEXT_INVALID", "Verified membership is required")
        if not role_scope_allowed(role, scope):
            _problem(403, "ROLE_FORBIDDEN", "Membership role cannot perform this operation")
        if scope not in scopes:
            _problem(403, "INSUFFICIENT_SCOPE", f"Scope {scope} is required")
        return c
    return dependency

