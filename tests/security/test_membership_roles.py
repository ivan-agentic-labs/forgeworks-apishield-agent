"""Role must not be bypassed by broader signed token scopes."""
import pytest
from fastapi import HTTPException
from apishield_agent.presentation import auth as api
from apishield_agent.presentation.role_policy import role_scope_allowed

class Store:
    def __init__(self, role):
        self.role=role
        self.lookups=0
    def member_role(self, tenant, user):
        assert tenant=="tenant-1" and user=="user-1"
        self.lookups+=1
        return self.role

@pytest.mark.parametrize(("role","permission","allowed"),[
    ("viewer","job:read",True),
    ("viewer","artifact:read",True),
    ("viewer","artifact:create",False),
    ("viewer","analysis:approve",False),
    ("editor","artifact:create",True),
    ("owner","artifact:create",True),
    ("admin","artifact:create",True),
    ("reviewer","job:read",False),
    (None,"job:read",False),
])
def test_role_matrix(role, permission, allowed):
    assert role_scope_allowed(role,permission) is allowed

def test_viewer_writes_fail_even_with_signed_scope(monkeypatch):
    monkeypatch.setattr(api,"verify_session",lambda *_: None)
    store=Store("viewer")
    claims={"tenant_id":"tenant-1","sub":"user-1","scope":"job:read artifact:create"}
    with pytest.raises(HTTPException) as error:
        api.require_scope("artifact:create",store)(claims)
    assert error.value.status_code==403
    assert error.value.detail["code"]=="ROLE_FORBIDDEN"
    assert store.lookups==1
    assert api.require_scope("job:read",Store("viewer"))(claims)==claims

def test_editor_still_needs_signed_scope(monkeypatch):
    monkeypatch.setattr(api,"verify_session",lambda *_: None)
    claims={"tenant_id":"tenant-1","sub":"user-1","scope":"job:read"}
    with pytest.raises(HTTPException) as error:
        api.require_scope("artifact:create",Store("editor"))(claims)
    assert error.value.detail["code"]=="INSUFFICIENT_SCOPE"

def test_absent_membership_denied(monkeypatch):
    monkeypatch.setattr(api,"verify_session",lambda *_: None)
    claims={"tenant_id":"tenant-1","sub":"user-1","scope":"job:read"}
    with pytest.raises(HTTPException) as error:
        api.require_scope("job:read",Store(None))(claims)
    assert error.value.detail["code"]=="TENANT_CONTEXT_INVALID"
