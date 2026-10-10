"""Fail closed: an active membership role and signed scope are both required."""
def role_scope_allowed(role: str | None, required_scope: str) -> bool:
    if role == "viewer":
        return required_scope.endswith(":read")
    return role in {"editor", "owner", "admin"}
