"""Fail closed: an active membership role and signed scope are both required."""
def role_scope_allowed(role: str | None, required_scope: str) -> bool:
    if not isinstance(role, str) or role != role.strip():
        return False
    normalized = role.casefold()
    if normalized == "viewer":
        return required_scope.endswith(":read")
    return normalized in {"editor", "owner", "admin"}
