"""Pure, intentionally non-networking ForgeWorks BFF route admission policy.

Route parsing is *not* authentication or authorization. The eventual
same-origin BFF must validate a real session, enforce workspace membership,
apply per-service authorization and have a separate audited egress transport.
This library only constructs plans for five fixed, read-only API endpoints.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from uuid import UUID

_PRODUCTS = {
    "apishield-agent": ("analyses", None, "analysis:read"),
    "accessfix-ai": ("scans", "findings", "scan:read"),
    "specforge-ai": ("spec-revisions", "openapi", "spec:read"),
    "agenttest-lab": ("evaluation-runs", "cases", "evaluation:read"),
    "datareconcile-ai": ("reports", "signature", "report:read"),
}
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


class RouteDenied(ValueError):
    """A request is not a documented read-only product resource."""


@dataclass(frozen=True)
class ReadRoute:
    product: str
    resource_id: str
    upstream_path: str
    method: str = "GET"
    required_scope: str = ""
    requires_verified_session: bool = True
    forward_enabled: bool = False


def plan_read(raw_target: str, *, method: str = "GET") -> ReadRoute:
    if method != "GET" or not isinstance(raw_target, str):
        raise RouteDenied("METHOD_OR_TARGET_DENIED")
    # Deliberately no URI-decoding, request-defined hosts, query parameters
    # or fragment components. Allowlisted literal ASCII path only.
    if (not 1 <= len(raw_target) <= 240
        or not raw_target.isascii()
        or any(c in raw_target for c in "%\\?#@;\x00\r\n\t")
        or "//" in raw_target or raw_target.endswith("/")):
        raise RouteDenied("AMBIGUOUS_TARGET")
    pieces = raw_target.split("/")
    if len(pieces) not in (6, 7) or pieces[:2] != ["", "api"]:
        raise RouteDenied("UNKNOWN_ROUTE")
    product = pieces[2]
    if product not in _PRODUCTS or pieces[3] != "v1":
        raise RouteDenied("UNKNOWN_PRODUCT_OR_VERSION")
    resource_name, suffix, scope = _PRODUCTS[product]
    if pieces[4] != resource_name:
        raise RouteDenied("UNKNOWN_RESOURCE")
    # The last segment is the resource ID for the single-segment route;
    # for the two-segment route, it is followed by a fixed suffix.
    if suffix is None:
        if len(pieces) != 6:
            raise RouteDenied("UNKNOWN_RESOURCE")
        object_id = pieces[5]
    else:
        if len(pieces) != 7 or pieces[6] != suffix:
            raise RouteDenied("UNKNOWN_RESOURCE")
        object_id = pieces[5]
    if not _UUID.fullmatch(object_id):
        raise RouteDenied("INVALID_RESOURCE_ID")
    try:
        if str(UUID(object_id)) != object_id:
            raise ValueError("NONCANONICAL_UUID")
    except (ValueError, AttributeError) as exc:
        raise RouteDenied("INVALID_RESOURCE_ID") from exc
    return ReadRoute(product=product, resource_id=object_id,
                     required_scope=scope, upstream_path="/v1/" + resource_name + "/" +
                     object_id + ("/" + suffix if suffix else ""))


def can_forward(_route: ReadRoute, *, trusted_identity=None) -> bool:
    """Fail closed until the signed-session and audience boundary exists.

    Passing a caller-supplied `trusted_identity` value must not unlock a
    private backend route. A future BFF must replace this with independently
    verified, correctly scoped and tested session/tenant authorization.
    """
    return False


@dataclass(frozen=True)
class ReviewedSessionSnapshot:
    """Offline policy input, NOT an authenticated session or verifiable token.

    A future BFF may construct this only after an independent OIDC/JWKS and
    live membership/session check. This object itself proves none of that.
    """
    product: str
    tenant_id: str
    subject: str
    session_id: str
    scopes: frozenset[str]
    member_role: str
    session_active: bool
    membership_active: bool
    expires_at: int


def preflight_read(route: ReadRoute, snapshot: ReviewedSessionSnapshot,
                   *, workspace_id: str, now: int) -> bool:
    """Pure conservative policy test. This NEVER grants forwarding authority."""
    if (type(route) is not ReadRoute or type(snapshot) is not ReviewedSessionSnapshot
            or route.forward_enabled or route.method != "GET"
            or not route.requires_verified_session or route.product not in _PRODUCTS
            or route.required_scope != _PRODUCTS[route.product][2]
            or type(now) is not int or type(snapshot.expires_at) is not int
            or now < 0 or snapshot.expires_at <= now
            or snapshot.product != route.product
            or snapshot.session_active is not True
            or snapshot.membership_active is not True
            or type(snapshot.scopes) is not frozenset
            or route.required_scope not in snapshot.scopes
            or snapshot.member_role not in {"viewer", "editor", "owner", "admin"}):
        return False
    # Never treat a hand-crafted ReadRoute as an authorized upstream URL.
    # Exact allowlist round-trip is mandatory even in this offline preflight.
    try:
        canonical = plan_read("/api/" + route.product + route.upstream_path)
    except RouteDenied:
        return False
    if route != canonical:
        return False
    for value in (workspace_id, snapshot.tenant_id, snapshot.subject,
                  snapshot.session_id):
        if type(value) is not str or not _UUID.fullmatch(value):
            return False
        try:
            if str(UUID(value)) != value:
                return False
        except ValueError:
            return False
    return workspace_id == snapshot.tenant_id
