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
    "apishield-agent": ("analyses", None),
    "accessfix-ai": ("scans", "findings"),
    "specforge-ai": ("spec-revisions", "openapi"),
    "agenttest-lab": ("evaluation-runs", "cases"),
    "datareconcile-ai": ("reports", "signature"),
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
    resource_name, suffix = _PRODUCTS[product]
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
                     upstream_path="/v1/" + resource_name + "/" +
                     object_id + ("/" + suffix if suffix else ""))


def can_forward(_route: ReadRoute, *, trusted_identity=None) -> bool:
    """Fail closed until the signed-session and audience boundary exists.

    Passing a caller-supplied `trusted_identity` value must not unlock a
    private backend route. A future BFF must replace this with independently
    verified, correctly scoped and tested session/tenant authorization.
    """
    return False
