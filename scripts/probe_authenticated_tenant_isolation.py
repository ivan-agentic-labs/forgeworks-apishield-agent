"""Opt-in *real authenticated* cross-tenant staging acceptance probe.

Requires two separately approved Supabase test accounts with distinct active
memberships and a real owned business resource per tenant, per product.
This script never provisions accounts, writes records, echoes tokens or prints
resource identities. The remote APIs, not unverified local JWT decoding,
authenticate each request. No pass is possible without real accepted reads.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request
from uuid import UUID

from verify_cross_product_staging import PRODUCTS, FAKE_RESOURCE, TIMEOUT_SECONDS, _NO_REDIRECT_OPENER
from verify_fleet_release import (
    MAX_PLAN_BYTES, unique_object, validate_plan, verify_fleet,
)


STAGING_SUPABASE_ISSUER = "https://fljekuwplgkrpdoajyhn.supabase.co/auth/v1"
TOKEN_CLOCK_SKEW_SECONDS = 30

PRODUCT_ALIASES = {
    "apishield-agent": "APISHIELD",
    "accessfix-ai": "ACCESSFIX",
    "specforge-ai": "SPECFORGE",
    "agenttest-lab": "AGENTTEST",
    "datareconcile-ai": "DATARECONCILE",
}


class AcceptanceError(ValueError):
    pass


def _uuid(value: object) -> str:
    if not isinstance(value, str) or len(value) != 36:
        raise AcceptanceError("Expected a canonical UUID fixture")
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError) as error:
        raise AcceptanceError("Invalid fixture UUID") from error
    if str(parsed) != value:
        raise AcceptanceError("Noncanonical fixture UUID")
    return value


def _token_claims(value: str) -> dict:
    if not isinstance(value, str) or not 100 <= len(value) <= 16384 or any(ch.isspace() for ch in value):
        raise AcceptanceError("Valid independent bearer tokens are required")
    pieces = value.split(".")
    if len(pieces) != 3 or not all(pieces):
        raise AcceptanceError("Malformed test access token")
    try:
        payload = base64.urlsafe_b64decode(pieces[1] + "=" * (-len(pieces[1]) % 4))
        if len(payload) > 8192:
            raise ValueError("Token claims exceed budget")
        result = json.loads(payload)
    except (ValueError, UnicodeError) as error:
        raise AcceptanceError("Malformed test access token") from error
    if not isinstance(result, dict) or result.get("role") != "authenticated" or result.get("is_anonymous") is True:
        raise AcceptanceError("A real authenticated test account is required")
    # Preflight only: unverified JWT claims cannot grant permissions. The hosted
    # API still validates the signature, session and server-owned membership.
    now = int(time.time())
    if result.get("iss") != STAGING_SUPABASE_ISSUER or result.get("aud") != "authenticated":
        raise AcceptanceError("Test token must belong to the dedicated ForgeWorks staging issuer")
    issued_at, expires_at = result.get("iat"), result.get("exp")
    if (type(issued_at) is not int or type(expires_at) is not int
            or issued_at > now + TOKEN_CLOCK_SKEW_SECONDS
            or expires_at <= now + TOKEN_CLOCK_SKEW_SECONDS
            or expires_at <= issued_at):
        raise AcceptanceError("Expired or invalid staging test session")
    not_before = result.get("nbf")
    if not_before is not None and (
            type(not_before) is not int or not_before > now + TOKEN_CLOCK_SKEW_SECONDS):
        raise AcceptanceError("Staging test token not yet valid")
    _uuid(result.get("sub"))
    _uuid(result.get("session_id"))
    return result  # Unverified metadata: NEVER used as authorization proof.


def build_plan(env: dict[str, str]) -> tuple[str, str, list[tuple[str, str, str, str, str]]]:
    """Validate every fixture before making ANY external request."""
    if env.get("FORGEWORKS_G3_AUTH_ACCEPTANCE") != "yes":
        raise AcceptanceError("Explicit owner acceptance opt-in is required")
    token_a = env.get("FORGEWORKS_G3_TENANT_A_TOKEN", "")
    token_b = env.get("FORGEWORKS_G3_TENANT_B_TOKEN", "")
    if not token_a or not token_b or token_a == token_b:
        raise AcceptanceError("Two distinct authenticated test identities are required")
    a, b = _token_claims(token_a), _token_claims(token_b)
    if a["sub"] == b["sub"]:
        raise AcceptanceError("Test accounts must have distinct user identities")
    if not isinstance(a.get("app_metadata"), dict) or not isinstance(b.get("app_metadata"), dict):
        raise AcceptanceError("Provisioned server-owned application metadata is required")
    plans: list[tuple[str, str, str, str, str]] = []
    for label, host, product, protected in PRODUCTS:
        alias = PRODUCT_ALIASES[product]
        resource_a = _uuid(env.get(f"FORGEWORKS_G3_{alias}_TENANT_A_RESOURCE_ID"))
        resource_b = _uuid(env.get(f"FORGEWORKS_G3_{alias}_TENANT_B_RESOURCE_ID"))
        if resource_a == resource_b:
            raise AcceptanceError("Distinct tenant-owned records are required")
        try:
            identity_a = a["app_metadata"]["forgeworks"][product]
            identity_b = b["app_metadata"]["forgeworks"][product]
            tenant_a = _uuid(identity_a["tenant_id"])
            tenant_b = _uuid(identity_b["tenant_id"])
        except (KeyError, TypeError, ValueError) as error:
            raise AcceptanceError("Product-specific tenant provisioning is required") from error
        if tenant_a == tenant_b:
            raise AcceptanceError("Test accounts must belong to distinct product tenants")
        if FAKE_RESOURCE not in protected:
            raise AcceptanceError("Product resource probe is not correctly scoped")
        plans.append((label, host, protected.replace(FAKE_RESOURCE, resource_a),
                      protected.replace(FAKE_RESOURCE, resource_b), product))
    return token_a, token_b, plans


def read_status(host: str, path: str, token: str) -> int:
    """One TLS-validated, pinned, read-only GET; never follow redirects."""
    if host not in {entry[1] for entry in PRODUCTS} or not path.startswith("/v1/") or path.startswith("//"):
        raise AcceptanceError("Invalid target")
    req = Request("https://" + host + path, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
        "User-Agent": "ForgeWorks-Owner-Authorized-G3-Probe/1.0",
    }, method="GET")
    try:
        with _NO_REDIRECT_OPENER.open(req, timeout=TIMEOUT_SECONDS) as response:
            return response.status
    except HTTPError as error:
        try:
            return error.code
        finally:
            error.close()


def verify_pair(label: str, host: str, path_a: str, path_b: str,
                token_a: str, token_b: str, transport=read_status) -> None:
    """Both users MUST read their own resource, and neither the other user's."""
    own_a = transport(host, path_a, token_a)
    own_b = transport(host, path_b, token_b)
    if own_a != 200 or own_b != 200:
        raise AcceptanceError(f"{label}: both authorized business reads must be HTTP 200")
    cross_a = transport(host, path_b, token_a)
    cross_b = transport(host, path_a, token_b)
    if cross_a not in (403, 404) or cross_b not in (403, 404):
        raise AcceptanceError(f"{label}: cross-tenant business reads must be denied HTTP 403/404")
    # Never print identities, JWTs, resource paths or business response bodies.
    print(f"PASS {label}: two real authorized reads + two denied cross-tenant reads")


def require_exact_staging_release(
    path: Path | None = None, *, verifier=verify_fleet,
) -> None:
    """Reject stale/mismatched hosted release before contacting business endpoints.

    This is independent public-only release evidence, never an auth bypass.
    A fresh hosted identity proof is required each time the G3 probe runs.
    """
    candidate = path or (
        Path(__file__).resolve().parents[1] / "ops/releases/fleet-staging-candidate.json"
    )
    if candidate.is_symlink() or not candidate.is_file():
        raise AcceptanceError("Pinned staging release candidate is unavailable")
    with candidate.open("rb") as handle:
        raw = handle.read(MAX_PLAN_BYTES + 1)
    if len(raw) > MAX_PLAN_BYTES:
        raise AcceptanceError("Pinned staging release candidate exceeds limit")
    try:
        plan = json.loads(raw, object_pairs_hook=unique_object)
        validate_plan(plan)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise AcceptanceError("Invalid pinned staging release candidate") from exc
    result = verifier(plan)
    if (not isinstance(result, dict) or result.get("result") != "PASS"
            or result.get("environment") != "staging"
            or result.get("production_acceptance") != "NOT_ACCEPTED"):
        raise AcceptanceError("Hosted staging release identity or boundaries are not verified")


def run() -> None:
    token_a, token_b, plans = build_plan(dict(os.environ))
    # An HTTP 200 from a healthy *old* deployment is not G3 evidence.
    require_exact_staging_release()
    for label, host, path_a, path_b, _ in plans:
        verify_pair(label, host, path_a, path_b, token_a, token_b)
    print("PASS five-product owner-authorized read-only tenant isolation acceptance")
    print("LIMITATION: This does not prove write isolation, lifecycle, finance acceptance or production security signoff")


if __name__ == "__main__":
    try:
        run()
    except (AcceptanceError, URLError, TimeoutError) as error:
        # Never interpolate exception text containing an untrusted URL or token.
        print("FAIL authenticated cross-tenant acceptance: " + type(error).__name__, file=sys.stderr)
        sys.exit(1)
