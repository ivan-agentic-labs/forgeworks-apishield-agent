"""External HTTPS contract across the five independent ForgeWorks staging APIs.

No credentials, customer records or state-changing requests are used.
The urllib opener validates TLS certificates by default; all hosts are pinned
to these public staging hostnames. Run this only from a connected CI runner.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

class _RejectRedirect(HTTPRedirectHandler):
    """Keep staging checks on their pinned origin; a 3xx must fail."""
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = build_opener(_RejectRedirect)

TIMEOUT_SECONDS = 15
MAX_RESPONSE_BYTES = 4096
FAKE_RESOURCE = "00000000-0000-0000-0000-000000000001"
PRODUCTS = (
    ("APIShield Agent", "apishield-agent-staging.up.railway.app", "apishield-agent", f"/v1/analyses/{FAKE_RESOURCE}"),
    ("AccessFix AI", "accessfix-ai-staging.up.railway.app", "accessfix-ai", f"/v1/scans/{FAKE_RESOURCE}/findings"),
    ("SpecForge AI", "specforge-ai-staging.up.railway.app", "specforge-ai", f"/v1/spec-revisions/{FAKE_RESOURCE}/openapi"),
    ("AgentTest Lab", "agenttest-lab-staging.up.railway.app", "agenttest-lab", f"/v1/evaluation-runs/{FAKE_RESOURCE}/cases"),
    ("DataReconcile AI", "datareconcile-ai-staging.up.railway.app", "datareconcile-ai", f"/v1/reports/{FAKE_RESOURCE}/signature"),
)



def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def forged_access_token(supabase_url: str, product: str, algorithm: str) -> str:
    """Make a synthetic *untrusted* token to prove staging rejects invented roles.

    No genuine identity credentials, provider keys or customer account IDs exist
    in this probe. Both algorithms MUST be rejected by the remote API.
    """
    if algorithm not in {"none", "HS256"}:
        raise ValueError("Only intentionally invalid token profiles may be emitted")
    now = int(time.time())
    claims = {
        "iss": supabase_url + "/auth/v1",
        "aud": "authenticated",
        "sub": "00000000-0000-4000-8000-000000000001",
        "session_id": "00000000-0000-4000-8000-000000000002",
        "exp": now + 120,
        "iat": now,
        "role": "authenticated",
        "is_anonymous": False,
        "app_metadata": {
            "forgeworks": {
                product: {
                    "tenant_id": "00000000-0000-4000-8000-000000000003",
                    "scopes": ["*:read"],
                },
            },
        },
    }
    header = {"alg": algorithm, "typ": "JWT"}
    encoded_header = _b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    encoded_claims = _b64url(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signing_input = f"{encoded_header}.{encoded_claims}"
    if algorithm == "none":
        return signing_input + "."
    # Synthetic marker only. Not a Supabase or application signing key.
    signature = hmac.new(
        b"forgeworks-public-negative-probe-never-trusted",
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return signing_input + "." + _b64url(signature)


def fetch(host: str, path: str, authorization: str | None = None) -> tuple[int, bytes]:
    if not host.endswith(".up.railway.app") or host not in {record[1] for record in PRODUCTS}:
        raise AssertionError("Unrecognized target host")
    if not path.startswith("/") or path.startswith("//"):
        raise AssertionError("Request path must be relative to the pinned staging origin")
    headers = {"Accept": "application/json", "User-Agent": "ForgeWorks-Cross-Product-Staging-Proof/1.0"}
    if authorization is not None:
        headers["Authorization"] = authorization
    request = Request(f"https://{host}{path}", headers=headers, method="GET")
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        status = error.code
        body = error.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise AssertionError("Unexpectedly large public response")
    return status, body


def payload(host: str, path: str, expected_status: int) -> dict:
    status, body = fetch(host, path)
    if status != expected_status:
        raise AssertionError(f"{host}{path}: expected HTTP {expected_status}, got {status}")
    try:
        result = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise AssertionError(f"{host}{path}: response is not JSON") from exc
    if not isinstance(result, dict):
        raise AssertionError("Unexpected public JSON response type")
    return result


def run() -> None:
    identities: set[tuple[str, str]] = set()
    for label, host, product, protected in PRODUCTS:
        live = payload(host, "/healthz", 200)
        ready = payload(host, "/readyz", 200)
        auth = payload(host, "/v1/auth/config", 200)
        if live.get("status") != "ok" or ready.get("status") != "ready":
            raise AssertionError(f"{label}: application or identity/database readiness failed")
        if auth.get("enabled") is not True or auth.get("product") != product or auth.get("environment") != "staging":
            raise AssertionError(f"{label}: unexpected public Auth contract")
        url, key = auth.get("supabase_url"), auth.get("publishable_key")
        if not isinstance(url, str) or not url.startswith("https://") or not url.endswith(".supabase.co"):
            raise AssertionError(f"{label}: invalid Supabase identity provider")
        if not isinstance(key, str) or not key.startswith("sb_publishable_"):
            raise AssertionError(f"{label}: not a public Supabase publishable key")
        identities.add((url, key))
        probes = (
            None,
            "Bearer not-a-jwt",
            "Bearer eyJhbGciOiJub25lIn0.e30.",
            "Bearer " + forged_access_token(url, product, "none"),
            "Bearer " + forged_access_token(url, product, "HS256"),
        )
        for value in probes:
            status, _ = fetch(host, protected, value)
            if status != 401:
                raise AssertionError(f"{label}: protected product-specific resource returned HTTP {status}, expected 401")
        # No raw JWT, tenant ID or publishable key is logged.
        print(f"PASS {label}: verified HTTPS identity/readiness and denied protected business read x{len(probes)}")

    if len(identities) != 1:
        raise AssertionError("Staging products expose inconsistent Supabase identity configurations")
    print("PASS all five staging products use the same configured Supabase identity endpoint and publishable key")
    print("LIMITATION: anonymous negative probes do not validate real customer login, RLS tenancy or business E2E")


if __name__ == "__main__":
    try:
        run()
    except (AssertionError, URLError, TimeoutError) as exc:
        print(f"FAIL live cross-product staging proof: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
