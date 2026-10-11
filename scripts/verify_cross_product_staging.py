"""External HTTPS contract across the five independent ForgeWorks staging APIs.

No credentials, customer records or state-changing requests are used.
The urllib opener validates TLS certificates by default; all hosts are pinned
to these public staging hostnames. Run this only from a connected CI runner.
"""
from __future__ import annotations

import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

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
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
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
        for value in (None, "Bearer not-a-jwt", "Bearer eyJhbGciOiJub25lIn0.e30."):
            status, _ = fetch(host, protected, value)
            if status != 401:
                raise AssertionError(f"{label}: protected product-specific resource returned HTTP {status}, expected 401")
        # Avoid logging credentials or public keys even though publishable.
        print(f"PASS {label}: verified HTTPS identity/readiness and denied protected business read x3")

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
