import shutil
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import jwt
import pytest
import uvicorn
from playwright.sync_api import sync_playwright

from apishield_agent.infrastructure.store import REPOSITORY, TENANT, USER
from apishield_agent.main import create_app

def local_get(url, **kwargs):
    return httpx.get(url, trust_env=False, **kwargs)


def local_post(url, **kwargs):
    return httpx.post(url, trust_env=False, **kwargs)


SECRET = "forgeworks-development-secret-32-plus"
ISSUER = "https://issuer.synthetic.invalid"
AUDIENCE = "forgeworks-api"
BASE = "a" * 40
HEAD = "b" * 40
ROOT = Path(__file__).resolve().parents[2]


def token(scope="repo:analyze analysis:read job:read"):
    return jwt.encode(
        {
            "sub": USER,
            "tenant_id": TENANT,
            "scope": scope,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
        SECRET,
        algorithm="HS256",
    )


class QuietStaticHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass


def _wait_for(url):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            response = local_get(url, timeout=0.5)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.02)
    raise AssertionError(f"server did not become ready: {url}")


def test_live_api_and_static_ui_smoke_flow(tmp_path, monkeypatch):
    """Exercise the real API process and browser UI, not a mocked fetch layer."""
    static = ThreadingHTTPServer(("127.0.0.1", 0), lambda *args, **kwargs: QuietStaticHandler(*args, directory=str(ROOT / "apps/web"), **kwargs))
    static_thread = threading.Thread(target=static.serve_forever, daemon=True)
    static_thread.start()
    static_url = f"http://127.0.0.1:{static.server_port}"

    monkeypatch.setenv("APISHIELD_CORS_ORIGINS", static_url)
    app = create_app(str(tmp_path / "api.sqlite"), seed=True)
    api_config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error", lifespan="on")
    # Uvicorn cannot expose a port chosen with port=0 to the caller, so reserve
    # a local ephemeral port and release it immediately before starting.
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        api_port = sock.getsockname()[1]
    api_config.port = api_port
    api_server = uvicorn.Server(api_config)
    api_thread = threading.Thread(target=api_server.run, daemon=True)
    api_thread.start()
    api_url = f"http://127.0.0.1:{api_port}"
    try:
        _wait_for(f"{api_url}/healthz")
        assert local_get(f"{api_url}/healthz").json() == {"status": "ok", "service": "apishield-agent"}
        asset = local_get(f"{static_url}/app.js")
        assert asset.status_code == 200
        assert "fetch(apiUrl(baseUrl" in asset.text

        headers = {"Authorization": f"Bearer {token()}", "Idempotency-Key": "e2e-analysis-key-0001"}
        submitted = local_post(
            f"{api_url}/v1/installations/1/repositories/{REPOSITORY}/analyses",
            headers=headers,
            json={"base_sha": BASE, "head_sha": HEAD, "capability_profile": "openapi31-typescript-v1"},
        )
        assert submitted.status_code == 202, submitted.text
        analysis = submitted.json()
        assert analysis["id"] and analysis["job_id"]

        job = None
        for _ in range(100):
            job_response = local_get(
                f"{api_url}/v1/jobs/{analysis['job_id']}",
                headers={"Authorization": f"Bearer {token('analysis:read job:read')}"},
            )
            assert job_response.status_code == 200, job_response.text
            job = job_response.json()
            if job["state"] == "SUCCEEDED":
                break
            time.sleep(0.02)
        assert job["state"] == "SUCCEEDED"

        browser_path = shutil.which("chromium") or shutil.which("google-chrome")
        requests = []
        with sync_playwright() as playwright:
            browser_path = browser_path or playwright.chromium.executable_path
            assert Path(browser_path).is_file(), "Chromium is required for the browser smoke flow"
            browser = playwright.chromium.launch(headless=True, executable_path=browser_path, args=["--no-sandbox"])
            page = browser.new_page()
            page.on("request", lambda request: requests.append(request.url) if "/v1/" in request.url else None)
            page.goto(f"{static_url}/?apiBaseUrl={api_url}", wait_until="networkidle")
            assert page.title() == "APIShield analysis viewer"
            page.locator("#api-base-url").fill(api_url)
            page.locator("#bearer-token").fill(token("analysis:read job:read"))
            page.locator("#analysis-id").fill(analysis["id"])
            page.locator("#job-id").fill(analysis["job_id"])
            page.locator("#load-button").click()
            page.locator("#status").wait_for(state="visible")
            page.wait_for_function("document.querySelector('#status').textContent === 'Loaded successfully.'")
            assert page.locator("#analysis-status").inner_text() == "SUCCEEDED"
            assert page.locator("#finding-count").inner_text() == "1 returned"
            assert page.locator(".finding strong").inner_text() == "REQUIRED_RESPONSE_FIELD_ADDED"
            browser.close()

        assert any(f"/v1/analyses/{analysis['id']}" in url for url in requests)
        assert any(f"/v1/jobs/{analysis['job_id']}" in url for url in requests)
        assert any(f"/v1/analyses/{analysis['id']}/findings" in url for url in requests)
    finally:
        api_server.should_exit = True
        api_thread.join(timeout=5)
        static.shutdown()
        static.server_close()
        static_thread.join(timeout=5)

