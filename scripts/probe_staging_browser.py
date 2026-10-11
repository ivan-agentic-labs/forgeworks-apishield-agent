"""Credential-free browser checks of the five fixed, deployed staging origins.

No login, upload, customer data, access grant or business mutation is performed.
"""
import argparse
import json
import re
import urllib.request

from playwright.sync_api import sync_playwright

PRODUCTS = ("apishield-agent", "accessfix-ai", "specforge-ai", "agenttest-lab", "datareconcile-ai")


def probe(product, preview_style_sha=None):
    origin = f"https://{product}-staging.up.railway.app"
    preview_css = None
    if preview_style_sha is not None:
        if not re.fullmatch(r"[0-9a-f]{40}", preview_style_sha):
            raise ValueError("Preview requires an immutable full Git SHA")
        source = f"https://raw.githubusercontent.com/ivan-agentic-labs/forgeworks-{product}/{preview_style_sha}/apps/web/styles.css"
        with urllib.request.urlopen(source, timeout=30) as result:
            preview_css = result.read(262145)
        assert len(preview_css) <= 262144, "Candidate stylesheet exceeds preview budget"
        preview_css = preview_css.decode("utf-8", errors="strict")
    errors = []
    unexpected = []
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            if preview_css is not None:
                # Override only stylesheet bytes inside this isolated browser.
                # The deployed app is unchanged, and the receipt says PREVIEW.
                page.route(origin + "/styles.css", lambda route: route.fulfill(status=200, content_type="text/css", body=preview_css))
            page.on("pageerror", lambda error: errors.append(type(error).__name__))
            page.on("request", lambda request: unexpected.append(request.url) if request.url.startswith("https://attacker.invalid") else None)
            # The origin override must not redirect the console's requests.
            response = page.goto(origin + "/?apiBaseUrl=https%3A%2F%2Fattacker.invalid", wait_until="networkidle", timeout=60000)
            assert response and response.status == 200, "Deployed UI did not load"
            page.wait_for_function("window.forgeAuthConfig && !document.getElementById('forge-signin').disabled", timeout=30000)
            assert page.locator("#forge-auth-status").inner_text() == "Masuk dengan akun yang memiliki membership ForgeWorks."
            assert page.locator("#forge-signout").is_hidden()
            assert page.locator("#forge-password").input_value() == ""
            assert page.evaluate("window.forgeAuthConfig.product") == product
            assert page.evaluate("window.forgeAuthConfig.environment") == "staging"
            assert page.evaluate("window.forgeAuthConfig.enabled") is True
            fields = page.locator("#api-base, #api-base-url, #baseUrl")
            assert fields.count() >= 1, "No API origin field rendered"
            for field in fields.all():
                assert field.input_value() == origin, "Console API origin escaped deployed origin"
                assert field.evaluate("node => node.readOnly") is True
            for field in page.locator("#token, #bearer-token").all():
                assert field.input_value() == ""
                assert field.evaluate("node => node.readOnly") is True
                assert field.is_hidden(), "Staging exposed manual development token input"
            # Browser-origin API probes, with no access token or cookies supplied.
            statuses = {}
            for endpoint, expected in (("healthz", 200), ("readyz", 200), ("v1/jobs/00000000-0000-0000-0000-000000000001", 401)):
                result = page.request.get(origin + "/" + endpoint, timeout=30000)
                assert result.status == expected, f"Unexpected HTTP status for {endpoint}"
                statuses[endpoint] = result.status
            assert not errors, "Uncaught browser JavaScript error"
            assert not unexpected, "Untrusted API origin override was used"
            return {"product": product, "ui_http_status": response.status, "title": page.title(), "auth_config": "staging-enabled", "api_origin_fenced": True, "anonymous_statuses": statuses, "javascript_errors": len(errors), "stylesheet_preview_sha": preview_style_sha, "scope": "CSS PREVIEW on deployed page; deployment not performed" if preview_style_sha else "credential-free deployed UI; authenticated business acceptance remains open"}
        finally:
            browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("product", choices=PRODUCTS)
    parser.add_argument("--preview-style-sha")
    args = parser.parse_args()
    print(json.dumps(probe(args.product, args.preview_style_sha), sort_keys=True))
