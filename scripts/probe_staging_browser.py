"""Credential-free browser checks of the five fixed, deployed staging origins.

No login, upload, customer data, access grant or business mutation is performed.
"""
import argparse
import json

from playwright.sync_api import sync_playwright

PRODUCTS = ("apishield-agent", "accessfix-ai", "specforge-ai", "agenttest-lab", "datareconcile-ai")


def probe(product):
    origin = f"https://{product}-staging.up.railway.app"
    errors = []
    unexpected = []
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(headless=True)
        try:
            page = browser.new_page()
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
            return {"product": product, "ui_http_status": response.status, "title": page.title(), "auth_config": "staging-enabled", "api_origin_fenced": True, "anonymous_statuses": statuses, "javascript_errors": len(errors), "scope": "credential-free deployed UI; authenticated business acceptance remains open"}
        finally:
            browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("product", choices=PRODUCTS)
    print(json.dumps(probe(parser.parse_args().product), sort_keys=True))
