"""Portal shell guardrail tests, deliberately offline with no live credentials."""
from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
PORTAL = ROOT / "apps" / "portal"
EXPECTED = {"apishield-agent","accessfix-ai","specforge-ai","agenttest-lab","datareconcile-ai"}


class PortalShellTests(unittest.TestCase):
    def test_catalog_has_exact_five_products_and_reserved_same_origin_paths(self):
        items = json.loads((PORTAL / "products.json").read_text())
        self.assertEqual(len(items), 5)
        self.assertEqual({x["id"] for x in items}, EXPECTED)
        for x in items:
            self.assertEqual(set(x), {"id", "title", "description", "domain", "platform_route"})
            self.assertEqual(x["platform_route"], "/app/" + x["id"])
            self.assertNotIn("http", x["platform_route"])
            self.assertTrue(all(x[field].strip() for field in ("title","description","domain")))

    def test_browser_does_not_load_external_scripts_or_inline_credentials(self):
        html = (PORTAL / "index.html").read_text()
        js = (PORTAL / "app.js").read_text()
        self.assertIn("default-src 'none'",html)
        self.assertIn("connect-src 'self'",html)
        self.assertIn("script-src 'self'",html)
        self.assertEqual(re.findall(r'<script[^>]+src="([^"]+)"',html), ["./app.js"])
        self.assertNotIn("<script>", html)
        self.assertNotIn("localStorage", js)
        self.assertNotIn("sessionStorage", js)
        self.assertNotIn("innerHTML", js)
        self.assertNotIn("Bearer ", js)
        self.assertIn("textContent",js)
        self.assertIn("credentials:'same-origin'",js)
        self.assertIn("'/api/platform/status'",js)

    def test_catalog_is_not_marked_as_a_live_product(self):
        text = (PORTAL / "index.html").read_text()
        js = (PORTAL / "app.js").read_text()
        self.assertIn("Belum diintegrasikan", text)
        self.assertIn("Akses portal belum diaktifkan", js)
        self.assertIn("production acceptance tetap diperlukan", js)
        self.assertNotIn("window.location =",js)


if __name__ == "__main__":
    unittest.main()
