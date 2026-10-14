"""Loopback preview server tests; no external network, accounts or secrets."""
from __future__ import annotations

from http.server import ThreadingHTTPServer
import importlib.util
import json
import http.client
from pathlib import Path
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("portal_preview", ROOT / "apps/portal/dev_server.py")
preview = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preview)


class PortalPreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), preview.handler_factory())
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def request(self, path, method="GET", headers=None):
        req = Request(self.origin + path, method=method, headers=headers or {})
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, response.headers, response.read()
        except HTTPError as error:
            with error:
                return error.code, error.headers, error.read()

    def test_static_assets_security_headers_and_no_store(self):
        for path in ["/", "/app.js", "/styles.css", "/products.json"]:
            with self.subTest(path=path):
                code, headers, body = self.request(path)
                self.assertEqual(code, 200)
                self.assertGreater(len(body), 30)
                self.assertEqual(headers["Cache-Control"], "no-store")
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(headers["X-Frame-Options"], "DENY")
                self.assertIn("connect-src 'self'", headers["Content-Security-Policy"])

    def test_local_status_is_not_staging_or_production_acceptance(self):
        code, _, body = self.request("/api/platform/status")
        self.assertEqual(code, 200)
        obj = json.loads(body)
        self.assertEqual(obj, {"schema": "forgeworks-portal-status-v1",
                               "environment": "development", "status": "reachable"})
        self.assertNotIn("production",body.decode())

    def test_business_proxy_is_not_implemented_or_open(self):
        for path in ["/api/apishield-agent/v1/jobs", "/app/apishield-agent", "/.env",
                     "/%2e%2e/%2e%2e/.env", "//example.invalid/x"]:
            with self.subTest(path=path):
                code, _, _ = self.request(path)
                self.assertIn(code, (400, 404))

    def test_write_methods_denied(self):
        for method in ["POST", "PUT", "PATCH", "DELETE"]:
            code, _, body = self.request("/api/platform/status", method=method)
            self.assertEqual(code, 405)
            self.assertNotIn(b"token",body)

    def test_query_strings_and_invalid_host_are_denied(self):
        self.assertEqual(self.request("/products.json?token=not-a-real-token")[0],400)
        self.assertEqual(self.request("/",headers={"Host":"attacker.invalid"})[0],421)


    def test_duplicate_host_headers_are_rejected(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            conn.putrequest("GET", "/", skip_host=True)
            conn.putheader("Host", f"127.0.0.1:{self.server.server_port}")
            conn.putheader("Host", "attacker.invalid")
            conn.endheaders()
            response = conn.getresponse()
            self.assertEqual(response.status, 421)
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
            response.read()
        finally:
            conn.close()

    def test_preview_never_accepts_credentials_or_request_bodies(self):
        for forbidden in ("Authorization", "Cookie", "Transfer-Encoding", "Content-Length"):
            with self.subTest(header=forbidden):
                value = "chunked" if forbidden == "Transfer-Encoding" else "1"
                if forbidden == "Authorization":
                    value = "Bearer fake-preview-credential"
                code, _, body = self.request("/", headers={forbidden: value})
                self.assertEqual(code, 400)
                self.assertNotIn(b"fake-preview-credential", body)

    def test_ambiguous_routes_fail_before_static_asset_lookup(self):
        for target in (
            "/%2e%2e/index.html", "/app.js%2fprivate", "/styles.css;ignored",
            "/app.js\\\\private", "/" + "a" * 260,
            "/api/platform/status%0d%0aHost:evil.invalid",
        ):
            with self.subTest(target=target):
                self.assertEqual(self.request(target)[0], 400)

    def test_head_has_headers_but_no_body(self):
        code, headers, body = self.request("/app.js",method="HEAD")
        self.assertEqual(code,200)
        self.assertEqual(body,b"")
        self.assertGreater(int(headers["Content-Length"]),30)


if __name__ == "__main__":
    unittest.main()
