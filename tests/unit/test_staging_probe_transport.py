"""Offline regression for origin pinning in the five-product staging probes.

No external requests, customer accounts, secrets or Railway state changes.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import verify_cross_product_staging as contract  # noqa: E402
import probe_bounded_staging_load as performance  # noqa: E402


class _LocalRedirect(BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self) -> None:
        type(self).hits.append(self.path)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/followed")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ready"}')

    def log_message(self, fmt, *args) -> None:
        pass


class StagingProbeTransportTests(unittest.TestCase):
    def test_unrecognized_host_and_protocol_relative_paths_rejected_before_io(self) -> None:
        good_host = contract.PRODUCTS[0][1]
        for bad_host in ("example.invalid", good_host + ".attacker.invalid", "localhost"):
            with self.subTest(host=bad_host), self.assertRaises(AssertionError):
                contract.fetch(bad_host, "/healthz")
        for bad_path in ("//attacker.invalid/readyz", "https://attacker.invalid", "healthz"):
            with self.subTest(path=bad_path), self.assertRaises(AssertionError):
                contract.fetch(good_host, bad_path)

    def test_both_probe_clients_refuse_http_redirects(self) -> None:
        _LocalRedirect.hits = []
        with ThreadingHTTPServer(("127.0.0.1", 0), _LocalRedirect) as server:
            runner = Thread(target=server.serve_forever, daemon=True)
            runner.start()
            origin = f"http://127.0.0.1:{server.server_port}/redirect"
            try:
                for client in (contract, performance):
                    with self.subTest(client=client.__name__):
                        with self.assertRaises(HTTPError) as observed:
                            client._NO_REDIRECT_OPENER.open(origin, timeout=3)
                        self.assertEqual(observed.exception.code, 302)
                # The browser/network helper must NEVER request a redirected target.
                self.assertEqual(_LocalRedirect.hits, ["/redirect", "/redirect"])
            finally:
                server.shutdown()
                runner.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
