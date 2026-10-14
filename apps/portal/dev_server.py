"""Loopback-only ForgeWorks portal preview server.

For developer preview, *never* customer traffic or authentication.
No arbitrary proxy, no business actions, no credentials, no external storage.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from urllib.parse import urlsplit

ASSETS = Path(__file__).resolve().parent
ROUTES = {"/": ("index.html", "text/html; charset=utf-8"),
          "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/styles.css": ("styles.css", "text/css; charset=utf-8"),
          "/products.json": ("products.json", "application/json; charset=utf-8")}
CSP = ("default-src 'none'; connect-src 'self'; script-src 'self'; "
       "style-src 'self'; img-src 'self'; base-uri 'none'; "
       "form-action 'none'; object-src 'none'; frame-ancestors 'none'")
STATUS = json.dumps({
    "schema": "forgeworks-portal-status-v1",
    "environment": "development",
    "status": "reachable",
}).encode("utf-8")


PRODUCT_ORDER = (
    "apishield-agent", "accessfix-ai", "specforge-ai", "agenttest-lab",
    "datareconcile-ai",
)


def public_services_snapshot(candidate):
    """Whitelist exact browser-visible fields, never pass collector objects through."""
    expected = {"schema", "environment", "result", "services",
                "business_access", "production_acceptance"}
    if (type(candidate) is not dict or set(candidate) != expected
            or candidate["schema"] != "forgeworks-portal-staging-services-v1"
            or candidate["environment"] != "staging"
            or candidate["result"] not in ("PASS", "DEGRADED")
            or candidate["business_access"] != "NOT_ENABLED"
            or candidate["production_acceptance"] != "NOT_ACCEPTED"
            or type(candidate["services"]) is not list
            or len(candidate["services"]) != len(PRODUCT_ORDER)):
        raise ValueError("INVALID_PUBLIC_SNAPSHOT")
    services = []
    for name, item in zip(PRODUCT_ORDER, candidate["services"]):
        if (type(item) is not dict or set(item) != {"product", "status"}
                or item["product"] != name
                or item["status"] not in ("ready", "unavailable")):
            raise ValueError("INVALID_PUBLIC_PRODUCT")
        services.append({"product": name, "status": item["status"]})
    ready = all(item["status"] == "ready" for item in services)
    if (candidate["result"] == "PASS") != ready:
        raise ValueError("INCONSISTENT_PUBLIC_SNAPSHOT")
    return {"schema": "forgeworks-portal-staging-services-v1",
            "environment": "staging", "result": candidate["result"],
            "services": services, "business_access": "NOT_ENABLED",
            "production_acceptance": "NOT_ACCEPTED"}


def handler_factory(root: Path = ASSETS, snapshot_provider=None):
    root = root.resolve(strict=True)

    class PreviewHandler(BaseHTTPRequestHandler):
        server_version = "ForgeWorksPreview"
        sys_version = ""

        def log_message(self, _format, *_args):
            # Do not record URL paths, query strings, headers, token values
            # or remote addresses in preview server logs.
            return

        def _send(self, code: int, body: bytes, mime: str, head: bool = False) -> None:
            self.send_response(code)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def _serve(self, head: bool = False):
            hosts = self.headers.get_all("Host", [])
            # Exactly one local Host is required; repeated Host headers can
            # produce conflicting request interpretations in intermediaries.
            if (len(hosts) != 1 or hosts[0] not in
                    {f"127.0.0.1:{self.server.server_port}",
                     f"localhost:{self.server.server_port}"}):
                self._send(421, b"Invalid preview origin\n", "text/plain; charset=utf-8", head)
                return
            # This server is a static preview, not a session endpoint.
            # Reject credentials and ambiguous request-body framing entirely.
            if (self.headers.get("Authorization") is not None
                    or self.headers.get("Cookie") is not None
                    or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Content-Length") is not None):
                self._send(400, b"Preview headers forbidden\n", "text/plain; charset=utf-8", head)
                return
            try:
                path = urlsplit(self.path)
            except ValueError:
                self._send(400, b"Invalid target\n", "text/plain; charset=utf-8", head)
                return
            # Reject encoded separators, backslashes and path parameters before
            # route matching; the preview has no need for URI decoding.
            if (not self.path.isascii() or len(self.path) > 256
                    or any(c in self.path for c in "%\\;\x00\r\n\t")):
                self._send(400, b"Ambiguous target\n", "text/plain; charset=utf-8", head)
                return
            if path.scheme or path.netloc or path.query or path.fragment:
                self._send(400, b"Invalid target\n", "text/plain; charset=utf-8", head)
                return
            if path.path == "/api/platform/status":
                self._send(200, STATUS, "application/json; charset=utf-8", head)
                return
            if path.path == "/api/platform/services":
                if snapshot_provider is None:
                    self._send(503, b'{"status":"not_configured"}', "application/json; charset=utf-8", head)
                    return
                try:
                    snapshot = public_services_snapshot(snapshot_provider())
                    payload = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
                    if len(payload) > 4096:
                        raise ValueError("EXCESSIVE_SNAPSHOT")
                except Exception:
                    self._send(503, b'{"status":"unavailable"}', "application/json; charset=utf-8", head)
                    return
                self._send(200 if snapshot.get("result") == "PASS" else 503,
                           payload, "application/json; charset=utf-8", head)
                return
            if path.path not in ROUTES:
                self._send(404, b"Not found\n", "text/plain; charset=utf-8", head)
                return
            filename, mime = ROUTES[path.path]
            selected = root / filename
            if selected.is_symlink() or not selected.is_file() or selected.resolve().parent != root:
                self._send(404, b"Not found\n", "text/plain; charset=utf-8", head)
                return
            data = selected.read_bytes()
            if len(data) > 128 * 1024:
                self._send(413, b"Asset too large\n", "text/plain; charset=utf-8", head)
                return
            self._send(200, data, mime, head)

        def do_GET(self):
            self._serve()

        def do_HEAD(self):
            self._serve(head=True)

        def do_POST(self):
            self._send(405, b"Read-only preview\n", "text/plain; charset=utf-8")

        do_PUT = do_POST
        do_PATCH = do_POST
        do_DELETE = do_POST

    return PreviewHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="Local, read-only portal preview (loopback only)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--probe-staging", action="store_true",
                        help="Explicitly allow fixed-origin, read-only staging observation")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be 1024..65535")
    provider = None
    if args.probe_staging:
        import sys
        sys.path.insert(0, str(ASSETS))
        from service_status import SnapshotCache
        provider = SnapshotCache(ttl=30).snapshot
    server = ThreadingHTTPServer(("127.0.0.1", args.port),
                                 handler_factory(snapshot_provider=provider))
    print(f"Local preview: http://127.0.0.1:{args.port} (no customer or real credentials)", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
