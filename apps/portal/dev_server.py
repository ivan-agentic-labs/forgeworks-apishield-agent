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


def handler_factory(root: Path = ASSETS):
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
            host = self.headers.get("Host", "")
            if host != f"127.0.0.1:{self.server.server_port}" and host != f"localhost:{self.server.server_port}":
                self._send(421, b"Invalid preview origin\n", "text/plain; charset=utf-8", head)
                return
            try:
                path = urlsplit(self.path)
            except ValueError:
                self._send(400, b"Invalid target\n", "text/plain; charset=utf-8", head)
                return
            if path.scheme or path.netloc or path.query or path.fragment:
                self._send(400, b"Invalid target\n", "text/plain; charset=utf-8", head)
                return
            if path.path == "/api/platform/status":
                self._send(200, STATUS, "application/json; charset=utf-8", head)
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
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be 1024..65535")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_factory())
    print(f"Local preview: http://127.0.0.1:{args.port} (no customer or real credentials)", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
