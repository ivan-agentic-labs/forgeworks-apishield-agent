"""Read-only portal monitoring routes using only a local HTTP listener."""
from __future__ import annotations
from http.server import ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
from threading import Thread
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("dev_portal_test",
                                              ROOT / "apps/portal/dev_server.py")
portal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(portal)


def snapshot():
    return {"schema":"forgeworks-portal-staging-services-v1",
            "environment":"staging", "result":"PASS",
            "services":[{"product":p,"status":"ready"} for p in
                        ["apishield-agent","accessfix-ai","specforge-ai","agenttest-lab","datareconcile-ai"]],
            "business_access":"NOT_ENABLED","production_acceptance":"NOT_ACCEPTED"}


def serve(provider):
    server=ThreadingHTTPServer(("127.0.0.1",0),portal.handler_factory(snapshot_provider=provider))
    t=Thread(target=server.serve_forever,daemon=True)
    t.start()
    return server,t


def request(srv,path,method="GET",headers=None):
    url=f"http://127.0.0.1:{srv.server_port}"+path
    req=Request(url,method=method,headers=headers or {})
    try:
        with urlopen(req,timeout=2) as resp:
            return resp.status,dict(resp.headers),resp.read()
    except HTTPError as error:
        with error:
            return error.code,dict(error.headers),error.read()


class MonitoringRouteTests(unittest.TestCase):
    def test_explicit_probed_route_has_only_sanitized_staging_metadata(self):
        server,thread=serve(snapshot)
        try:
            code,headers,raw=request(server,"/api/platform/services")
            self.assertEqual(code,200)
            data=json.loads(raw)
            self.assertEqual(data["result"],"PASS")
            self.assertEqual(len(data["services"]),5)
            self.assertEqual(data["business_access"],"NOT_ENABLED")
            self.assertEqual(headers["Cache-Control"],"no-store")
            self.assertIn("frame-ancestors 'none'",headers["Content-Security-Policy"])
            self.assertNotIn("http",raw.decode())
            self.assertNotIn("token",raw.decode())
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)

    def test_disabled_monitoring_returns_503_and_performs_no_network(self):
        server,thread=serve(None)
        try:
            self.assertEqual(request(server,"/api/platform/services")[0],503)
            self.assertEqual(request(server,"/api/platform/services?product=ignored")[0],400)
            self.assertEqual(request(server,"/api/accessfix-ai/v1/jobs")[0],404)
            self.assertEqual(request(server,"/api/platform/services",method="POST")[0],405)
            self.assertEqual(request(server,"/api/platform/services",
                                     headers={"Host":"attacker.invalid"})[0],421)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)

    def test_upstream_fault_cannot_expose_internals(self):
        def fail():
            raise RuntimeError("Bearer invented-session-secret")
        server,thread=serve(fail)
        try:
            code,_,raw=request(server,"/api/platform/services")
            self.assertEqual(code,503)
            self.assertEqual(json.loads(raw),{"status":"unavailable"})
            self.assertNotIn(b"invented-session-secret",raw)
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)


if __name__=="__main__":
    unittest.main()
