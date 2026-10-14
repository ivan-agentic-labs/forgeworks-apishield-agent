"""Offline negative/positive routing tests for the unactivated BFF plan."""
from __future__ import annotations
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("bff_policy", ROOT / "apps/portal/bff_policy.py")
policy = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = policy
spec.loader.exec_module(policy)

RESOURCE = "00000000-0000-4000-8000-000000000001"
CASES = {
    "apishield-agent": ("analyses", None),
    "accessfix-ai": ("scans", "findings"),
    "specforge-ai": ("spec-revisions", "openapi"),
    "agenttest-lab": ("evaluation-runs", "cases"),
    "datareconcile-ai": ("reports", "signature"),
}


class BFFReadAdmissionTests(unittest.TestCase):
    def path(self, product, kind, suffix):
        return f"/api/{product}/v1/{kind}/{RESOURCE}" + (f"/{suffix}" if suffix else "")

    def test_every_product_has_one_exact_get_read_route(self):
        for product, (kind, suffix) in CASES.items():
            with self.subTest(product=product):
                route = policy.plan_read(self.path(product, kind, suffix))
                self.assertEqual(route.product, product)
                self.assertEqual(route.resource_id, RESOURCE)
                self.assertEqual(route.upstream_path, f"/v1/{kind}/{RESOURCE}" + (f"/{suffix}" if suffix else ""))
                self.assertTrue(route.requires_verified_session)
                self.assertFalse(route.forward_enabled)
                self.assertFalse(policy.can_forward(route))

    def test_write_or_unapproved_methods_are_denied(self):
        path = self.path("apishield-agent", "analyses", None)
        for method in ("POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "get"):
            with self.subTest(method=method), self.assertRaises(policy.RouteDenied):
                policy.plan_read(path, method=method)

    def test_url_confusion_and_traversal_denied(self):
        valid = self.path("apishield-agent", "analyses", None)
        bad = (
            "https://evil.example/" + valid.lstrip("/"),
            "//evil.example" + valid,
            valid + "?token=not-a-real-token",
            valid + "#fragment",
            valid + "/", valid.replace("/v1/", "//v1/"),
            valid.replace(RESOURCE, "../" + RESOURCE),
            valid.replace(RESOURCE, "%2e%2e"),
            valid.replace(RESOURCE, "%2f" + RESOURCE),
            valid.replace(RESOURCE, "123E4567-E89B-42D3-A456-426614174000"),
            valid.replace(RESOURCE, "\\etc"),
            valid + ";ignored",
            valid + "\nsecret",
            valid + "\x00",
            "/" + "a" * 250,
            " /api/apishield-agent/v1/analyses/" + RESOURCE,
        )
        for path in bad:
            with self.subTest(path=path), self.assertRaises(policy.RouteDenied):
                policy.plan_read(path)

    def test_scope_cannot_be_changed_by_user_path(self):
        for product, (kind, suffix) in CASES.items():
            path = self.path(product, kind, suffix)
            for corrupted in (path.replace("/v1/", "/v2/"),
                              path.replace(f"/api/{product}/", "/api/sealangel-work/"),
                              path.replace("/api/", "/proxy/"),
                              path + "/admin",
                              path.replace("/v1/", "/v1/admin/")):
                with self.subTest(path=corrupted), self.assertRaises(policy.RouteDenied):
                    policy.plan_read(corrupted)

    def test_claims_or_untrusted_session_cannot_activate_proxy(self):
        route = policy.plan_read(self.path("specforge-ai", "spec-revisions", "openapi"))
        for untrusted in (None, True, {}, {"is_admin": True}, {"tenant_id": RESOURCE}, "trusted"):
            with self.subTest(untrusted=repr(untrusted)):
                self.assertFalse(policy.can_forward(route, trusted_identity=untrusted))


if __name__ == "__main__":
    unittest.main()
