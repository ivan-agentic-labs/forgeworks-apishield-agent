"""Offline acceptance harness tests. No real accounts or network activity."""
from __future__ import annotations

import base64
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import probe_authenticated_tenant_isolation as probe  # noqa: E402


def fake_jwt(user, tenant):
    claims = {
        "sub": user, "session_id": "00000000-0000-4000-8000-000000000099",
        "role": "authenticated", "is_anonymous": False,
        "app_metadata": {"forgeworks": {
            entry[2]: {"tenant_id": tenant, "scopes": ["*:read"]}
            for entry in probe.PRODUCTS
        }},
    }
    b64 = lambda v: base64.urlsafe_b64encode(json.dumps(v).encode()).rstrip(b"=").decode()
    return b64({"alg": "HS256", "typ": "JWT"}) + "." + b64(claims) + ".synthetic"


def fixture_env():
    a = "00000000-0000-4000-8000-000000000001"
    b = "00000000-0000-4000-8000-000000000002"
    env = {
        "FORGEWORKS_G3_AUTH_ACCEPTANCE": "yes",
        "FORGEWORKS_G3_TENANT_A_TOKEN": fake_jwt(a, "00000000-0000-4000-8000-000000000003"),
        "FORGEWORKS_G3_TENANT_B_TOKEN": fake_jwt(b, "00000000-0000-4000-8000-000000000004"),
    }
    for name in probe.PRODUCT_ALIASES.values():
        env[f"FORGEWORKS_G3_{name}_TENANT_A_RESOURCE_ID"] = "00000000-0000-4000-8000-000000000011"
        env[f"FORGEWORKS_G3_{name}_TENANT_B_RESOURCE_ID"] = "00000000-0000-4000-8000-000000000022"
    return env


class AuthenticatedG3ProbeTests(unittest.TestCase):
    def test_fixture_plan_demands_all_five_pairs_and_opt_in(self):
        env = fixture_env()
        token_a, token_b, plans = probe.build_plan(env)
        self.assertEqual(len(plans), 5)
        self.assertNotEqual(token_a, token_b)
        for _, host, a, b, _ in plans:
            self.assertTrue(host.endswith(".up.railway.app"))
            self.assertNotEqual(a, b)
        del env["FORGEWORKS_G3_AUTH_ACCEPTANCE"]
        with self.assertRaises(probe.AcceptanceError):
            probe.build_plan(env)

    def test_missing_resource_identity_fails_before_network(self):
        env = fixture_env()
        del env["FORGEWORKS_G3_DATARECONCILE_TENANT_B_RESOURCE_ID"]
        with self.assertRaises(probe.AcceptanceError):
            probe.build_plan(env)

    def test_same_user_or_same_tenant_is_not_isolation_evidence(self):
        env = fixture_env()
        user = "00000000-0000-4000-8000-000000000001"
        env["FORGEWORKS_G3_TENANT_B_TOKEN"] = fake_jwt(
            user, "00000000-0000-4000-8000-000000000004",
        )
        with self.assertRaises(probe.AcceptanceError):
            probe.build_plan(env)
        env["FORGEWORKS_G3_TENANT_B_TOKEN"] = fake_jwt(
            "00000000-0000-4000-8000-000000000002",
            "00000000-0000-4000-8000-000000000003",
        )
        with self.assertRaises(probe.AcceptanceError):
            probe.build_plan(env)

    def test_unauthorized_own_read_never_claims_isolation(self):
        env = fixture_env()
        token_a, token_b, plans = probe.build_plan(env)
        label, host, path_a, path_b, _ = plans[0]
        requests = []

        def transport(actual_host, path, token):
            requests.append((actual_host, path, token))
            return 401 if token == token_a else 200

        output = StringIO()
        with redirect_stdout(output), self.assertRaises(probe.AcceptanceError):
            probe.verify_pair(label, host, path_a, path_b, token_a, token_b, transport)
        self.assertEqual(len(requests), 2)
        self.assertEqual(output.getvalue(), "")

    def test_cross_tenant_200_or_401_never_passes(self):
        token_a, token_b, plans = probe.build_plan(fixture_env())
        label, host, path_a, path_b, _ = plans[0]
        for invalid in (200, 401):
            with self.subTest(status=invalid):
                def transport(_host, path, token):
                    if (path == path_a and token == token_a) or (path == path_b and token == token_b):
                        return 200
                    return invalid
                with self.assertRaises(probe.AcceptanceError):
                    probe.verify_pair(label, host, path_a, path_b, token_a, token_b, transport)

    def test_both_valid_tenant_reads_and_both_denials_are_required(self):
        token_a, token_b, plans = probe.build_plan(fixture_env())
        label, host, path_a, path_b, _ = plans[0]
        seen = []

        def transport(_host, path, token):
            seen.append((path, token))
            if (path == path_a and token == token_a) or (path == path_b and token == token_b):
                return 200
            return 403 if token == token_a else 404

        output = StringIO()
        with redirect_stdout(output):
            probe.verify_pair(label, host, path_a, path_b, token_a, token_b, transport)
        self.assertEqual(len(seen), 4)
        self.assertIn("PASS", output.getvalue())
        self.assertNotIn(token_a, output.getvalue())
        self.assertNotIn(token_b, output.getvalue())
        self.assertNotIn(path_a, output.getvalue())
        self.assertNotIn(path_b, output.getvalue())

    def test_unpinned_host_and_absolute_paths_fail_before_transport(self):
        with self.assertRaises(probe.AcceptanceError):
            probe.read_status("example.invalid", "/v1/analyses/record", "synthetic")
        with self.assertRaises(probe.AcceptanceError):
            probe.read_status(probe.PRODUCTS[0][1], "//evil.invalid", "synthetic")


if __name__ == "__main__":
    unittest.main()
