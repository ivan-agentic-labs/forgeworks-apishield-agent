"""Offline fleet inventory tests; no credentials or network calls."""
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("observe_fleet", ROOT / "scripts/observe_fleet_runtime.py")
import sys
sys.path.insert(0, str(ROOT / "scripts"))
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def candidate():
    return {"schema": "forgeworks-fleet-staging-candidate-v1", "environment": "staging",
            "products": [
                {"product": p, "revision_sha": "a" * 40, "runtime_manifest":
                    {"profile": "forgeworks-runtime-manifest-v1", "file_count": 2, "sha256": "b" * 64}}
                for p in mod.PRODUCTS]}


def transport(plan):
    records = mod.validate_plan(plan)
    def get(product, path):
        if path in ("/healthz", "/readyz"):
            return 200, {"status": "ok" if path == "/healthz" else "ready"}
        if path == "/versionz":
            return 200, {**records[product], "environment": "staging"}
        if path == "/metricsz":
            return 401, None
        raise AssertionError("Unexpected request")
    return get


class FleetObservationTests(unittest.TestCase):
    def test_all_exact_revisions_match(self):
        plan = candidate()
        result = mod.observe(plan, transport(plan))
        self.assertEqual(result["candidate_relation"], "MATCH")
        self.assertEqual([x["result"] for x in result["products"]], ["PASS"] * 5)
        self.assertEqual(result["production_acceptance"], "NOT_ACCEPTED")

    def test_one_changed_source_reports_drift_not_false_acceptance(self):
        plan = candidate()
        proper = transport(plan)
        def drift(product, path):
            status, value = proper(product, path)
            if product == "apishield-agent" and path == "/versionz":
                value = {**value, "revision_sha": "c" * 40}
            return status, value
        result = mod.observe(plan, drift)
        self.assertEqual(result["candidate_relation"], "NOT_MATCHED")
        self.assertEqual(result["products"][0]["result"], "DRIFT")
        self.assertEqual(result["products"][0]["revision_sha"], "c" * 40)

    def test_no_network_with_invalid_plan(self):
        plan = candidate()
        plan["products"][0]["runtime_manifest"]["file_count"] = True
        with self.assertRaises(ValueError):
            mod.observe(plan, lambda *_: self.fail("Unexpected network"))

    def test_partial_telemetry_failure_does_not_invent_success(self):
        plan = candidate()
        proper = transport(plan)
        def failed(product, path):
            if product == "specforge-ai" and path == "/metricsz":
                return 503, None
            return proper(product, path)
        result = mod.observe(plan, failed)
        self.assertEqual(result["products"][2]["result"], "ERROR")
        self.assertEqual(result["candidate_relation"], "NOT_MATCHED")

    def test_untrusted_exception_message_is_suppressed(self):
        plan = candidate()
        def failure(*_):
            raise ValueError("secret-in-upstream-exception")
        result = mod.observe(plan, failure)
        self.assertEqual([x["result"] for x in result["products"]], ["ERROR"] * 5)
        self.assertNotIn("secret-in-upstream-exception", str(result))

    def test_invalid_hosted_manifest_does_not_pass(self):
        plan = candidate()
        proper = transport(plan)
        for altered in (True, 2.5, 0, 300):
            def bad(product, path):
                status, value = proper(product, path)
                if product == "agenttest-lab" and path == "/versionz":
                    value = copy.deepcopy(value)
                    value["runtime_manifest"]["file_count"] = altered
                return status, value
            self.assertEqual(mod.observe(plan, bad)["products"][3]["result"], "ERROR")

    def test_wrong_environment_or_product_does_not_pass(self):
        plan = candidate()
        proper = transport(plan)
        for field, altered in (("environment", "production"), ("product", "sealangel-work")):
            def bad(product, path):
                status, value = proper(product, path)
                if product == "datareconcile-ai" and path == "/versionz":
                    value = {**value, field: altered}
                return status, value
            self.assertEqual(mod.observe(plan, bad)["products"][4]["result"], "ERROR")


if __name__ == "__main__":
    unittest.main()
