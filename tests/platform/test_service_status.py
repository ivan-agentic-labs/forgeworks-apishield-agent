"""Offline five-service portal status tests. Does not reach Railway."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import sys
from threading import Lock
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "apps/portal"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("status_test", SCRIPTS / "service_status.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def mock_plan():
    return {"schema": "forgeworks-fleet-staging-candidate-v1",
            "environment": "staging", "products": [
                {"product": p, "revision_sha": "a" * 40, "runtime_manifest": {
                    "profile": "forgeworks-runtime-manifest-v1", "file_count": 1, "sha256": "b" * 64}}
                for p in module.PRODUCTS]}


def public_transport(plan, denied=None):
    lookup = module.validate_plan(plan)
    def request(product, path):
        if path == "/healthz":
            return 200, {"status": "ok"}
        if path == "/readyz":
            return 200, {"status": "ready"}
        if path == "/versionz":
            return 200, {**lookup[product], "environment": "staging"}
        if path in ("/metricsz", module.verify_fleet.__globals__["BUSINESS_PATHS"][product]):
            if denied == (product, path):
                return 200, {}
            return 401, None
        raise AssertionError("Unrecognized target")
    return request


class ServiceStatusTests(unittest.TestCase):
    def test_valid_real_contract_transforms_to_safe_status(self):
        plan = mock_plan()
        result = module.verify_fleet(plan, public_transport(plan))
        view = module.snapshot_from_report(result)
        self.assertEqual(view["result"], "PASS")
        self.assertEqual(len(view["services"]), 5)
        self.assertTrue(all(x["status"] == "ready" for x in view["services"]))
        self.assertEqual(view["business_access"], "NOT_ENABLED")
        self.assertEqual(view["production_acceptance"], "NOT_ACCEPTED")
        self.assertNotIn("a" * 40, str(view))
        self.assertNotIn("b" * 64, str(view))

    def test_open_private_metrics_fails_only_affected_product(self):
        plan = mock_plan()
        report = module.verify_fleet(plan, public_transport(plan, ("specforge-ai", "/metricsz")))
        view = module.snapshot_from_report(report)
        self.assertEqual(view["result"], "DEGRADED")
        self.assertEqual([x["status"] for x in view["services"]].count("unavailable"), 1)
        self.assertEqual(view["services"][2]["status"], "unavailable")

    def test_malformed_report_never_downgrades_to_pass(self):
        plan = mock_plan()
        report = module.verify_fleet(plan, public_transport(plan))
        bad = dict(report)
        bad["products"] = report["products"][:4] + [dict(report["products"][0])]
        with self.assertRaises(ValueError):
            module.snapshot_from_report(bad)
        bad = dict(report)
        bad["result"] = "FAIL"
        with self.assertRaises(ValueError):
            module.snapshot_from_report(bad)

    def test_candidate_rejects_symlink_duplicate_keys_oversized_and_bad_schema(self):
        with tempfile.TemporaryDirectory() as folder:
            place = Path(folder)
            f = place / "plan.json"
            target = place / "target.json"
            f.write_text(json.dumps(mock_plan()))
            self.assertEqual(len(module.load_candidate(f)["products"]), 5)
            target.write_text("{}")
            f.unlink()
            f.symlink_to(target)
            with self.assertRaises(ValueError):
                module.load_candidate(f)
            f.unlink()
            f.write_text('{"schema":"x","schema":"y"}')
            with self.assertRaises(ValueError):
                module.load_candidate(f)
            f.write_text(" " * (module.MAX_PLAN_BYTES + 1))
            with self.assertRaises(ValueError):
                module.load_candidate(f)
            f.write_text("{}")
            with self.assertRaises(ValueError):
                module.load_candidate(f)

    def test_cache_serializes_concurrent_probes_and_returns_copies(self):
        lock = Lock()
        calls = []
        clock = [100.0]
        def collector():
            with lock:
                calls.append(1)
            return module.snapshot_from_report(module.verify_fleet(mock_plan(), public_transport(mock_plan())))
        cache = module.SnapshotCache(ttl=30, collector=collector, clock=lambda:clock[0])
        with ThreadPoolExecutor(max_workers=8) as pool:
            values = list(pool.map(lambda _:cache.snapshot(), range(8)))
        self.assertEqual(len(calls), 1)
        values[0]["services"][0]["status"] = "unavailable"
        self.assertEqual(cache.snapshot()["services"][0]["status"],"ready")
        clock[0] = 131.0
        cache.snapshot()
        self.assertEqual(len(calls), 2)

    def test_current_staging_availability_does_not_reuse_stale_release_candidate(self):
        plan = mock_plan()
        request = public_transport(plan)

        def newly_deployed(product, path):
            code, body = request(product, path)
            if path == "/versionz":
                body = dict(body, revision_sha="f" * 40)
            return code, body

        live = module.gather_current(newly_deployed)
        self.assertEqual(live["result"], "PASS")
        self.assertEqual(len(live["services"]), 5)
        self.assertTrue(all(row["status"] == "ready" for row in live["services"]))
        self.assertEqual(live["business_access"], "NOT_ENABLED")
        self.assertEqual(live["production_acceptance"], "NOT_ACCEPTED")
        self.assertNotIn("f" * 40, str(live))

    def test_current_monitor_denies_open_metrics_or_protected_business_data(self):
        plan = mock_plan()
        for path in ("/metricsz", module.verify_fleet.__globals__["BUSINESS_PATHS"]["accessfix-ai"]):
            with self.subTest(path=path):
                status = module.gather_current(public_transport(plan, ("accessfix-ai", path)))
                self.assertEqual(status["result"], "DEGRADED")
                self.assertEqual(status["services"][1]["status"], "unavailable")
                self.assertEqual([row["status"] for row in status["services"]].count("ready"), 4)

    def test_current_monitor_rejects_invalid_runtime_identity(self):
        transport = public_transport(mock_plan())
        def invalid_version(product, path):
            code, body = transport(product, path)
            if path == "/versionz" and product == "agenttest-lab":
                return code, dict(body, revision_sha="not-a-sha")
            return code, body
        report = module.gather_current(invalid_version)
        self.assertEqual(report["result"], "DEGRADED")
        self.assertEqual(report["services"][3]["status"], "unavailable")


    def test_cache_rejects_forged_business_access_and_contradictory_health(self):
        valid = module.snapshot_from_report(
            module.verify_fleet(mock_plan(), public_transport(mock_plan()))
        )
        mutations = []
        elevated = dict(valid)
        elevated["business_access"] = "ENABLED"
        mutations.append(elevated)
        accepted = dict(valid)
        accepted["production_acceptance"] = "ACCEPTED"
        mutations.append(accepted)
        extra = dict(valid)
        extra["services"] = valid["services"] + [{"product": "unexpected", "status": "ready"}]
        mutations.append(extra)
        conflicting = dict(valid)
        conflicting["services"] = [dict(item) for item in valid["services"]]
        conflicting["services"][0]["status"] = "unavailable"
        mutations.append(conflicting)
        swapped = dict(valid)
        swapped["services"] = list(reversed(valid["services"]))
        mutations.append(swapped)
        invented = dict(valid)
        invented["extra_status"] = "verified"
        mutations.append(invented)
        for mutated in mutations:
            with self.subTest(mutated=mutated):
                cache = module.SnapshotCache(collector=lambda value=mutated: value)
                result = cache.snapshot()
                self.assertEqual(result["result"], "DEGRADED")
                self.assertEqual(result["business_access"], "NOT_ENABLED")
                self.assertEqual(result["production_acceptance"], "NOT_ACCEPTED")
                self.assertTrue(all(x["status"] == "unavailable" for x in result["services"]))


    def test_collector_errors_stay_generic_and_fail_closed(self):
        def failure():
            raise RuntimeError("Authorization: Bearer forbidden-to-log")
        cache = module.SnapshotCache(collector=failure)
        result = cache.snapshot()
        self.assertEqual(result["result"],"DEGRADED")
        self.assertTrue(all(x["status"]=="unavailable" for x in result["services"]))
        self.assertNotIn("forbidden-to-log",str(result))


if __name__=="__main__":
    unittest.main()
