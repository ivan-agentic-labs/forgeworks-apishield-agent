"""Offline regression tests for per-endpoint latency evidence and fail-closed thresholds."""
from contextlib import redirect_stdout
from io import StringIO
import importlib.util
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/probe_bounded_staging_load.py"
spec = importlib.util.spec_from_file_location("staging_load_test", SCRIPT)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class BoundedLoadEvidenceTests(TestCase):
    def parse_output(self, value):
        idx = value.index('{\n')
        end = value.index('\nPASS 75 read-only live HTTPS probes', idx)
        return json.loads(value[idx:end])

    def test_separate_health_and_readiness_samples_not_mixed(self):
        def fake(host, path, status):
            assert host in probe.DOMAINS.values()
            return 4.0 if path == "/healthz" else 250.0
        buffer = StringIO()
        with patch.object(probe, "request", side_effect=fake), redirect_stdout(buffer):
            probe.main()
        report = self.parse_output(buffer.getvalue())
        self.assertEqual(report["measured_requests"], 75)
        self.assertEqual(report["error_count"], 0)
        self.assertEqual(len(report["endpoint_latency_ms"]), 5)
        for product, endpoints in report["endpoint_latency_ms"].items():
            with self.subTest(product=product):
                self.assertEqual(endpoints["/healthz"]["samples"], 12)
                self.assertEqual(endpoints["/healthz"]["p50"], 4.0)
                self.assertEqual(endpoints["/readyz"]["samples"], 3)
                self.assertEqual(endpoints["/readyz"]["p95"], 250.0)
                self.assertEqual(report["services"][product]["passed"], 15)

    def test_readiness_only_regression_must_fail(self):
        def fake(host, path, status):
            return 4.0 if path == "/healthz" else probe.MAX_P95_MS + 1.0
        with patch.object(probe, "request", side_effect=fake), redirect_stdout(StringIO()):
            with self.assertRaisesRegex(AssertionError, "latency check failed"):
                probe.main()

    def test_upstream_error_must_fail_even_when_other_services_pass(self):
        seen = {"ready": 0}
        def fake(host, path, status):
            if host == probe.DOMAINS["SpecForge"] and path == "/readyz":
                seen["ready"] += 1
                if seen["ready"] > 1:
                    raise AssertionError("synthetic failure")
            return 5.0
        with patch.object(probe, "request", side_effect=fake), redirect_stdout(StringIO()):
            with self.assertRaisesRegex(AssertionError, "latency check failed"):
                probe.main()
