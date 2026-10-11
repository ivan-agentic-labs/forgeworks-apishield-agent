"""Bounded, read-only concurrent staging probe; NOT a capacity certification.

Five known Railway-managed ForgeWorks staging domains. 3 concurrent requests
max, 15 measured GETs per product (12 liveness, 3 readiness), 5 warmups.
No write endpoints, tokens, credentials, accounts or customer data.
"""
from __future__ import annotations

import json
import math
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DOMAINS = {
    "APIShield": "apishield-agent-staging.up.railway.app",
    "AccessFix": "accessfix-ai-staging.up.railway.app",
    "SpecForge": "specforge-ai-staging.up.railway.app",
    "AgentTest": "agenttest-lab-staging.up.railway.app",
    "DataReconcile": "datareconcile-ai-staging.up.railway.app",
}
MAX_WORKERS = 3
REQUEST_TIMEOUT = 10
MAX_BODY = 1024
MAX_P95_MS = 5000
COUNTS = (("/healthz", 12, "ok"), ("/readyz", 3, "ready"))


def request(host: str, path: str, expected: str) -> float:
    started = time.perf_counter()
    req = Request("https://" + host + path, headers={
        "Accept": "application/json",
        "User-Agent": "ForgeWorks-Bounded-Readiness-Probe/1.0",
    }, method="GET")
    try:
        with urlopen(req, timeout=REQUEST_TIMEOUT) as response:
            status, body = response.status, response.read(MAX_BODY + 1)
    except HTTPError as exc:
        raise AssertionError(f"HTTP {exc.code}: {host}{path}") from None
    except (URLError, TimeoutError) as exc:
        raise AssertionError(f"Network failure: {host}{path}, {type(exc).__name__}") from None
    elapsed_ms = (time.perf_counter() - started) * 1000
    if status != 200 or len(body) > MAX_BODY:
        raise AssertionError(f"Invalid status/size: {host}{path} HTTP {status}")
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise AssertionError(f"Invalid JSON: {host}{path}") from exc
    if not isinstance(payload, dict) or payload.get("status") != expected:
        raise AssertionError(f"Unhealthy response: {host}{path}")
    return elapsed_ms


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    rank = math.ceil(pct * len(ordered)) - 1
    return ordered[max(0, min(rank, len(ordered) - 1))]


def main() -> None:
    # Warmup checks detect unavailable deployment before bounded concurrency.
    for name, host in DOMAINS.items():
        request(host, "/readyz", "ready")
        print(f"WARMUP {name}: ready", flush=True)
    tasks = [(name, host, path, status)
             for name, host in DOMAINS.items()
             for path, count, status in COUNTS
             for _ in range(count)]
    results: dict[str, list[float]] = {name: [] for name in DOMAINS}
    errors = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(request, host, path, status): (name, path)
                   for name, host, path, status in tasks}
        for future in as_completed(futures):
            name, path = futures[future]
            try:
                results[name].append(future.result())
            except AssertionError as exc:
                errors.append({"service": name, "path": path, "error": str(exc)})
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": "bounded-read-only-staging-probe",
        "concurrency": MAX_WORKERS,
        "measured_requests": len(tasks),
        "services": {name: {
            "passed": len(values), "p50_ms": round(statistics.median(values), 1) if values else None,
            "p95_ms": round(percentile(values, .95), 1) if values else None,
            "max_ms": round(max(values), 1) if values else None,
        } for name, values in results.items()},
        "error_count": len(errors),
        "errors": errors[:8],
    }
    print(json.dumps(report, indent=2, sort_keys=True), flush=True)
    if errors or any(len(values) != 15 or percentile(values, .95) > MAX_P95_MS
                     for values in results.values()):
        raise AssertionError("Bounded staging readiness or latency check failed")
    print("PASS 75 read-only live HTTPS probes, zero errors and bounded p95 on all five products.")
    print("LIMITATION: this cannot establish authenticated performance, sustained throughput or production capacity.")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
