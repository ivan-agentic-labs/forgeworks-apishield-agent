"""Bounded, fail-closed five-product staging monitoring for a local portal.

All upstream HTTPS requests use the exact, non-configurable host allowlist and
strict transport from scripts.verify_fleet_release. No forwarding of browser
headers, authorization tokens, cookies, paths, or customer data. This does
NOT enable a business BFF, hosted user login, or production acceptance.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys
from threading import Lock
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from verify_fleet_release import (  # noqa: E402
    MAX_PLAN_BYTES, PRODUCTS, unique_object, validate_plan, verify_fleet,
)

CANDIDATE = ROOT / "ops/releases/fleet-staging-candidate.json"
ALLOWED_RESULT = {"PASS", "FAIL"}


def load_candidate(path: Path = CANDIDATE) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("CANDIDATE_UNSAFE")
    with path.open("rb") as stream:
        raw = stream.read(MAX_PLAN_BYTES + 1)
    if len(raw) > MAX_PLAN_BYTES:
        raise ValueError("CANDIDATE_TOO_LARGE")
    return validate_plan(json.loads(raw, object_pairs_hook=unique_object))


def snapshot_from_report(report: dict) -> dict:
    if (type(report) is not dict
            or report.get("schema") != "forgeworks-fleet-public-release-proof-v1"
            or report.get("environment") != "staging"
            or report.get("result") not in ALLOWED_RESULT
            or type(report.get("products")) is not list
            or len(report["products"]) != len(PRODUCTS)):
        raise ValueError("INVALID_FLEET_REPORT")
    seen = set()
    services = []
    for item in report["products"]:
        if type(item) is not dict:
            raise ValueError("INVALID_PRODUCT_REPORT")
        product, result = item.get("product"), item.get("result")
        if product not in PRODUCTS or product in seen or result not in ALLOWED_RESULT:
            raise ValueError("INVALID_PRODUCT_RESULT")
        seen.add(product)
        # Deliberately discard raw upstream error text, SHA and fingerprints.
        services.append({"product": product,
                         "status": "ready" if result == "PASS" else "unavailable"})
    if seen != set(PRODUCTS):
        raise ValueError("INCOMPLETE_FLEET_REPORT")
    by_id = {item["product"]: item for item in services}
    ordered = [by_id[product] for product in PRODUCTS]
    outcome = "PASS" if all(x["status"] == "ready" for x in ordered) else "DEGRADED"
    if (outcome == "PASS") != (report["result"] == "PASS"):
        raise ValueError("INCONSISTENT_FLEET_REPORT")
    return {
        "schema": "forgeworks-portal-staging-services-v1",
        "environment": "staging",
        "result": outcome,
        "services": ordered,
        "business_access": "NOT_ENABLED",
        "production_acceptance": "NOT_ACCEPTED",
    }


def gather(request=None) -> dict:
    plan = load_candidate()
    report = verify_fleet(plan) if request is None else verify_fleet(plan, request)
    return snapshot_from_report(report)


class SnapshotCache:
    """One bounded fleet probe per TTL across concurrent preview requests."""

    def __init__(self, ttl: int = 30, collector=gather, clock=time.monotonic):
        if type(ttl) is not int or not 5 <= ttl <= 300:
            raise ValueError("INVALID_CACHE_TTL")
        self.ttl = ttl
        self.collector = collector
        self.clock = clock
        self.lock = Lock()
        self.expiry = 0.0
        self.value = None

    def snapshot(self) -> dict:
        with self.lock:
            now = self.clock()
            if self.value is not None and now < self.expiry:
                return deepcopy(self.value)
            try:
                current = self.collector()
                if (type(current) is not dict
                        or current.get("schema") != "forgeworks-portal-staging-services-v1"
                        or current.get("environment") != "staging"
                        or current.get("result") not in {"PASS", "DEGRADED"}):
                    raise ValueError("INVALID_COLLECTOR_SNAPSHOT")
            except Exception:
                # Do not leak the exception; internal outage cannot become a PASS.
                current = {
                    "schema": "forgeworks-portal-staging-services-v1",
                    "environment": "staging",
                    "result": "DEGRADED",
                    "services": [{"product": p, "status": "unavailable"} for p in PRODUCTS],
                    "business_access": "NOT_ENABLED",
                    "production_acceptance": "NOT_ACCEPTED",
                }
            self.value = deepcopy(current)
            self.expiry = self.clock() + self.ttl
            return deepcopy(self.value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fixed-origin staging fleet observer")
    parser.add_argument("--live-staging", action="store_true", required=True,
                        help="Explicit read-only staging network opt-in")
    args = parser.parse_args()
    if not args.live_staging:
        return 2
    result = SnapshotCache(ttl=30).snapshot()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
