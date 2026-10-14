"""Read-only inventory of the five *deployed* ForgeWorks staging revisions.

This is an observation, NOT a production release acceptance. The read-only
transport is reused from the strict fleet verifier: fixed HTTPS origins,
allowed paths only, no redirects, bounded response bodies and duplicate-key
rejection. Never print authorization data, test identities or response errors.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from verify_fleet_release import PRODUCTS, fetch, unique_object, validate_plan

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE = ROOT / "ops/releases/fleet-staging-candidate.json"
MAX_BYTES = 65536
HEX_SHA = re.compile(r"[0-9a-f]{40}")
HEX_DIGEST = re.compile(r"[0-9a-f]{64}")


def valid_identity(product: str, identity: object) -> dict:
    if not isinstance(identity, dict) or set(identity) != {
        "product", "environment", "revision_sha", "runtime_manifest"
    } or identity["product"] != product or identity["environment"] != "staging":
        raise ValueError("INVALID_HOSTED_IDENTITY")
    revision = identity["revision_sha"]
    manifest = identity["runtime_manifest"]
    if not isinstance(revision, str) or not HEX_SHA.fullmatch(revision):
        raise ValueError("INVALID_HOSTED_REVISION")
    if not isinstance(manifest, dict) or set(manifest) != {
        "profile", "file_count", "sha256"
    } or manifest["profile"] != "forgeworks-runtime-manifest-v1":
        raise ValueError("INVALID_HOSTED_MANIFEST")
    if (type(manifest["file_count"]) is not int
            or not 1 <= manifest["file_count"] <= 256
            or not isinstance(manifest["sha256"], str)
            or not HEX_DIGEST.fullmatch(manifest["sha256"])):
        raise ValueError("INVALID_HOSTED_MANIFEST")
    return identity


def load_candidate(path: Path = CANDIDATE) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("INVALID_CANDIDATE_FILE")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("CANDIDATE_TOO_LARGE")
    plan = json.loads(data, object_pairs_hook=unique_object)
    validate_plan(plan)
    return plan


def observe(candidate: dict, request=fetch) -> dict:
    # Validate before any network interaction; malformed candidate cannot be
    # laundered into an apparently successful observation.
    planned = validate_plan(candidate)
    observed = []
    for product in PRODUCTS:
        try:
            states = {}
            for path, expected in (("/healthz", "ok"), ("/readyz", "ready")):
                status, body = request(product, path)
                states[path] = status == 200 and type(body) is dict and body.get("status") == expected
            code, body = request(product, "/versionz")
            identity = valid_identity(product, body) if code == 200 else None
            metrics_denied = request(product, "/metricsz")[0] == 401
            if not all(states.values()) or identity is None or not metrics_denied:
                raise ValueError("RUNTIME_BOUNDARY_OR_READINESS_FAILED")
            matches = (identity["revision_sha"] == planned[product]["revision_sha"]
                       and identity["runtime_manifest"] == planned[product]["runtime_manifest"])
            observed.append({
                "product": product, "result": "PASS" if matches else "DRIFT",
                "revision_sha": identity["revision_sha"],
                "runtime_manifest": identity["runtime_manifest"],
                "health": "PASS", "readiness": "PASS", "anonymous_metrics": "DENIED",
            })
        except Exception:
            # Hide exception text and raw transport data; audit logs may contain
            # user input and secrets in other transports.
            observed.append({"product": product, "result": "ERROR", "code": "OBSERVATION_FAILED"})
    overall = "MATCH" if all(item["result"] == "PASS" for item in observed) else "NOT_MATCHED"
    return {
        "schema": "forgeworks-fleet-staging-observation-v1",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "environment": "staging", "candidate_relation": overall,
        "products": observed, "production_acceptance": "NOT_ACCEPTED",
        "limits": "Public identity/readiness and anonymous metrics only. No business, tenant, load or recovery acceptance.",
    }


def exit_status(report: dict, strict: bool = False) -> int:
    """Strict scheduled probes must not be green on observed release drift."""
    if any(x["result"] == "ERROR" for x in report["products"]):
        return 1
    if strict and report["candidate_relation"] != "MATCH":
        return 1
    return 0


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Bounded read-only staging fleet inventory")
    parser.add_argument("--require-match", action="store_true",
                        help="Fail if any live revision or runtime fingerprint differs from the reviewed candidate")
    options = parser.parse_args()
    try:
        candidate = load_candidate()
        report = observe(candidate)
    except (OSError, ValueError, TypeError):
        print('FAILED_FLEET_INVENTORY_CONFIGURATION', file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return exit_status(report, strict=options.require_match)


if __name__ == "__main__":
    raise SystemExit(main())
