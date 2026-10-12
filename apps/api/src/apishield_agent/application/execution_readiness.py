"""Reject hosted queue admission when no executable worker path is configured."""
import os


def hosted_execution_error(tenant, store, source_reader):
    if os.getenv("APP_ENV", "development") not in {"staging", "production"}:
        return None
    if source_reader is None:
        return "SOURCE_PROVIDER_NOT_CONFIGURED"
    if os.getenv("APISHIELD_EMBEDDED_WORKER", "1") != "1":
        # A future external-worker heartbeat can establish admission readiness.
        # A declaration in an environment variable is not a live-worker proof.
        return "WORKER_NOT_AVAILABLE"
    worker_tenants = getattr(store, "worker_tenants", None)
    try:
        if worker_tenants is None or tenant not in worker_tenants():
            return "TENANT_WORKER_NOT_ENROLLED"
    except (ValueError, TypeError):
        return "WORKER_CONFIGURATION_INVALID"
    return None
