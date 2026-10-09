# Worker (PLANNED)
No agent/tool execution exists. Sandbox/permissions tests must pass before enabling untrusted workloads.


## Runnable durable worker

Install `apps/api`, set `APISHIELD_EMBEDDED_WORKER=0` in the API process, and run `python -m apishield_agent.application.analysis_worker` in the worker process. Use `--once` for a bounded one-job run. Both processes share `APISHIELD_DATABASE_URL`; PostgreSQL workers also require an explicit UUID allowlist in `APISHIELD_WORKER_TENANTS`. SQLite is supported only for synthetic development/test via `APISHIELD_DB_PATH`. No untrusted repository code is executed.
