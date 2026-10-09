# APIShield Agent MVP

This synthetic-only MVP implements authenticated analysis requests, tenant-scoped local persistence, a persisted job state, a polling worker, deterministic OpenAPI required-response-field diffing, findings, and status reads.

Run with `python -m pip install -e 'apps/api[test]'` and `APISHIELD_SEED_FIXTURE=1 PYTHONPATH=apps/api/src uvicorn apishield_agent.main:app`.

The local SQLite store and HS256 development issuer are test-only. Production still requires a configured OIDC/JWKS validator, PostgreSQL adapter, queue, repository reader, sandbox, and reviewed GitHub App permissions. The PostgreSQL migration is `migrations/versions/001_apishield_mvp.sql`; candidate SQL and `30_fk_addendum_REVIEW_ONLY.sql` are not applied automatically.
