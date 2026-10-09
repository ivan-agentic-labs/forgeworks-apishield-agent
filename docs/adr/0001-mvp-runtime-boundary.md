# ADR-0001: Synthetic MVP runtime boundary

- Status: accepted for implementation milestone, not production approval
- Date: 2026-10-09

## Decision

Implement the first APIShield vertical slice with FastAPI, a tenant-scoped SQLite adapter for reproducible local tests, a persisted job state plus polling worker, and a deterministic OpenAPI diff limited to added required response fields. Use a development-only HS256 issuer with explicit issuer, audience, expiry, scope, and membership checks.

The PostgreSQL migration is versioned separately and includes tenant RLS policies. It is not claimed as live evidence until executed with migration and non-owner roles in disposable PostgreSQL. The `30_fk_addendum_REVIEW_ONLY.sql` candidate is not applied.

## Rationale

This creates an executable, synthetic-only acceptance slice without external GitHub credentials, customer data, arbitrary repository execution, AI provider calls, or remote writes. The boundary keeps domain diff code independent from FastAPI and persistence.

## Consequences

- Verified: deterministic fixture analysis, auth fail-closed behavior, idempotency, job persistence, findings, and status reads.
- Not verified: live PostgreSQL/RLS, real OIDC/JWKS, GitHub App, sandbox, external queue, remote PR, and production deployment.
- Any production configuration using the development secret is rejected by the application.
