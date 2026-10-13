# APIShield Evidence Export Change Advisory — 2026-10-13

**Status:** Candidate implementation on `agent/apishield-metadata-evidence-export`; independent read-only review found no issues. PostgreSQL runtime CI remains pending. This advisory does not change the G1 gate or claim deployment readiness.

## Change classification and scope

This is a security-sensitive, additive read surface for audit metadata. It adds `GET /v1/analyses/{analysis_id}/evidence-export` with the explicit `evidence:read` scope. The endpoint is available only for terminal analyses and active tenant members, and it rejects access when repository permission has been revoked. PostgreSQL uses tenant RLS plus a repository share lock; the evidence rows are read within one repeatable-read transaction. A serialization failure (`SQLSTATE 40001`) is retried once; a second conflict fails closed with 409. SQLite opens an explicit read transaction for the same snapshot behavior.

No database migration, object-store write, export record, GitHub write, approval behavior change, or retention job is added. The route returns an `application/json` attachment with `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`; error responses use `application/problem+json`. The request has no external side effect.

## Export contents and integrity

The bounded manifest contains:

- Tenant and analysis identifiers, terminal outcome, base/head commit identifiers, and analysis timestamps.
- The initiating actor and request digest when exactly one matching idempotency record exists.
- SHA-256 digests for the analyzed base/head source bytes; the server re-decodes and verifies stored bytes against those hashes before export.
- The declared capability profile, findings and their evidence digests, proposal status/digests, and approval decisions with reviewer IDs and expiry.
- IDs and metadata for existing audit events, plus a digest of each canonicalized event payload; raw event payloads are not returned.
- An explicit `missing_components` list and `evidence_status` (`PARTIAL` or `COMPLETE`).

Raw source bytes, base64 snapshots, patch text, credentials, signed transfer URLs and external provider data are not included. The bundle digest is SHA-256 over the canonical UTF-8 JSON serialization of all bundle fields except `bundle_sha256`, using sorted keys and compact separators. The result is deterministic for an unchanged database snapshot.

The export fails closed for non-terminal analyses, revoked repository access, corrupted source bytes or audit payloads, more than 1000 items in any exported collection, or a serialized response over 2 MiB. Oversized exports are rejected rather than truncated.

## Known completeness gaps — do not claim a complete audit package

The current data model does not persist a versioned analyzer build or policy version, nor per-finding rule versions. It does not emit proposal-creation or approval-decision audit events, does not record access to this GET export, and does not implement the owner-specified two-year evidence retention. Terminal failures/cancellations also lack a terminal-outcome audit event. These gaps are reported in the bundle rather than synthesized. Consequently, ordinary exports are `PARTIAL`; this change is not an attestation, a compliance archive, or proof of the retention requirement.

The separate product decisions on rate limits/quotas remain untouched. No numeric quota is introduced by this patch.

## Rollback and operational boundary

Rollback is a code revert of this branch/PR; no migration or persistent export data needs cleanup. Disabling `evidence:read` issuance or reverting the route stops new exports. Because the operation is a GET, it does not create a durable audit record; that limitation is explicitly surfaced and must be addressed before treating the endpoint as a fully audited export workflow.

## Local verification

- `APP_ENV=test AUTH_MODE=development python -W error -m pytest tests -q -rs`: **497 passed, 6 skipped, 24 subtests passed**.
  - One skip is `tests/integration/test_postgres_runtime.py`: no explicitly opted-in disposable PostgreSQL instance was available locally; this is **not** a local PostgreSQL runtime pass.
  - Five skips belong to the TypeScript caller CLI tests, which require their dedicated CI step.
- SDK regeneration and strict TypeScript compile: pass (`npm run generate --prefix packages/sdk` and `npm run check --prefix packages/sdk`).
- Browser JavaScript syntax and tests: pass (**11 tests**).
- TypeScript caller-analysis tests and the dedicated Python CLI proof: pass (**42 Node tests and 5 pytest cases**).
- Bootstrap scan: pass (**255 files scanned, no findings**).
- Static contract check: pass (**15 operations, no errors**).
- Independent OpenAPI validation: pass. This is not a runtime test.
- `git diff --check`: pass.

No disposable PostgreSQL service is configured in this local sandbox; its pytest skip is not a runtime pass. The disposable PostgreSQL CI workflow must execute the updated `test_postgres_runtime.py` on the PR head before the change is treated as verified. Independent review is complete with no findings; owner/release signoffs remain pending.
