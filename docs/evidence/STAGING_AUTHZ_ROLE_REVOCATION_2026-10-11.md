# Role-aware staging authorization checkpoint — 2026-10-11

## Verified current source

- Product: `apishield-agent`.
- Railway environment: `staging`, project `1b35f35d-ad5b-4b93-ad20-ed68251b4589`.
- Running source commit: `bbd9f18a8c77722995daf9268007f7f60ade3015`, deployment `e16eec4f-659e-4104-b990-c0e1ad7ad204`, Railway `SUCCESS`, one running replica, zero crashed.
- Railway GitHub source is pinned to the above SHA. Documentation/test-only commits after that SHA are **not** automatically deployed.
- Functional change: a current ACTIVE database membership role AND a signed, product-scoped JWT permission are both required. `viewer` is read-only; trusted role labels are case-normalized; unknown roles fail closed. The existing session revocation check remains.
- [Membership-role authorization PR](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/pull/9) and [canonical role casing PR](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/pull/10): approved by green CI and merged.
- [Disposable PostgreSQL immediate revocation regression](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/pull/11): tests an editor's ACTIVE->REVOKED->ACTIVE transition **only in an isolated localhost fixture**. This does not reactivate a hosted staging account.

## Actual Supabase staging authorization state

- Exactly two server-pregranted, email-verified identities have matching staging tenant records for this product.
- Both matching membership rows have role `OWNER` and status `REVOKED`; there are `0 ACTIVE` memberships.
- This is a **deliberate denial state** until authorized identity review. No staged user was created, promoted, reauthorized, or issued an access token.
- An AccessFix viewer insertion was **rejected inside a transaction and rolled back** because the existing revoked primary keys prevented a safe new grant. Candidate scripts were removed. See the cross-project checkpoint in `forgeworks-accessfix-ai/docs/evidence/STAGING_REVOKED_IDENTITY_BLOCKER_2026-10-11.md`.

## What the evidence does and does not prove

Proven: synthetically tested role/scope intersection, current status-based membership denial in disposable PostgreSQL, CI checks, and a running version-pinned staging service. Scheduled public HTTPS smoke tests independently verify readiness and unauthenticated request denial.

Not proven: real authenticated customer flows, manual approval of past revocations, cross-tenant *hosted* identity isolation, external provider connectors, monitored load/SLOs, operational restore/DR, and G3–G6 owner/domain/legal acceptance. Production gate: **NO-GO**. No customer data use, new production environment or release.
