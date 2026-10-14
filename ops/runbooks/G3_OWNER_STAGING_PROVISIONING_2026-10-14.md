# G3 staging: owner-authorized identity provisioning and acceptance runbook

Date: 2026-10-14. **ForgeWorks AI only** (Supabase project `fljekuwplgkrpdoajyhn` and Railway project `ForgeWorks AI staging`). SealAngel is excluded.

## Verified and already completed

- Owner explicitly authorized creating new staging-only identities, tenants and synthetic business fixtures on 2026-10-14.
- Read-only schema verification confirmed `tenants(id,slug,status)` and `memberships(tenant_id,user_id,role,status)` in all five ForgeWorks product schemas. The `user_id` column is **text** in APIShield, **uuid** in the other four.
- Exactly **10 NEW ACTIVE staging tenant records** were inserted, two per product, in one Postgres transaction, using `gen_random_uuid()` and slugs `g3-owner-20261014-tenant-a` / `g3-owner-20261014-tenant-b`.
- A separate SELECT proved exactly **5 `a` and 5 `b`** new tenants. Old records and the 16 REVOKED memberships were untouched.
- `scripts/g3_staging_grants.sql` is a read-only, tested SQL query returning exactly two `app_metadata` JSON objects, each with five product grants for the correct tenant. Each grant has **only one explicit read scope**. Do not copy these tenant IDs into public CI artifacts.
- The existing opt-in `scripts/probe_authenticated_tenant_isolation.py` has strict staging issuer/time preflight and verifies the exact five-service Railway release fingerprint **before** authenticated business probes.

## Blocker verified through connected app permissions

The Supabase connector exposes database SQL, management APIs and Edge Function deployment, **not Supabase Auth Admin createUser/updateUserById**. Railway OAuth exposes variable names only, not secret values; the five app services expose `SUPABASE_PUBLISHABLE_KEY` but **not a secret/service-role key** for Admin provisioning. A publishable key cannot authorize Auth Admin changes.

**Do not** insert into `auth.users` via SQL, convert REVOKED historical users into fixtures, deploy an unguarded Admin endpoint, alter JWTs or copy secret keys into public GitHub or chat. No production deployment is authorized by this acceptance runbook.

## One necessary owner-controlled Admin operation (two NEW users)

Through the [ForgeWorks Supabase Authentication dashboard](https://supabase.com/dashboard/project/fljekuwplgkrpdoajyhn/auth/users), create two fresh, controlled test accounts distinct from existing users. Choose strong credentials and arrange email verification or use trusted server-only [Auth Admin createUser](https://supabase.com/docs/reference/javascript/auth-admin-createuser) with `email_confirm` where appropriate; no production person/customer emails. Do not post credentials or access tokens.

Retrieve the `a` and `b` JSON returned by [the read-only grant planner](../../scripts/g3_staging_grants.sql). Set those as **server-owned** `app_metadata` for the corresponding new accounts via [Auth Admin updateUserById](https://supabase.com/docs/reference/javascript/auth-admin-updateuserbyid) in a secure server-side context. Do not use `user_metadata`: users can edit that field. Create fresh sessions *after* updating the grants.

The only information safe to share with the connected assistant for SQL-based membership registration is **the two new Auth user UUIDs and which one is A/B**. Keep email, password, service-role key and tokens outside chat. All changes can then be implemented against the **10 already created tenant rows**, conditional on verifying those Auth UUIDs are new and currently active.

## Membership registration invariants

For each of the five schemas, insert one `viewer` / `ACTIVE` membership for user A into the `-a` tenant and user B into the `-b` tenant, using a single transaction with strict positive postconditions.

Before inserting:
- Exact project `fljekuwplgkrpdoajyhn`; confirm neither UUID equals an existing REVOKED membership principal.
- Verify both users exist in `auth.users`, are distinct, are current non-anonymous test identities and have the expected five product grants in `raw_app_meta_data`.
- Verify all ten `tenants` are `ACTIVE` and no target membership currently exists.
- Stop on any existing/conflicting membership. Never use `ON CONFLICT DO UPDATE` or mass update a membership table.

After inserting, independently re-query each (schema, tenant, user) combination: exactly 10 `ACTIVE viewer` rows; no change to prior 16 `REVOKED` rows. Treat membership INSERT as authorized staging setup, **not as proof that JWT/session enforcement works**.

## Hosted acceptance still requires product-generated business fixtures

Create exactly one owned business resource per newly authorized identity *through each product's authorized API*, not through direct inserts into business tables. Required real resource classes:

| Product | Protected read endpoint | Required signed scope |
| --- | --- | --- |
| APIShield Agent | `GET /v1/analyses/{id}` | `analysis:read` |
| AccessFix AI | `GET /v1/scans/{id}/findings` | `scan:read` |
| SpecForge AI | `GET /v1/spec-revisions/{id}/openapi` | `spec:read` |
| AgentTest Lab | `GET /v1/evaluation-runs/{id}/cases` | `evaluation:read` |
| DataReconcile AI | `GET /v1/reports/{id}/signature` | `report:read` |

After each product's two independent fixtures are ready, supply ephemeral token and resource IDs to the opt-in script in a secure, isolated test execution environment. It first checks the **actual hosted five-service revision/manifest**, then requires HTTP 200 for both own-record reads and HTTP 403/404 for both cross-tenant reads. Never report synthetic tests, auth dashboard existence or infrastructure readiness as a G3 PASS.

## Remaining acceptance controls

- Authenticated read and write isolation, membership downgrade/revocation, expired-session handling and secret-safe evidence
- Real functional and provider acceptance across five products, signed artifacts, bounded workloads/SLO, observability, incident and restore/DR
- Independent security/privacy review and owner signoff for the **production** environment, which must be isolated from staging

**Current status:** TENANTS_PREPARED; AUTH_IDENTITIES_NOT_PROVISIONED; MEMBERSHIPS_NOT_ACTIVE; BUSINESS_FIXTURES_INCOMPLETE; HOSTED_G3_NOT_ACCEPTED; PRODUCTION_NO_GO.
