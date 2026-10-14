# ForgeWorks G3 hosted authenticated tenant acceptance: staging fixture gap

**Observed date:** 2026-10-14. **Environment:** existing ForgeWorks AI staging only.
**Status:** NOT_ACCEPTED. The observations below are point-in-time aggregate
database counts; do not infer signed identities, ownership, or customer value.

## Read-only connected staging inventory

- Supabase project: `fljekuwplgkrpdoajyhn` (five ForgeWorks product schemas).
- Supabase Auth: 2 auth.users and 2 auth.sessions records observed. A session
  row alone does **not** establish a usable unexpired bearer token or a currently
  permitted user.
- Product memberships: APIShield 8 rows spanning 6 tenants; AccessFix, SpecForge,
  AgentTest, and DataReconcile each have 2 memberships spanning 2 tenants.
- Accessible business-fixture inventory from direct table aggregates:

| Product | Business table | Rows | Distinct tenants | Requirement |
|---|---|---:|---:|---|
| APIShield Agent | `analysis_jobs` | 5 | 5 | Verify two records tied to two current provisioned test accounts |
| AccessFix AI | `scan_jobs` | 0 | 0 | Two separately owned valid scan records |
| SpecForge AI | `spec_revisions` | 0 | 0 | Two separately owned revisions |
| AgentTest Lab | `evaluation_runs` | 2 | 1 | Run record for a second independently authorized tenant |
| DataReconcile AI | `reports` | 0 | 0 | Two separately owned report records |

These are aggregate counts, not signed proof of fixture ownership. Do not seed
business records directly as a substitute for using authorized product flows.

## Already completed and separately evidenced

1. Five production-denying staging deployments are healthy, with exact public
   release fingerprint proof.
2. Four S3-backed products passed pre-deploy synthetic upload, read-integrity,
   delete and verified-absence probes; each receipt lives at
   `docs/evidence/STAGING_S3_DISPOSABLE_PROOF_2026-10-14.json` in its own repo.
3. AgentTest case listing now returns tenant-safe 404 when the run is invisible,
   rather than HTTP 200 with an empty list. Real two-tenant hosted business
   acceptance is still not claimed.

## Required live G3 proof

The opt-in script `scripts/probe_authenticated_tenant_isolation.py` is
read-only and fail-closed. It requires:

- Explicit owner authorization through `FORGEWORKS_G3_AUTH_ACCEPTANCE=yes`.
- Two **different active** Supabase test identities with a current access token
  each and a distinct active product membership, via **server-owned**
  `app_metadata.forgeworks[product]` grants for each of the five products.
- Five product-specific owned business resource IDs for **each** account.
- Positive HTTP 200 GET of each owner's own resource, plus HTTP 403/404 when
  each account reads the *other* account's resource, for all five products.
- Revocation negative tests after approved session/membership changes, with a
  fresh session as needed. Never alter live customer identities.

**Credential boundary:** do not put test tokens or signing keys into GitHub
source, issue comments, CI artifacts, browser localStorage, or chat. Use an
approved ephemeral server-side secret mechanism and redact all probe logs.

**Failure semantics:** the existence of two Auth users, an empty business table,
a database membership count, successful synthetic CI, or an HTTP 401 from an
anonymous request cannot be promoted to a passing authenticated cross-tenant
proof. Production additionally requires independent privacy, security, recovery,
SLO and owner acceptance.
