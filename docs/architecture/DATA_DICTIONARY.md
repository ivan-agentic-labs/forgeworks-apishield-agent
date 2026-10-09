# APIShield Agent — Data model, relational constraints and transaction design

## Canonical relational aggregates (v4.1: authoritative)

Previous v4.0 terminology is mapped to **one** physical table per aggregate. Never generate two tables for one alias.

| Previous functional term | Canonical table | Mapping |
|---|---|---|
| `github_installations` | `github_installations` | Unchanged |
| `repositories` | `repositories` | Unchanged |
| `contract_snapshots` | `contract_snapshots` | Unchanged |
| `analysis_runs` | `analysis_jobs` | Renamed alias |
| `impact_findings` | `analysis_findings` | Renamed alias |
| `patch_proposals` | `patch_proposals` | Unchanged |
| `test_executions` | `test_executions` | Unchanged |
| `approval_decisions` | `approvals` | Renamed alias |
| `remote_effects` | `pr_effects` | Renamed alias |

All canonical tables must have a physical column contract below; shared per-product platform tables are covered in governance.

## RLS and role design (not executed migration)
- Separate migration/owner role from API/worker read-write roles; application roles never hold BYPASSRLS/superuser or table owner privileges.
- Enable RLS and FORCE where suitable, separate `USING` and `WITH CHECK`; set `app.tenant_id` with `SET LOCAL` inside transactional request after auth membership resolution.
- Transaction-pool reused sessions must not inherit tenant variables. Test PgBouncer/pooled mode after selected provider is known.
- Compound FK + membership/policy validation is required despite RLS; no cross-tenant object keys or storage ACL inheritance.
- Synthetic two-tenant fixtures cover SELECT/INSERT/UPDATE/DELETE, foreign keys, joined views, workers and pooled connections.

## SQL transaction boundaries
1. Job accepted: domain validation + write `jobs` + `outbox` + `idempotency_records` in a **single commit**; return 202 only after commit succeeds.
2. Worker lease: visibility timeout/fencing token; dedupe message ID in inbox; at-least-once delivery with idempotent handlers.
3. Approval: compare `version` and content SHA, actor role+tenant, policy, expiry and external permission; conflicting writers return 409.
4. External effect: commit unique effect reservation → invoke outside DB transaction → store external ID/outcome; timeout -> `UNKNOWN_REMOTE` -> provider-specific lookup/reconciliation; never retry blindly.
5. Artifact: quarantine content until checksum, MIME, virus/format checks and final tenant-owner authorization; download intent scoped and revocation bounded by provider semantics.

## Domain-specific invariants and source column dictionary
GitHub App tokens scoped per installation/repository; code and CI scripts run in disposable remote VM; branch SHA and patch SHA bound to approval; PR effect reconciled after timeout.

# APIShield Agent — proposed physical model, not executed DDL

## Shared physical schema model (applied independently per product)

All tenant-owned tables: `tenant_id UUID NOT NULL`, `id UUID NOT NULL`, `created_at TIMESTAMPTZ NOT NULL DEFAULT now()`, `PRIMARY KEY (tenant_id,id)`.
A child FK must use `(tenant_id,parent_id) REFERENCES parent(tenant_id,id)`; foreign UUID alone is insufficient. Database roles: migration owner != API/worker; API/worker roles have no SUPERUSER/BYPASSRLS privileges. Proposed RLS uses `tenant_id = nullif(current_setting('app.tenant_id',true),'')::uuid` with `USING` and `WITH CHECK`; tenant context set `SET LOCAL` **inside a transaction** using server-verified membership, never client supplied. Connection pool reuse without transaction isolation is prohibited.

Other independent core tables for every product: `tenants`, `users`, `memberships`, `jobs`, `outbox_events`, `inbox_receipts`, `idempotency_records`, `audit_events`, `artifact_references` (tenant-scoped). Their schema and cleanup/retention must be supplied by the shared-platform contract before migration code.

Immutable audit records require explicit retention/legal basis. Event idempotency does not imply exactly-once external effects; use reconciliation and unique natural business keys. Soft deletion alone is not a privacy deletion implementation.


## Domain tables

### `repositories`

| Column | PostgreSQL design type / rule |
|---|---|
| `tenant_id` | `UUID NOT NULL` |
| `id` | `UUID NOT NULL` |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` |
| `installation_ref_id` | `uuid NOT NULL` |
| `github_node_id` | `text NOT NULL` |
| `default_branch` | `text NOT NULL` |
| `permission_state` | `text NOT NULL` |
| `updated_at` | `timestamptz NOT NULL` |

**Keys/indexes:** `PRIMARY KEY (tenant_id,id)`; `UNIQUE (tenant_id, github_node_id)`.
**Scoped FK:** `(tenant_id,installation_ref_id) -> github_installations(tenant_id,id)`.
**Domain constraints:** installation ownership verified before reading repository; GitHub external numeric installation ID exists only in `github_installations`.

### `contract_snapshots`

| Column | PostgreSQL design type / rule |
|---|---|
| `tenant_id` | `UUID NOT NULL` |
| `id` | `UUID NOT NULL` |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` |
| `repository_id` | `uuid NOT NULL` |
| `commit_sha` | `text NOT NULL` |
| `oas_sha256` | `char(64) NOT NULL` |
| `profile_version` | `text NOT NULL` |
| `artifact_key` | `text NOT NULL` |

**Keys/indexes:** `PRIMARY KEY (tenant_id,id)`; `UNIQUE (tenant_id, repository_id, commit_sha, oas_sha256)`.
**Scoped FK:** `(tenant_id,repository_id) -> repositories(tenant_id,id)`.
**Domain constraints:** unsupported constructs tagged unsupported.

### `analysis_jobs`

| Column | PostgreSQL design type / rule |
|---|---|
| `tenant_id` | `UUID NOT NULL` |
| `id` | `UUID NOT NULL` |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` |
| `repository_id` | `uuid NOT NULL` |
| `base_sha` | `text NOT NULL` |
| `head_sha` | `text NOT NULL` |
| `status` | `text NOT NULL` |
| `profile_version` | `text NOT NULL` |
| `version` | `int NOT NULL DEFAULT 1` |

**Keys/indexes:** `PRIMARY KEY (tenant_id,id)`; `INDEX (tenant_id, repository_id, created_at DESC)`.
**Scoped FK:** `(tenant_id,repository_id) -> repositories(tenant_id,id)`.
**Domain constraints:** immutable commits through approval.

### `analysis_findings`

| Column | PostgreSQL design type / rule |
|---|---|
| `tenant_id` | `UUID NOT NULL` |
| `id` | `UUID NOT NULL` |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` |
| `analysis_id` | `uuid NOT NULL` |
| `rule_id` | `text NOT NULL` |
| `openapi_pointer` | `text NOT NULL` |
| `coverage` | `text NOT NULL` |
| `evidence_sha256` | `char(64) NOT NULL` |

**Keys/indexes:** `PRIMARY KEY (tenant_id,id)`; `UNIQUE (tenant_id, analysis_id, rule_id, openapi_pointer)`.
**Scoped FK:** `(tenant_id,analysis_id) -> analysis_jobs(tenant_id,id)`.
**Domain constraints:** finding is deterministic diff evidence.

### `patch_proposals`

| Column | PostgreSQL design type / rule |
|---|---|
| `tenant_id` | `UUID NOT NULL` |
| `id` | `UUID NOT NULL` |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` |
| `version` | `int NOT NULL DEFAULT 1 CHECK (version >= 1)` |
| `analysis_id` | `uuid NOT NULL` |
| `base_sha` | `text NOT NULL` |
| `patch_sha256` | `char(64) NOT NULL` |
| `sandbox_status` | `text NOT NULL` |
| `approval_status` | `text NOT NULL` |
| `artifact_key` | `text NOT NULL` |

**Keys/indexes:** `PRIMARY KEY (tenant_id,id)`; `UNIQUE (tenant_id, analysis_id, patch_sha256)`.
**Scoped FK:** `(tenant_id,analysis_id) -> analysis_jobs(tenant_id,id)`.
**Domain constraints:** sandbox success before PR.

### `approvals`

| Column | PostgreSQL design type / rule |
|---|---|
| `tenant_id` | `UUID NOT NULL` |
| `id` | `UUID NOT NULL` |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` |
| `proposal_id` | `uuid NOT NULL` |
| `actor_id` | `uuid NOT NULL` |
| `decision` | `text NOT NULL CHECK (decision IN ('approve','reject'))` |
| `proposal_version` | `int NOT NULL CHECK (proposal_version >= 1)` |
| `reviewed_patch_sha256` | `char(64) NOT NULL` |
| `reviewed_base_sha` | `text NOT NULL` |
| `expires_at` | `timestamptz NOT NULL` |
| `revoked_at` | `timestamptz` |

**Keys/indexes:** `PRIMARY KEY (tenant_id,id)`; `UNIQUE (tenant_id, proposal_id, reviewed_patch_sha256, actor_id)`.
**Scoped FK:** `(tenant_id,proposal_id) -> patch_proposals(tenant_id,id)`.
**Domain constraints:** review records both approve and reject; only `decision=approve` and matching current proposal version, base SHA, patch digest, unexpired/unrevoked approval authorize a remote PR effect; transaction must compare-and-swap proposal.version and append audit event.

### `pr_effects`

| Column | PostgreSQL design type / rule |
|---|---|
| `tenant_id` | `UUID NOT NULL` |
| `id` | `UUID NOT NULL` |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` |
| `proposal_id` | `uuid NOT NULL` |
| `approval_id` | `uuid NOT NULL` |
| `external_key` | `text NOT NULL` |
| `github_pr_node_id` | `text` |
| `status` | `text NOT NULL` |

**Keys/indexes:** `PRIMARY KEY (tenant_id,id)`; `UNIQUE (tenant_id, proposal_id)`; `UNIQUE (tenant_id, external_key)`.
**Scoped FK:** `(tenant_id,proposal_id) -> patch_proposals(tenant_id,id)`; `(tenant_id,approval_id) -> approvals(tenant_id,id)`.
**Domain constraints:** external reconciliation on unknown result.

## Transaction boundaries

- Creating a job: validate actor+tenant+resource; insert job and outbox in same PostgreSQL commit, then return HTTP 202. Broker delivery happens after transaction commit.
- External mutation: reserve unique business effect key and approval snapshot inside DB transaction; call external API outside transaction; reconcile remote effect ID after uncertain timeout.
- Final approval: optimistic `version`/If-Match plus exact content digest; reject stale updates.
- Tenant isolation test: same IDs searched under different tenant contexts must not disclose existence or associated storage objects.

## Schema proof not yet collected

Column design is not a generated migration and has not been executed against PostgreSQL. FK/index names, enum strategy, JSONB evidence fields, full SQL migration, query plans, retention and concurrency isolation must be validated during implementation.


> **DDL status:** conceptual physical design; no migration executed or database schema proved. Exact FK constraint names, indexes, query plans, row locks and RLS enforcement require G2/G4 evidence. The appended v3.2 dictionary is historic source input, not an executed implementation.


## v4.1 — Added physical model definitions and closure notes

These are **design-only table contracts**, not executed migrations. Explicit FK/index names, datatype behavior, RLS, and transaction isolation remain subject to PostgreSQL tests.

### `github_installations`

| Column | PostgreSQL design type / rule |
|---|---|
| `tenant_id` | `UUID NOT NULL` |
| `id` | `UUID NOT NULL` |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` |
| `github_installation_id` | `BIGINT NOT NULL` |
| `account_login` | `TEXT NOT NULL` |
| `permissions_digest` | `CHAR(64) NOT NULL` |
| `status` | `TEXT NOT NULL` |
| `verified_at` | `TIMESTAMPTZ` |

**Keys/indexes:** `PRIMARY KEY (tenant_id,id)`; `UNIQUE (tenant_id,github_installation_id)`.
**Scoped FK:** `(tenant_id,id)` referenced by repositories after migration.
**Domain constraints:** GitHub installation owner/org membership validated separately; webhook events cannot grant tenant privileges.

### `test_executions`

| Column | PostgreSQL design type / rule |
|---|---|
| `tenant_id` | `UUID NOT NULL` |
| `id` | `UUID NOT NULL` |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` |
| `analysis_job_id` | `UUID NOT NULL` |
| `proposal_id` | `UUID NOT NULL` |
| `runner_execution_id` | `TEXT NOT NULL` |
| `base_sha` | `TEXT NOT NULL` |
| `patch_sha256` | `CHAR(64) NOT NULL` |
| `status` | `TEXT NOT NULL` |
| `evidence_digest` | `CHAR(64)` |
| `started_at` | `TIMESTAMPTZ` |
| `finished_at` | `TIMESTAMPTZ` |

**Keys/indexes:** `PRIMARY KEY (tenant_id,id)`; `UNIQUE (tenant_id,runner_execution_id)`.
**Scoped FK:** `(tenant_id,analysis_job_id) -> analysis_jobs`; `(tenant_id,proposal_id) -> patch_proposals`.
**Domain constraints:** Patch and base SHA must equal approval inputs; tests from untrusted code run only in isolated sandbox; test failure cannot be declared pass.


### Domain-specific mapping decisions

- API resource `/v1/analyses` maps to `analysis_jobs` row. `remote_effects` is a conceptual capability implemented as `pr_effects` for GitHub PR plus the shared `effect_ledger`, not a duplicate domain table.
- Add `repositories.github_installation_id` as tenant-scoped FK to `github_installations.id` in migration design; external installation numeric ID must never be used as tenant identity.
