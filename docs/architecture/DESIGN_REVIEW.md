# APIShield Agent — Product Design Review (canonical summary)
**Status:** `DESIGN REVIEW CANDIDATE`. G1 domain signoff `BLOCKED`. This note **does not claim tested functionality**.

## Purpose and scope
**ICP:** Engineering platform teams maintaining OpenAPI-driven services and GitHub codebases.

**P0 workflow:** Select installed repository/contract SHAs → classify breaking changes → map call sites → plan patch → isolated tests → approve immutable proposal → draft PR.

**Explicit exclusions:** No auto-merge, no auto-deploy, no unreviewed arbitrary shell, no guarantee every language call site is found.

**Subsystems:** GitHub App installation/webhook; OpenAPI parser/diff; source map; proposed patches; isolated CI results; approval; PR state.

## API inventory (as currently specified)
| Method/path | `operationId` | Scope |
|---|---|---|
| `POST /v1/installations/{installation_id}/repositories/{repository_id}/analyses` | `post_v1_installations_installation_id_repositories_repository_id_analyses` | `repo:analyze` |
| `GET /v1/analyses/{analysis_id}` | `get_v1_analyses_analysis_id` | `analysis:read` |
| `GET /v1/analyses/{analysis_id}/findings` | `get_v1_analyses_analysis_id_findings` | `analysis:read` |
| `POST /v1/analyses/{analysis_id}/proposals` | `post_v1_analyses_analysis_id_proposals` | `patch:create` |
| `POST /v1/proposals/{proposal_id}/approvals` | `post_v1_proposals_proposal_id_approvals` | `patch:approve` |
| `POST /v1/proposals/{proposal_id}/pull-requests` | `post_v1_proposals_proposal_id_pull_requests` | `github:write` |
| `POST /v1/artifacts/upload-intents` | `post__v1_artifacts_upload_intents` | `artifact:create` |
| `POST /v1/artifacts/{artifact_id}/commit` | `post__v1_artifacts_artifact_id_commit` | `artifact:commit` |
| `GET /v1/artifacts/{artifact_id}` | `get__v1_artifacts_artifact_id` | `artifact:read` |
| `POST /v1/artifacts/{artifact_id}/download-intents` | `post__v1_artifacts_artifact_id_download_intents` | `artifact:download` |
| `GET /v1/jobs/{job_id}` | `get__v1_jobs_job_id` | `job:read` |

`openapi.yaml` is the source. These routes are not running. Remaining contract hardening: independent validator and SDK; verify existing cursor pagination semantics in runtime; security tests and example/runtime parity.

## Database inventory and handling
From candidate SQL (18 tables): `tenants`, `users`, `artifact_references`, `audit_events`, `github_installations`, `idempotency_records`, `inbox_receipts`, `jobs`, `memberships`, `outbox_events`, `test_executions`, `repositories`, `analysis_jobs`, `contract_snapshots`, `analysis_findings`, `patch_proposals`, `approvals`, `pr_effects`.

- Keep physical table names from `docs/verification/sql-candidates/10_schema_candidate.sql` as **candidate canonical**; historical aliases may not be implemented simultaneously.
- Apply `tenant_id` composite relations, invariant constraints and optimistic version where review/approval is relevant.
- Validate DDL in disposable PostgreSQL with owned migration role, nonowner runtime login role, multiple tenants; DDL presently unexecuted.

## Product-specific invariants and required negative proofs
| ID | Invariant | Negative case required | Evidence |
|---|---|---|---|
| `AS-INV-01` | Frozen contract/head SHA cannot silently change during analysis | Change SHA before approval: reject stale commit/PR | Runtime test + reviewer signoff |
| `AS-INV-02` | Proposal approval bound to snapshot and optimistic version | Concurrent different approvals: 1 winner, 409 loser | Runtime test + reviewer signoff |
| `AS-INV-03` | PR creation idempotent across provider timeout | Simulated 503 after remote PR exists: reconcile by correlation ID | Runtime test + reviewer signoff |
| `AS-INV-04` | Runner receives no repository write token or production secret | Adversarial repo script cannot read credential or access private networks | Runtime test + reviewer signoff |

## Modules/files planned for ownership (domain and adapters)
- `apps/api/src/apishield_agent/domain/entities.py`
- `apps/api/src/apishield_agent/infrastructure/persistence/models.py`
- `apps/api/src/apishield_agent/infrastructure/persistence/repositories.py`
- `apps/api/src/apishield_agent/infrastructure/llm/provider_adapter.py`
- `apps/api/src/apishield_agent/domain/contract_diff_policy.py`
- `apps/api/src/apishield_agent/domain/impact_policy.py`
- `apps/api/src/apishield_agent/domain/patch_approval.py`
- `apps/api/src/apishield_agent/domain/repository_scope.py`
- `apps/api/src/apishield_agent/application/commands/start_analysis.py`
- `apps/api/src/apishield_agent/application/commands/plan_patch.py`
- `apps/api/src/apishield_agent/application/commands/approve_proposal.py`
- `apps/api/src/apishield_agent/application/commands/publish_draft_pr.py`
- `apps/api/src/apishield_agent/infrastructure/github/app_auth.py`
- `apps/api/src/apishield_agent/infrastructure/github/repository_reader.py`
- `apps/api/src/apishield_agent/infrastructure/github/pull_request_writer.py`
- `apps/api/src/apishield_agent/infrastructure/openapi/diff_adapter.py`
- `apps/api/src/apishield_agent/infrastructure/source/typescript_indexer.py`
- `apps/api/src/apishield_agent/infrastructure/sandbox/remote_runner.py`
- `apps/api/src/apishield_agent/application/commands/commit_artifact.py`
- `apps/api/src/apishield_agent/infrastructure/storage/object_store.py`
- `apps/api/src/apishield_agent/infrastructure/security/tenant_context.py`
- `apps/api/src/apishield_agent/infrastructure/persistence/outbox.py`

## Failure semantics
Unsupported OpenAPI change returns UNSUPPORTED; cannot assert full code coverage; PR creation fails closed if approval stale. If downstream AI/provider fails, persist recoverable explicit job state and do not fabricate a successful output. Remote writes require `approval_snapshot` and idempotent effect ledger.

## Evidence and customer acceptance
**Required positive proof:** On labeled breaking-change fixtures, produces correct impact classifications, reviewable candidate patch, reproducible tests; no unsafe writes.

**Main threats:** GitHub App scopes, webhook signature/replay, branch protected policy, runner escape, unrecognized dynamic API usage.

**Data/IP/approval:** Respect repo licenses and developer IP; avoid uploading private code to external model without authorization.

## P0 gates and signoff
- Founder/product owner: validates use-case acceptance from qualified user/buyer; **OPEN**.
- API reviewer: external OAS validation, SDK build, authorization negative tests; **NOT RUN**.
- DB/security reviewer: two-tenant SQL execution, constraints, RLS, IAM and sandbox where required; **NOT RUN**.
- Domain specialist: accessibility, finance, graders, provenance, GitHub contract per product; **OPEN**.
- Ops owner: cost/vendor, data policy, restore and incident evidence; **OPEN**.

**Outcome:** Documentation improved and canonical routes/tables inventoried; no independent product-domain approval or G1 PASS granted.
