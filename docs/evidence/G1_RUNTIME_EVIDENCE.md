# APIShield Agent — G1 runtime evidence

**Evidence posture:** `G1-D CONDITIONAL / NOT SIGNED`; `G1-E PARTIAL EVIDENCE / BLOCKED`, **not PASS**.

This record is an evidence ledger, not reviewer approval or a production-readiness decision. It records only the evidence observed for the current `main` revision at audit time.

## Provenance

| Field | Value |
|---|---|
| Repository | `ivan-agentic-labs/forgeworks-apishield-agent` |
| Audited source revision (current `main` before this evidence update) | `345f15abdfc89f1f8ac21e85801122c741b0dee7` |
| Local environment | Ubuntu sandbox, Python 3.12.3, pytest 8.4.2, Node.js 22, Chromium available to the E2E test |
| Evidence date | 2026-10-09 |
| Reviewer approval | **None recorded** |
| Data boundary | Synthetic fixtures and disposable/local databases only; no customer data or production credentials |

The source SHA above is the exact revision tested. The commit containing this evidence record is returned separately by the delivery result; it must not be confused with the tested product revision.

## Exact local execution record

All commands below were run from the repository root. Exit code `0` is the observed local success outcome.

| Exact command | Observed outcome | Exit |
|---|---|---:|
| `python -m pytest -W error tests/unit tests/integration tests/resilience tests/e2e` | `13 passed in 4.52s` (unit, integration, resilience, and API/UI E2E suites) | 0 |
| `python scripts/verify_bootstrap.py` | 97 files scanned; `errors: []` | 0 |
| `python scripts/verify_contracts.py` | 11 operations; Draft 2020-12 event schema; `errors: []` | 0 |
| `python scripts/validate_openapi_independent.py` | `Independent OpenAPI validator: PASS for openapi.yaml` | 0 |
| `bash -n scripts/probe_disposable_postgres.sh scripts/test_disposable_postgres_rls.sh` | Shell syntax valid | 0 |
| `node --check apps/web/app.js` | JavaScript syntax valid | 0 |
| `node --check apps/web/config.js` | JavaScript syntax valid | 0 |
| `git diff --check` | No whitespace errors | 0 |
| `G1_DISPOSABLE_DB=yes PGHOST=127.0.0.1 PGPORT=5432 PGUSER=postgres PGPASSWORD=g1_only_disposable_password PGDATABASE=forgeworks_g1 bash scripts/probe_disposable_postgres.sh` | Local PostgreSQL authentication failed; no local disposable proof was claimed | 2 |
| `G1_DISPOSABLE_DB=yes PGHOST=127.0.0.1 PGPORT=5432 PGUSER=postgres PGPASSWORD=g1_only_disposable_password PGDATABASE=forgeworks_g1 bash scripts/test_disposable_postgres_rls.sh` | Local PostgreSQL authentication failed; no local RLS proof was claimed | 2 |

The two local PostgreSQL exit-2 outcomes are recorded as environment-unavailable local runs. The CI results below are the retained disposable-instance evidence.

## GitHub Actions evidence for the audited SHA

All four runs below report `completed / success` and check out the same exact SHA `345f15abdfc89f1f8ac21e85801122c741b0dee7`.

| Evidence | Workflow command/scope | Run URL | Run SHA |
|---|---|---|---|
| Application | `python -m pytest -W error tests/unit tests/integration tests/resilience tests/e2e`; compileall; static checks; shell and Node checks | [APIShield MVP Application CI run 37877947984](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37877947984) | `345f15abdfc89f1f8ac21e85801122c741b0dee7` |
| Contract/event | `python scripts/verify_bootstrap.py && python scripts/verify_contracts.py && python scripts/validate_openapi_independent.py` | [G1 Contract Verification run 37877947986](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37877947986) | `345f15abdfc89f1f8ac21e85801122c741b0dee7` |
| Empty disposable migration | `bash scripts/probe_disposable_postgres.sh` on PostgreSQL 17 service | [G1 Disposable PostgreSQL DDL Proof run 37877985097](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37877985097) | `345f15abdfc89f1f8ac21e85801122c741b0dee7` |
| Non-owner tenant RLS | `bash scripts/test_disposable_postgres_rls.sh` on PostgreSQL 17 service | [G1 Disposable PostgreSQL RLS Negative Proof run 37877987422](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37877987422) | `345f15abdfc89f1f8ac21e85801122c741b0dee7` |

The PostgreSQL workflows use an intentionally public password only inside a disposable localhost-bound CI service. This is not production credential evidence.

## Explicit G1 criterion table

`VERIFIED` means the named evidence executed successfully at the stated synthetic/disposable scope. `PASS_STATIC_LIMITED` means an offline or local check passed but does not establish an external/runtime/production property. `NOT_RUN` and `BLOCKED` are deliberate non-green outcomes.

| Criterion | Status | Evidence and exact scope | Residual limitation |
|---|---|---|---|
| Independent OpenAPI semantic validation | **VERIFIED** | `python scripts/validate_openapi_independent.py`, local exit 0, and successful [G1 Contract Verification](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37877947986) | No generated TypeScript client compilation or interoperability proof |
| Event schema shape | **PASS_STATIC_LIMITED** | `python scripts/verify_contracts.py`, local exit 0; Draft 2020-12 schema check and event contract shape | No broker delivery, compatibility history, or operational consumer proof |
| Empty disposable migration | **VERIFIED** | Successful [G1 Disposable PostgreSQL DDL Proof](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37877985097) runs `bash scripts/probe_disposable_postgres.sh` against an empty PostgreSQL 17 service | Disposable DDL smoke only; review-only FK addendum remains unapplied and production migration/rollback is unproved |
| Non-owner two-tenant RLS | **VERIFIED** | Successful [G1 Disposable PostgreSQL RLS Negative Proof](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37877987422); non-owner role, tenant-A visibility, and cross-tenant insert denial are exercised | This script does not establish every UPDATE/DELETE/context-reset/concurrency case in the broader test plan |
| Auth and tenant negative tests | **PASS_STATIC_LIMITED** | Local `test_auth_scope_and_cross_tenant_fail_closed` passes in the 13-test suite: missing scope and wrong synthetic tenant return 403 | Development HS256 issuer and SQLite adapter; real IdP/OIDC/JWKS, CSRF, provisioning, and live authorization integration are absent |
| API E2E | **VERIFIED** | `tests/e2e/test_ui_smoke.py` starts the local API, submits an analysis, polls the job, and reads results; included in local and successful Application CI run | Synthetic local service and fixtures only; no GitHub App or external provider effects |
| UI/browser E2E | **VERIFIED** | Same E2E test launches headless Chromium and loads the static UI; local suite and Application CI passed | Browser sandbox escape/egress and hostile-repository browser isolation are not tested here |
| Worker reliability | **VERIFIED** | Six `tests/resilience/test_worker_reliability.py` tests pass, covering concurrent idempotency, atomic leases, stale lease fencing, retry terminal state, duplicate-safe completion, and artifact rejection | No 2x load, crash/partition, queue, region-failure, or production telemetry run |
| Artifact/integrity tests | **VERIFIED** | `tests/integration/test_hardening.py` and resilience tests pass patch digest, approval version/idempotency, artifact digest/size rejection, and disabled GitHub write checks | No external object-store generation or retention/integrity proof |
| Real IdP/OIDC/JWKS and CSRF | **NOT_RUN** | No retained run or external identity configuration | Required before G1-E can close |
| Browser sandbox / network egress / SSRF isolation | **NOT_RUN** | No independent runner or hostile fixture evidence | Required where repository/browser execution is introduced |
| External storage, queue, and provider permissions | **NOT_RUN** | MVP uses local SQLite and synthetic stubs | No external object store, queue, GitHub App, or AI-provider evidence |
| Generated client compilation/interoperability | **NOT_RUN** | No generated-client job or artifact retained | Independent validator alone is insufficient |
| Legal, domain, operations, accessibility, and cost signoff | **BLOCKED** | No signed owner/independent reviewer record is present | Do not fabricate approval; OD-01–OD-09 remain open per governance baseline |
| Production backup/restore and DR | **NOT_RUN** | No production or restore drill executed | No production authorization |
| Production deployment/customer data/public release | **BLOCKED** | Explicitly outside this synthetic-only evidence scope | Later security and governance gates remain required |

## Decision and residual blockers

- This record **does not change** `MASTER_G1_DECISION.md` or `DESIGN_GATE_STATUS.md`: G1-D remains conditional and unsigned; G1-E remains blocked/open.
- The successful CI runs establish partial, reproducible contract, synthetic application, disposable migration, and bounded RLS evidence. They do **not** constitute full G1 approval.
- The unapproved `docs/verification/sql-candidates/30_fk_addendum_REVIEW_ONLY.sql` remains review-only and was not applied.
- No reviewer approval, legal/domain/ops/cost signoff, real IdP/OIDC evidence, sandbox/egress evidence, external storage/queue evidence, generated-client evidence, or production backup/restore evidence is claimed.
