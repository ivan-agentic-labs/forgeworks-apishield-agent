# APIShield Agent — Verifiable test and evaluation plan

| Test ID | Scenario | Fixture / setup | Expected acceptance result | Execution |
|---|---|---|---|---|
| API-T01 | Changed required response field classified as breaking | Golden OpenAPI before/after | inline response guarantee removal is BREAKING; addition is REVIEW/LIMITED | **PASS_LOCAL** — `tests/unit/test_response_compatibility_corpus.py::test_golden_fixture_required_response_field_addition_is_review_only`, `test_inline_response_presence_corpus`, and compatibility matrix suite (152 passed, `-W error`). Covers deterministic OpenAPI classification only; external adjudication remains open. |
| API-T02 | App installation removed after approval | Revoked GitHub installation | No PR and no token usage | **PARTIAL_LOCAL** — `test_approval_replay_is_proposal_bound_and_revocation_checked`, `test_revoked_approved_proposal_cannot_be_authorized_for_write`, `test_installation_transition`, `test_unique_delayed_deliveries_preserve_revocation`, and `test_read_only_adapter_signs_scoped_token_and_verifies_exact_blobs`. Covers synthetic revocation fencing and write-disabled/read-only boundaries; no live GitHub installation removal, token invalidation, or remote PR. |
| API-T03 | Branch updated after sandbox validation | Different base SHA | Approval invalidated, 409 | **PASS_LOCAL** — `tests/integration/test_hardening.py::test_proposal_approval_idempotency_stale_version_and_artifact_digest` and `tests/security/test_approval_fencing.py::test_approval_rejects_changed_base_sha_without_recording_approval`. Synthetic changed-base approval returns `409 STALE_ARTIFACT` and records no approval; no remote branch/provider check. |
| API-T04 | Duplicate PR request | same idempotency key | One remote PR at most, audit duplicate | **PARTIAL_LOCAL** — `test_proposal_approval_idempotency_stale_version_and_artifact_digest` repeats the same disabled PR request and verifies `GITHUB_WRITE_DISABLED` plus zero local PR rows. Remote PR deduplication and audit delivery are not exercised because GitHub writes are intentionally disabled. |
| API-T05 | Malicious package scripts inside repo | sandbox fixture | No secret/metadata/private network access | **PARTIAL_LOCAL** — `tests/security/test_sandbox_policy.py::test_synthetic_canary_command_has_no_host_mount_or_secrets`, `test_mutable_image_reference_is_rejected`, and bounded pull/opt-in tests. Covers command construction and refusal/retry policy only; no Docker canary or malicious package execution was run locally. |
| API-T06 | Tenant A reads Tenant B analysis | cross-tenant IDs | 404/403 with no data disclosure | **PASS_LOCAL** — `tests/integration/test_analysis_flow.py::test_auth_scope_and_cross_tenant_fail_closed`, `tests/integration/test_patch_read_authorization.py::test_patch_never_visible_to_other_tenant_or_without_scope`, and `test_existing_patch_is_denied_after_permission_loss`. Synthetic API negative paths returned denial without data; this is not a new PostgreSQL/RLS or production acceptance run. |

## Coverage and execution gates
- Unit: every pure domain invariant, deterministic cross-validation, state guard, authorization policy and financial arithmetic where relevant.
- Contract: OpenAPI semantic validation, JSON Schema, request/response/error examples, client generation, event backwards compatibility.
- Integration: PostgreSQL tenant/RLS/FKs/transactions, storage capability, OIDC+BFF flow, inbox/outbox/queue, provider-scoped permissions.
- E2E: five canonical success/failure paths including human approval and result retrieval; use separate tenants and consented/synthetic data.
- Agent evaluation: frozen labeled corpus with human adjudication, baseline comparison, model/version pinning, typed outputs, prompt injection and tool abuse fixtures.
- Security: SAST/SCA/secret/DAST and cross-tenant negative tests, SSRF sandbox escape, revocation, external effect uncertainty.
- Reliability: 2x planned load (tentative), forced worker crash, network partitions, point-in-time DB restore, region failure simulation.

## Metrics to establish on actual runs
- verified breaking-change recall on supported corpus
- false positive rate of caller impact
- patch build/contract-test pass rate
- median analysis time and cost per run
- remote writes with verified approval = 100%

**No arbitrary success numbers:** Define threshold from buyer risk tolerance and pilot corpus before G1. Store observed accuracy and sample size, confidence/coverage when meaningful, source hash, run logs, costs, p95, failure distribution. A test case being designed is not a passed test.

## Evidence format
`{test_id, requirement_id, revision_sha, input_fixture_sha, dataset_version, environment, exact_command, expected, observed, pass_fail, reviewer, trace_id, issues}`.
