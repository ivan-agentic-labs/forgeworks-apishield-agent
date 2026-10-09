# APIShield Agent — Verifiable test and evaluation plan

| Test ID | Scenario | Fixture / setup | Expected acceptance result | Execution |
|---|---|---|---|---|
| API-T01 | Changed required response field classified as breaking | Golden OpenAPI before/after | diff finding severity matches reviewed corpus | NOT RUN |
| API-T02 | App installation removed after approval | Revoked GitHub installation | No PR and no token usage | NOT RUN |
| API-T03 | Branch updated after sandbox validation | Different base SHA | Approval invalidated, 409 | NOT RUN |
| API-T04 | Duplicate PR request | same idempotency key | One remote PR at most, audit duplicate | NOT RUN |
| API-T05 | Malicious package scripts inside repo | sandbox fixture | No secret/metadata/private network access | NOT RUN |
| API-T06 | Tenant A reads Tenant B analysis | cross-tenant IDs | 404/403 with no data disclosure | NOT RUN |

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
