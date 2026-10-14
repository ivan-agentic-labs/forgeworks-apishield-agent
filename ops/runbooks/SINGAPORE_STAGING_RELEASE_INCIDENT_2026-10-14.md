# ForgeWorks staging: region migration and release identity (2026-10-14)

**Scope:** the five ForgeWorks backends only. No SealAngel infrastructure,
production traffic, customer records or schema changes. This is a staging
incident and evidence record, **not** a production acceptance.

## Initial conditions

- Four stateless Railway staging services were deployed in `iad`, with
  their database located in Supabase `ap-northeast-2` (Seoul). APIShield was
  already in Railway `asia-southeast1-eqsg3a` (Singapore).
- Railway HTTP request logs attributed most observed high-percentile
  staging latency to `GET /readyz`, not the product business endpoints.
  Typical older /readyz durations on the four IAD services were roughly
  1,800–2,200 ms, based on sampled staging probe requests.
- All five services had exact pinned source revisions and an application-level
  fallback `FORGEWORKS_RELEASE_SHA`; when Railway injects its own
  `RAILWAY_GIT_COMMIT_SHA`, the two identities must match.

## Incident and verified recovery

1. A non-destructive four-service region configuration patch was applied to
   Singapore. Railway rebuilt newer documentation-only GitHub `main` HEAD
   revisions instead of the earlier pinned executable release revisions.
   The fallback release SHA remained old.
2. All four services could show Railway deployment SUCCESS and /readyz HTTP
   200 while `/versionz` returned HTTP **503**. This is a critical example
   of why health checks alone do not prove release identity.
3. The exact fleet and individual GitHub Actions release proofs correctly
   detected the mismatch and failed. No production promotion occurred.
4. Prior successful builds were retained for recovery. Reusing old builds
   restored release identity but selected their older `iad` placement.
5. The permanent fix staged **both** an explicit GitHub source commit pin
   (latest reviewed source SHA) and the exactly matching
   `FORGEWORKS_RELEASE_SHA` on each affected Singapore service, then
   committed the patch. Each rebuild reached terminal SUCCESS in Singapore.
6. The credential-free five-service inventory observed correctly shaped
   /versionz payloads at all five exact releases, with readiness and anonymous
   metrics denial. Candidate drift was then reconciled to observed SHA values.
7. [The exact hosted five-service release proof](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/38521516802)
   **passed** with all five revisions and runtime fingerprints.
   Individual release proofs on the four updated record commits also passed.

## Final observed staging revisions

| Product | Observed source SHA | Singapore deployment ID |
| --- | --- | --- |
| APIShield Agent | `1839d276a0bccc3382e9e64ddc83e02675d58679` | `a61c827e-7cd2-434c-8ec8-556fd30c868d` |
| AccessFix AI | `50affc6e61d8517c6e888901bae49b51299a294b` | `48d374ff-6bd1-480e-9354-07b0c3b00304` |
| SpecForge AI | `314a239aee667808c612ebb79294ebe760ac7c77` | `54acea65-bcc7-47e8-a07c-4b259c65565f` |
| AgentTest Lab | `11957fe1f728cdcc932fdf5e7455d7df1e16536d` | `03bac45b-9502-424e-a1c1-5fab7a307621` |
| DataReconcile AI | `fd3294551ebc35e891f50fc191a17e9d22e13880` | `86c53728-8f73-4a3e-9282-10856061f829` |

The runtime SHA is deliberately different from subsequent documentation-only
commits in each repository's GitHub `main`. A later `main` HEAD is not
evidence that new application bytes were deployed.

## Post-migration HTTP readiness observation

Railway HTTP logs on 2026-10-14, after 06:18 UTC, yielded the following small
staging samples of successful `GET /readyz` requests. The values below are
nearest-rank percentiles over **only these requests**, not customer business
transaction latency or an application load SLO.

| Service | Samples | p50 (ms) | p95 (ms) |
| --- | ---: | ---: | ---: |
| APIShield Agent | 13 | 730 | 1113 |
| AccessFix AI | 14 | 904 | 1250 |
| SpecForge AI | 14 | 837 | 1111 |
| AgentTest Lab | 14 | 893 | 1031 |
| DataReconcile AI | 14 | 901 | 1106 |

The pre/post difference is consistent with shorter distance to Seoul, but the
sample windows and workload mixes are not identical. A controlled benchmark,
real authenticated workload, and production SLO measurements remain OPEN.

## Mandatory future staging deployment procedure

1. Check five latest GitHub commits and exact reviewed CI results, and separately
   note the five **runtime** commits currently deployed.
2. Compare proposed Railway source commit pins and `FORGEWORKS_RELEASE_SHA`
   for equality **per service**. Do not stage region changes independently
   without re-reviewing source pins and release variables; Railway can choose
   the latest branch HEAD when rebuilding after a config change.
3. Review the complete staged environment patch, including deployment region,
   variables and any implicit source change. Preserve previous successful
   builds, rollback identities, regions and service credentials.
4. Commit only a reviewed non-destructive patch. Poll each new deployment
   until terminal SUCCESS. Query `GET /readyz` **and `GET /versionz`**;
   /readyz alone can pass when source identity is invalid.
5. Run `scripts/observe_fleet_runtime.py`, inspect the actual observed SHA
   and fingerprint on every product, then update the fleet candidate **from
   observations**, never from GitHub HEAD guesses.
6. Require `scripts/verify_fleet_release.py` PASS at all five exact
   identities; update five separate `ops/releases/staging.json` receipts,
   run each exact deployed release proof, and record rollback/build identities.
7. If any product is 503 or mismatched, stop promotion. Restore an appropriate
   previously proven build **and** correct release SHA and region in tandem,
   or stage a verified source revision plus matching release SHA and redeploy.
   Never treat a Railway SUCCESS state as sufficient evidence on its own.
8. Recheck RLS/tenant isolation and storage access for any subsequent schema
   or service-level change. Source rollback does not reverse a database change.

## Release limitations

- Not an authenticated two-tenant product acceptance, write-isolation check,
  recovery drill, malware scan, production secret rotation or independent audit.
- `/metricsz` was checked anonymously for denial, not with a private operator
  credential in this workflow.
- No customer data or production SLO/availability promise is authorized by
  these results.
