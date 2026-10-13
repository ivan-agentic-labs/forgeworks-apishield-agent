# ForgeWorks comprehensive re-verification — 2026-10-11

**Decision: production NO-GO.** This audit rechecked the five repositories, Railway staging inventory/source changes/configuration, Supabase catalog/advisors, real HTTPS responses, and actual Chromium browser behavior. It is not a complete line-by-line code/security certification, real customer acceptance, load test, or live disaster-recovery exercise. No deployment or authorization grant was performed.

## Product results

| Product | Exact-main CI workflows | Fresh HTTP checks | Deployed browser | Live source SHA | Staged source SHA |
| --- | --- | --- | --- | --- | --- |
| apishield-agent | 5/5 | 5/5 | FAIL: manual token input visible | 7508a6f26fbf | 0def1b62391f |
| accessfix-ai | 5/5 | 5/5 | PASS | c396da079a70 | 087aa38071c7 |
| specforge-ai | 4/4 | 5/5 | FAIL: manual token input visible | 41d2b8abbefe | f521c2c3f3b6 |
| agenttest-lab | 4/4 | 5/5 | FAIL: manual token input visible | 2e6ba172855d | 11fde128de2c |
| datareconcile-ai | 5/5 | 5/5 | FAIL: manual token input visible | 5c679ac742a2 | eccbf71aed0f |

GitHub: 23/23 workflows at the inspected main commits are completed/success. These are existing exact-commit CI results read back from GitHub, not 23 newly rerun workflows. APIShield main inspected: 9424bf48720e5128e708439738c0b8a1e0859be3; its release candidate is 0def1b62391f95624cf8756b7a202b314e68aee7. Other main commits equal their staged release pins. The full receipt stores exact SHAs and run URLs.

Fresh HTTP: 25/25 checks passed on the real five origins at approximately 08:19 WIB: healthz 200 with expected service/status body, readyz 200 with ready body, UI 200 (following expected /ui/ redirects), anonymous job 401, malformed bearer 401. HTTP 200 does not prove rendered UI correctness; 401 does not prove valid-user tenant workflows.

Deployed Chromium: [workflow 38097144473](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/38097144473) reran failed jobs; all four reproduced the manual development-token visibility failure at 08:19–08:20 WIB. AccessFix's successful job was then rerun separately and passed with an explicit deployed receipt. Final job lists carry forward other attempt results; timestamps in captured logs identify the fresh checks. No candidate stylesheet was injected into this deployed test. Earlier five-product CSS previews passed, but the fix remains unreleased.

## Railway

All five old deployments are SUCCESS, one replica each in iad. The pending patch d7e9d350-5dae-4464-9869-e4103521ce0b remains STAGED, 17 source-field changes, destructive=false. No new deployment was attempted in this audit. Previously accept-deploy returned “Cancelled — the user did not approve this action. No changes were made.” The connector gives no deeper cause; owner authorization is present in conversation. This is not evidence of a build/test failure or an identified hidden approval rule.

All services have /readyz healthchecks and Railway staging domains; no custom domains were observed. Capacity is configured at one replica / one CPU / 500,000,000 memory bytes per service. Tracing is disabled. These are configuration observations; load resilience, high availability, customer domain readiness and observability acceptance remain unproven.

Bounded HTTP log samples contained only 200/307/401 and no 5xx within the returned rows (not an all-time error claim). One-hour resource samples show low observed usage, which is not a load/performance benchmark. Full summaries and sample counts are in the JSON receipt. Variable names were inspected; secret values were not fetched. Presence of a variable name does not prove its configured value or a functioning external integration.

## Supabase

- 62/62 product tables have RLS + FORCE RLS.
- All 19 recently added indexes are indisvalid=true and indisready=true.
- Advisor findings: unindexed foreign keys 0; overlapping permissive policies 0; unused-index informational findings 25.
- All 11 product/login/webhook roles lack superuser, BYPASSRLS, create-role, create-database and replication privileges. Each product login inherits only its own product rw role; the platform postgres administrator memberships are expected and are recorded separately.
- anon/authenticated have no direct SELECT/INSERT/UPDATE/DELETE privileges on product tables and no usage on the inspected private definer-function schemas.
- APIShield repositories_tenant targets only fw_apishield_agent_rw; webhook policy restricts updates to REVOKED. This is catalog/config readback, not a new live mutation attempt by the webhook role.
- Five session_active SECURITY DEFINER functions have search_path=pg_catalog, explicitly qualified auth tables, matching auth.uid()/subject/session checks and only their corresponding rw role plus postgres execution grants. anon/authenticated cannot execute them. This reduces the observed public-execution/search-path risk; it does not prove the full session lifecycle.
- Ten membership rows remain REVOKED, zero ACTIVE. No approved active identity was available for positive authenticated business acceptance.
- Security advisor still flags [leaked-password protection disabled](https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection). Seven RLS-without-policy findings are informational deny-by-default tables; adding permissive policies merely to clear them would change the access model.

## Open acceptance gates

1. Apply the reviewed staged release after the approval block is resolved; verify actual deployed SHAs and rerun all browser/API checks.
2. Provision an explicitly reviewed test identity and product grants; verify login, online session revocation, membership denial and real cross-tenant business workflows. Do not simply re-enable historical revoked memberships.
3. Enable and verify leaked-password protection through an authorized Auth configuration surface; the installed connector has no matching configuration operation.
4. Verify actual product GitHub App/provider/source/storage execution and quality/cost evidence. Current scaffolding, signed-webhook or synthetic sandbox results do not establish real external effects.
5. Run live load, recovery and operational/domain/privacy acceptance with defined thresholds. Disposable restore tests are not production recovery proof.

Full evidence: [COMPREHENSIVE_REVERIFICATION_2026-10-11.json](COMPREHENSIVE_REVERIFICATION_2026-10-11.json).
