# ForgeWorks live staging checkpoint — 2026-10-11 UTC

Production decision: **NO-GO**. The database changes below are live; the Railway application release remains staged and was not deployed. This checkpoint covers APIShield Agent, AccessFix AI, SpecForge AI, AgentTest Lab and DataReconcile AI under ivan-agentic-labs.

## Completed engineering and database verification

Five database hardening PRs were merged after 17 successful PR workflows. The corresponding main workflows also passed. Added 19 tenant-prefixed indexes with lock/statement timeouts and replay-safe migrations. APIShield's repository tenant policy now targets only fw_apishield_agent_rw, closing the webhook regrant path. The PostgreSQL regression reproduces the old single-row bypass before applying the role fence, then verifies READ/WRITE regrants are rejected while revoke and application tenant isolation continue working.

Live Supabase project: fljekuwplgkrpdoajyhn.
Applied migrations:
- 20261010235248 — apishield_repository_policy_role_fence
- 20261010235302 — forgeworks_remaining_tenant_foreign_key_indexes

Live readback verified all 19 indexes valid/ready, the role restriction, and RLS plus FORCE RLS on all 62 product tables. Performance advisor unindexed-FK findings fell from 19 to 0; overlapping permissive-policy findings fell from 2 to 0. Unused-index informational findings remain expected immediately after creation. Leaked-password protection remains disabled (security warning). No customer rows, memberships or role grants were changed.

## Tests and their limits

Local Python suites, excluding browser E2E: **1,157 passed, 17 skipped**.
| Product | Passed | Skipped |
| --- | ---: | ---: |
| AccessFix AI | 215 | 8 |
| AgentTest Lab | 265 | 1 |
| APIShield Agent | 259 | 6 |
| DataReconcile AI | 214 | 1 |
| SpecForge AI | 204 | 1 |

Existing Node tests: **31 passed**. Contract sanity, independent OpenAPI validation, static bootstrap and whitespace checks passed for all five repositories. Local PostgreSQL and local browser installation were unavailable; actual PostgreSQL 17, browser and disposable backup/restore proofs ran on GitHub-hosted CI. Disposable restore proves the synthetic harness, not live disaster recovery.

Post-migration real HTTPS requests passed for all five staging origins: healthz 200, readyz 200, anonymous job access 401. Earlier malformed-bearer checks also returned 401. See LIVE_HTTP_2026-10-11.json for timestamps and observed statuses. Bounded sampled logs showed 200/401; this is not an all-time error audit or load test.

## Candidate application release

A real deployed-browser test discovered that label display styles overrode the HTML hidden attribute on four staging consoles. All five repositories now include an explicit [hidden] display rule. The 23 workflows for the exact release commits below passed.

| Product | Candidate commit |
| --- | --- |
| forgeworks-accessfix-ai | 087aa38071c71cde57532d1ae001c3a4ba120d36 |
| forgeworks-agenttest-lab | 11fde128de2cb4d103434fa088beb91650de5cdc |
| forgeworks-apishield-agent | ac2c0173f86f274e097b210c34f65828daad3384 |
| forgeworks-datareconcile-ai | eccbf71aed0ff33296bb9d23b7ff14d9c66e5b92 |
| forgeworks-specforge-ai | f521c2c3f3b6573b4d390d9f309b077d1d6d6732 |

Railway project 1b35f35d-ad5b-4b93-ad20-ed68251b4589; staging environment 0395e7ac-10f8-4004-8bb7-ddee901343c7. Patch d7e9d350-5dae-4464-9869-e4103521ce0b remains STAGED (five source pins, 17 source-field changes; no destructive changes).
The deployment request was rejected: “Cancelled — the user did not approve this action. No changes were made.” It was not retried by another path.

PR #23 adds a credential-free actual-browser probe and a separately labeled candidate CSS preview. Preview supplies only immutable candidate stylesheet bytes within an isolated browser; deployed HTML, JavaScript and anonymous API responses remain live. Preview does not deploy or prove the candidate application runtime. Default deployed-browser proof continues to detect old live UI behavior until deployment occurs.

## Remaining acceptance gates

All ten existing OWNER membership rows are REVOKED; no ACTIVE membership is available for an approved authenticated test identity. Real login, tenant workflows, GitHub App/provider execution and customer acceptance therefore remain unverified. Live load, production recovery, domain/operational readiness and other existing release gates remain open. Staging service deployment SUCCESS and anonymous health checks do not establish production readiness.

Next action requiring renewed approval after the rejection: apply the concrete staged five-service Railway release above. Then verify actual deployed source SHAs, rerun the credential-free deployed-browser matrix and API checks, and assess authenticated acceptance using an explicitly reviewed identity.

## Final browser receipt

All five candidate stylesheet previews passed in real GitHub-hosted Chromium: [run 38097144466](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/38097144466), probe source 0d4d9822d57b1d14545d0ebf35b842ce1804fb92. Captured receipt confirms the candidate stylesheet actually intercepted the requested /styles.css or /ui/styles.css resource. All five previews observed UI HTTP 200, staging auth configuration enabled, fenced/read-only API origin, blank/hidden manual-token controls, zero uncaught JavaScript errors, health/readiness 200 and anonymous job 401.

The default deployed-browser matrix [run 38097144473](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/38097144473) still fails the token visibility assertion for APIShield, AgentTest, SpecForge and DataReconcile; AccessFix passes. This explicitly records the unreleased live defect. PR #23 remains open pending actual release and successful deployed verification. Its contract, application, PostgreSQL role-fence regression and disposable sandbox workflows are green.

Machine-readable evidence: CANDIDATE_CSS_BROWSER_2026-10-11.json, CANDIDATE_CI_2026-10-11.json, RAILWAY_STAGED_RELEASE_2026-10-11.json and LIVE_HTTP_2026-10-11.json in this directory.
