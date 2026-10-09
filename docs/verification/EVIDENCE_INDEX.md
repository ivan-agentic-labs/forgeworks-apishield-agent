# G1 evidence index

- **Source revision:** `345f15abdfc89f1f8ac21e85801122c741b0dee7` (the exact `main` SHA audited in [`docs/evidence/G1_RUNTIME_EVIDENCE.md`](../evidence/G1_RUNTIME_EVIDENCE.md)).
- [x] **Independent OpenAPI validation — VERIFIED:** local exit 0 and [G1 Contract Verification run 37877947986](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37877947986).
- [ ] **Generated TypeScript client compilation/interoperability — NOT_RUN.** No generated-client job or retained artifact.
- [x] **Empty disposable PostgreSQL migration — VERIFIED:** [G1 Disposable PostgreSQL DDL Proof run 37877985097](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37877985097).
- [x] **Non-owner two-tenant RLS — VERIFIED at tested scope:** [G1 Disposable PostgreSQL RLS Negative Proof run 37877987422](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37877987422). The script proves tenant-A visibility and cross-tenant INSERT denial; it is not a claim that every UPDATE/DELETE/context-reset/concurrency case passed.
- [x] **Synthetic auth/tenant negative tests — PASS_STATIC_LIMITED:** local 13-test suite passes missing-scope and wrong-tenant 403 checks.
- [x] **Synthetic API/UI E2E — VERIFIED:** local suite and [Application CI run 37877947984](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37877947984) pass.
- [x] **Synthetic worker reliability and artifact/integrity tests — VERIFIED:** local resilience/hardening coverage passes; see the runtime evidence record.
- [ ] **Transaction context reset/role bypass, real IdP session/CSRF, browser sandbox/egress, external storage/queue/provider permissions — NOT_RUN.**
- [ ] **Owner/independent reviewer signoffs, legal/domain/operations/cost approval, production backup/restore and DR — BLOCKED or NOT_RUN.** No approval is fabricated.

The four successful CI runs above all check out source SHA `345f15abdfc89f1f8ac21e85801122c741b0dee7`. These are partial evidence only; G1-D remains conditional/unsigned and G1-E remains blocked/open. The review-only FK addendum remains unapplied.
