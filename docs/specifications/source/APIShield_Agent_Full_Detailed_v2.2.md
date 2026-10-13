# APIShield Agent — Complete Detailed Project Specification

**Version:** 2.2.0-detailed-full  
**Date:** 2026-10-13  
**Status:** FINAL  

Includes security controls.

> APIShield Agent detects breaking changes between pinned OpenAPI contract versions, maps them to high-confidence TypeScript callers, proposes patches in an isolated environment, and creates draft pull requests only after digest-bound approval.

---

## 1. Executive Definition

The system helps backend teams understand the downstream impact of API contract changes. Classification of breaking changes is deterministic. Patches are prepared without production credentials. Secrets are scanned. Approval is required. Only draft PRs are created.

---

## 2. Detailed Workflow

1. User selects an allowlisted repository. GitHub App permissions are verified (contents read, pull requests write for draft, metadata read).
2. Before and after OpenAPI SHAs are pinned. Both must fall inside the supported capability matrix.
3. Deterministic diff classifies changes. Examples: required field added = breaking; optional field added = non-breaking; path removed = breaking.
4. High-confidence caller mapping (exact path/operationId or generated client usage) is performed. Low-confidence matches are listed for manual review only.
5. Patch is generated in an isolated runner (no production secrets, restricted egress, time limits).
6. Tests run: schema validation, example checks, TypeScript compile of affected files, lint.
7. Secret scan on the diff. Detected secrets reject the proposal.
8. New dependencies require explicit reviewer acknowledgment.
9. Approval binds to patch digest + both contract digests.
10. Draft PR is created only if approval is still valid. Analysis timeout is 15 minutes. Stale SHAs invalidate the job.
11. Rate limit: 20 jobs per workspace per day (configurable up to 100).
12. All approvals and PR creations write append-only audit events. Tokens are short-lived.

---

## 3. Waiver and Deferral

Critical breaking changes cannot be waived. Non-critical changes may be waived or deferred with reason and optional expiry. Deferred items reappear after expiry.

---

## 4. Closing

All rules, including security controls, are final for P0. APIShield Agent will not create a pull request without valid approval and will not ignore detected secrets.

*End of APIShield Agent Complete Detailed Specification*
