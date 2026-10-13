# APIShield Agent — Product Specification (owner revision, 2026-10-13)

**Source:** `APIShield_Agent_Full_Detailed_v2.2.md`, `APIShield_Agent_Expanded_Parent_v3.0.md`, `APIShield_Agent_Ultra_Detailed_Extension.md` and `IR/APIShield_Agent_IR_Catalogue.md` in the owner-supplied `ForgeWorks_5_Projects_Long_Narrative_plus_IR.zip`.

**Status:** OWNER DESIGN REFERENCE; NOT a declaration of implementation, CI success, hosted acceptance, or production readiness. This document supersedes the repository's older *design handoff/review narrative*, not its actual contracts, migrations, tests, security runbooks, or dated evidence.

## Product boundary
Detect breaking changes between pinned OpenAPI revisions; map changes to high-confidence TypeScript callers; prepare an isolated patch with explicit human approval; optionally create **draft** pull requests. No automatic merge, direct production credential access, or broad arbitrary-code execution. The current synthetic MVP does not imply the complete approved-PR flow works on remote GitHub.

## P0 workflow from the owner document
1. Validate tenant identity, installed GitHub App permission and allowlisted repository.
2. Pin before/after OpenAPI content SHAs and check capability support matrix.
3. Deterministically classify changes: removed path and new required field are breaking; optional field addition is non-breaking.
4. Map exact path, operationId, or generated-client usage; uncertain callers are review-only.
5. Generate patches in an isolated runner with bounded egress, time and credentials.
6. Validate schemas/examples; TypeScript-compile and lint the affected project; scan patches for secrets.
7. Require explicit reviewer acknowledgement for newly introduced dependencies.
8. Bind approval to both OpenAPI digests and the exact patch digest; stale source invalidates approval.
9. Create a **draft** GitHub PR only when target, permission and approval remain valid; audit provider result and reconcile uncertain writes.
10. Support reasoned, expiring deferral of non-critical changes; critical breaking changes cannot be waived.

**Proposed P0 design limits:** analysis 15 minutes; 20 jobs per workspace/day, configurable to 100. These are OWNER DESIGN VALUES; verify implementation before advertising them.

## Implementation register: 11 distinct topic families
IR-AP-001 repository allowlist; IR-AP-002 contract pinning; IR-AP-003 breaking classification; IR-AP-004 caller mapping; IR-AP-005 isolated patch; IR-AP-006 secret scanning; IR-AP-007 contract testing; IR-AP-008 approval; IR-AP-009 draft PR; IR-AP-010 rate limit; IR-AP-011 audit.

The uploaded IR catalogue repeats each topic 40 times (440 IDs total); repeated entries are not separate evidence of engineering completion. Each implemented topic requires linked code path, positive and negative tests, fixture/digest, environment, commit SHA and reviewer.

## Boundary to the unified ForgeWorks application
APIShield remains an independently versioned backend product in its existing repository. The future unified ForgeWorks web application provides one login, navigation, workspace model and billing/usage surface; it calls each product over explicit, versioned, least-privilege APIs. Neither merging the backend repositories nor promoting staging to production is authorized by this document.

## Acceptance gate
No production claim until identity/tenant isolation, GitHub App granted scopes, isolated patch runner, stale approval rejection, provider effect reconciliation, audit/export, secrets containment, tested rollback/recovery and customer/reviewer acceptance are evidenced against a precise source SHA and deployment identity. Historical evidence remains under `docs/evidence/`.
