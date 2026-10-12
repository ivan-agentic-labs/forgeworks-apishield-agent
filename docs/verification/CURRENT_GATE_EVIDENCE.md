# G1/G2 evidence and acceptance register

Latest live checkpoint: [2026-10-11 database, CI and browser evidence](../evidence/STAGING_DATABASE_AND_BROWSER_CHECKPOINT_2026-10-11.md). Historical receipts below retain their original scope and timestamps.

The owner authorizes engineering directly on main. Owner design approval is permission to proceed; it is not an independent domain/security/legal signoff or a G1-E test result. Five repositories remain independent and public. No production deployment or customer data is included.

| Area | Status | Evidence and limit |
|---|---|---|
| G2 repository bootstrap | VERIFIED | Independent repositories, blueprint documentation, contracts, engineering config, SDK and Actions; committed contents read back from GitHub. |
| Contract semantics/client | VERIFIED, scoped | Independent OpenAPI validator, event-schema checks, generated TypeScript compilation and selected runtime response validation. This does not prove all application response paths. |
| Implemented PostgreSQL MVP runtime | VERIFIED, disposable | Migrations 001/002, non-owner runtime role, forced tenant RLS, negative access and product-specific concurrent commands. Design-candidate schema/FK addendum is not applied or accepted by these tests. |
| Logical restore | VERIFIED, disposable | Fresh database dump/restore, table digests, columns, constraints, RLS flags and restored non-owner membership/context behavior. Not PITR, regional failover or production RTO/RPO. |
| JWT/OIDC | PARTIAL | Fixed algorithms, mandatory claims/UUID tenant, expiry/issuer/audience checks, offline key rotation and explicit configuration. Real IdP sessions, provisioning, BFF, CSRF and revocation remain open. |
| Storage/real source bytes | PARTIAL | APIShield local bytes and DataReconcile/AgentTest persisted report/export downloads have integrity evidence. External storage scanning, retention/deletion and source/dataset ingestion remain open. |
| Remote sandbox/provider/GitHub App | PARTIAL / BLOCKED | Signed GitHub webhook intake, replay protection and installation revocation projection are implemented with a separate least-privilege role. Remote execution/effects still fail closed; no independent escape/egress/SSRF proof, installed test GitHub App, repository read or approval-bound PR effect evidence exists. |
| Domain/privacy/operations/acceptance | OPEN | Human-adjudicated corpus/thresholds, legal/domain/accessibility review, independent signoff and production operating evidence are not supplied. |
| G1-E overall | OPEN/BLOCKED | Individual test success is not whole-gate acceptance. |

## Exact source receipt

Source: `c89785c342d488340ffa18d6dc35bcadaa7ccc47`. This immutable receipt covers that exact source, including synthetic/disposable limits. Later engineering commits require their own CI results; current main workflow status is authoritative for those commits.

- [G1 Contract Verification](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37888154257): **success** at `c89785c342d488340ffa18d6dc35bcadaa7ccc47`.
- [APIShield PostgreSQL Runtime Proof](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37888154277): **success** at `c89785c342d488340ffa18d6dc35bcadaa7ccc47`.
- [APIShield MVP Application CI](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent/actions/runs/37888154220): **success** at `c89785c342d488340ffa18d6dc35bcadaa7ccc47`.

- APIShield PostgreSQL Runtime Proof: 1 passed in 1.87s
- APIShield PostgreSQL Runtime Proof: {"check": "disposable logical restore and restored membership/RLS", "limits": "Not PITR, regional failover, production RTO/RPO or operational signoff", "result": "PASS", "rows": 19, "tables": 13}
- APIShield MVP Application CI: ======================== 40 passed, 1 skipped in 20.19s ========================

## Current product scope

Disposable logical restore verification now compares actual tenant RLS policy expressions/role bindings, table grants, and non-internal trigger definitions/functions, in addition to row digests, columns, constraints and RLS flags. This remains a logical disposable proof, not PITR, regional failover or production operating acceptance.

Disposable Sandbox Proof runs fixed synthetic Docker canaries on an opted-in GitHub Actions runner: non-root, read-only filesystem, dropped capabilities, no-new-privileges, seccomp, bounded scratch/resource policy and direct-IP network denial. The job resolves and records an immutable image ID before execution. It never runs customer code or mounts the host workspace/secrets. Passing this job is NOT an independent escape audit, image approval, production sandbox service or complete egress proof.

A read-only GitHub App source adapter is implemented and wired to embedded/standalone workers behind APISHIELD_GITHUB_READS_ENABLED. It mints RS256 App JWTs, requests repository-ID-restricted contents:read installation tokens, verifies repository identity and Git blob hashes, accepts only immutable commit SHAs, and refuses redirects/path escapes. Provisioned tenant/repository mappings are server-owned configuration, not request input. Synthetic injected-transport tests exercise this adapter and resulting snapshot-bound patches without network or real secrets. LIVE INSTALLATION PROOF REMAINS OPEN: no product GitHub App/private key/mapping has been supplied. Remote PR writes remain disabled.

Migration 004 persists immutable tenant-isolated analysis source snapshots in the same completion transaction. Proposals use these exact bytes and verify their digests, rather than reading mutable repository paths again. Missing/tampered snapshots fail closed. Runtime PostgreSQL roles cannot update/delete snapshot rows. This binds local analyzed bytes, not an independently fetched GitHub revision: real repository reads remain open.

Contract ingestion and analysis share a bounded offline parser that rejects duplicate mapping keys, YAML aliases, remote references, non-finite numbers, excessive structures and unsafe non-regular source files. Analysis hashes the exact bytes it parses, instead of reading the input again for its digest. Internal references/composition are explicitly recorded as UNSUPPORTED findings and counted in API responses and completion events, not silently presented as zero coverage gaps. Full OpenAPI compatibility analysis remains unfinished.

Approval writes now use compare-and-swap version fencing before inserting the approval record, and PostgreSQL locks repository permission reads within that transaction. Approval/commit idempotency digests include resource IDs, preventing cross-resource replay. Revoked repository access blocks approval commands and replays. Synthetic SQLite and disposable PostgreSQL concurrency proofs cover one-winner approval behavior; remote effects remain disabled.

Repository revocation now blocks new analysis requests (including idempotent replay), worker source reads, analysis result completion, and new patch proposals. Synthetic regression tests cover these paths. This is not proof of all concurrent external GitHub permission races or real installation lifecycle delivery.

Deterministic inline response-presence diffs, durable worker, verified local contract bytes and downloadable contract patches. Remote GitHub effects and sandbox execution remain disabled.

## Remaining dependency and implementation register

### Compatibility continuation, 2026-10-09

Analysis now detects operation removal even without required response fields, and request bodies becoming required. It resolves at most 32 pure local reference hops, with exact JSON Pointer escaping; cycles, missing targets and assertion siblings remain unknown. Required response presence changes can be detected through supported local references, but reference constructs still produce UNSUPPORTED review findings because full schema semantics are not implemented. Unresolved schemas are not treated as empty schemas. Findings use escaped pointers and tuple comparison keys to avoid delimiter collisions; evidence binds exact input digests. Regression corpus covers these rules and malformed response/request-body structures. Composition, full parameter/type/enum compatibility and live GitHub acceptance remain open.

1. Configure a real IdP and provisioned internal identities; finish BFF/session/CSRF/revocation and test them. This includes unfinished code, not only credentials.
2. Configure external private storage/scanning/retention/deletion and implement remaining source/dataset/upload adapters; do not treat placeholder metadata or quarantined objects as verified bytes.
3. Supply an isolated runner/network policy and installed test GitHub App; exercise the implemented webhook/revocation path against GitHub, then implement and prove repository reads and approval-bound remote effects before enabling them.
4. Supply approved evaluation corpora/thresholds and provider budget; implement real source/scanner/agent paths and establish observed quality/cost/load/recovery results.
5. Obtain domain/legal/privacy/operations/independent acceptance. Production acceptance remains blocked on these unresolved gates.

No background completion, production readiness or full-G1-E PASS is asserted.

## Runtime release controls — engineering continuation 2026-10-12

This change implements hosted revision/fingerprint identity, bounded private metrics, sanitized request logs, a fixed-origin deployment proof and a trusted-key production acceptance validator. Negative tests cover tampered/wrong-target receipts, open controls, invalid timing, staging relabelling, metric secrecy and incomplete responses. The production template remains unsigned and OPEN; no actual reviewer, production receipt, or authenticated hosted acceptance is asserted.

The local executor disconnected before publication. The publishable patch was reconstructed through the GitHub API; GitHub Actions at its exact committed bytes is the required regression evidence before promotion. Earlier local test counts are not proof for the reconstructed commit. Read the exact CI jobs and deployment source pin for current status.
