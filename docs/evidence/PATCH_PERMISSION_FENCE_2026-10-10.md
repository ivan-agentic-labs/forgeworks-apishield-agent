# Patch permission fence — 2026-10-10

Historical proposal patch bytes now require current READ/WRITE repository permission at transfer time. The store checks the tenant-bound proposal/analysis/repository relationship, acquires a repository share lock on PostgreSQL (or a SQLite write transaction), copies the patch bytes, and verifies the stored SHA in the same transaction. A revocation committed before this check prevents transfer with REPOSITORY_ACCESS_REVOKED. Bytes already copied under an authorized earlier check cannot be recalled from a concurrent response or a previous download.

New approvals also verify actual stored patch bytes before updating proposal version or inserting approval evidence. Missing/tampered content returns PATCH_INTEGRITY_FAILURE and writes no approval. Existing historical approval replay remains an audit record rather than permission to execute a repository effect; GitHub write effects are still disabled.

Six integration regressions cover permission states, tamper/deletion before approval, tenant isolation, scope, and digest response headers. Local application tests: 230 passed, 1 PostgreSQL skip, excluding the browser E2E because the local browser is unavailable. Both PostgreSQL and browser are mandatory workflow proofs. The PostgreSQL webhook proof now checks denial of an existing patch following an authenticated installation suspension.

This patch is a source contract comparison, not a TypeScript caller migration. It does not implement repository writes or production deployment.
