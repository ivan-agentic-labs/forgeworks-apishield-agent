# G2 bootstrap status — 9 October 2026

Owner: `ivan-agentic-labs`. Five independent private repositories are authorized.
G1 owner design approval permits bootstrap; historical conditional review text remains baseline evidence. G1-D remains CONDITIONAL/UNSIGNED and G1-E remains OPEN/BLOCKED until all required runtime evidence and signoffs are accepted.

For source SHA `345f15abdfc89f1f8ac21e85801122c741b0dee7`, local product pytest (13 tests), independent OpenAPI validation, static contract/event checks, and shell/Node checks passed. GitHub Actions also passed the application, contract, empty disposable PostgreSQL migration, and bounded non-owner RLS workflows: see `docs/evidence/G1_RUNTIME_EVIDENCE.md` for exact commands, exits, and run URLs. This is partial evidence, not G1 approval. Generated-client compilation, real IdP/OIDC/CSRF, browser sandbox/egress, external storage/queue/provider permissions, legal/domain/ops/cost signoff, and production backup/restore remain NOT_RUN or BLOCKED. Local PostgreSQL attempts were not claimed as evidence because both exited 2 on unavailable local authentication.

APIShield is the first implementation priority AFTER remote bootstrap and CI verification. No production deployment or customer data is authorized.

The PostgreSQL workflow uses an intentionally public, disposable localhost-only test password. This is not a production credential. Never reuse it outside the isolated test service.
