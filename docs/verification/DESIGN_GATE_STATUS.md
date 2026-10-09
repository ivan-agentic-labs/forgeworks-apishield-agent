# apishield-agent — G1-D / G1-E decision
**Owner approval to proceed: RECORDED. Domain/independent signoffs: OPEN. G1-E: PARTIAL / BLOCKED.**

**Required domain signoff:** GitHub App permission scoping, OpenAPI breaking-change compatibility, patch provenance and VM sandbox.
**Fail-closed constraint:** No automatic repo merge or arbitrary execution; GitHub App read scope before PR permissions.

Canonical implementation-input files are `contracts/openapi.yaml`, `contracts/events.schema.json`, `docs/verification/sql-candidates/00_role_candidate.sql`, `docs/verification/sql-candidates/10_schema_candidate.sql`, `docs/verification/sql-candidates/20_grants_candidate.sql`, and the **unapproved** `docs/verification/sql-candidates/30_fk_addendum_REVIEW_ONLY.sql`.

The `30_` file contains proposed composite FKs only. **Do not apply automatically**, migrate real data, or mark it approved before domain/cardinality/delete-semantics review and live PostgreSQL tests. It is deliberately not merged into `10_schema_candidate.sql`.

Required before G1-E PASS: semantic OpenAPI validator+client compilation, PostgreSQL empty-DB migration and two-tenant negative tests, ownership/membership authorization checks, identity provider integration, sandbox escape/egress tests where relevant, and production budget/privacy/domain review.


## Current engineering evidence

[Current gate ledger](CURRENT_GATE_EVIDENCE.md) supersedes earlier NOT_RUN labels only for its explicitly verified scope. Design-candidate SQL, external acceptance and full-gate approval remain separate.
