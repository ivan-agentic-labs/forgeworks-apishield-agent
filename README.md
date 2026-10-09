# APIShield Agent

**Status: synthetic MVP milestone implemented and tested locally. Not deployed, not production-ready, and G1-E remains open.**

API change impact analysis, verified patch proposals and GitHub PR approval workflows.

The first executable slice accepts an authorized analysis request, persists a tenant-scoped job, runs a deterministic OpenAPI fixture diff through a local worker, and exposes findings/status. It does not perform GitHub writes, arbitrary code execution, AI provider calls, or customer-data processing.

## MVP run and test
```bash
python -m pip install -e 'apps/api[test]'
APISHIELD_SEED_FIXTURE=1 PYTHONPATH=apps/api/src uvicorn apishield_agent.main:app --reload
python -W error -m pytest tests/unit tests/integration
```
The default SQLite store, synthetic HS256 issuer, and golden fixture are development/test-only. See `docs/evidence/MVP_CHECKPOINT.md`.

## Documents
- Product scope: `docs/product/PRODUCT_SCOPE.md`
- Architecture and file ownership: `docs/architecture/`
- Source contracts: `contracts/openapi.yaml` and `contracts/events.schema.json`
- Candidate SQL: `docs/verification/sql-candidates/` (NOT migration scripts)
- Signoff / blockers: `docs/verification/DESIGN_GATE_STATUS.md` and `docs/governance/MASTER_G1_DECISION.md`

## Local verification
Install dependencies from `scripts/requirements-verification.txt` then run:

```bash
python scripts/verify_bootstrap.py
python scripts/verify_contracts.py
python scripts/validate_openapi_independent.py
```

CI contains a manual PostgreSQL disposable DDL smoke test. **No live RLS/two-tenant proof or sandbox evidence is claimed.**

## Non-goals at this stage
No production deployment, customer data, code-execution agent, public access, financial mutation, license assertion or fake passing tests.

## Governance
The owner approved proceeding with GitHub bootstrap. Technical G1-E controls are still pending until their tests actually pass and evidence is reviewed. See `docs/governance/MASTER_G1_DECISION.md` for pre-approval baseline language; the owner approval is recorded here as a later decision.
