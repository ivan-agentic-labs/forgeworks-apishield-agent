# APIShield Agent

**Status: synthetic MVP deployed to Railway staging, with scoped CI evidence. Not production-ready; G1-E and authenticated customer acceptance remain open.**

API change impact analysis, verified patch proposals and GitHub PR approval workflows.

The first executable slice accepts an authorized analysis request, persists a tenant-scoped job, runs a deterministic OpenAPI fixture diff through a local worker, and exposes findings/status. It does not perform GitHub writes, arbitrary code execution, AI provider calls, or customer-data processing.

## MVP run and test

```bash
python -m pip install --require-hashes -r requirements-runtime.lock
python -m pip install -e 'apps/api[test]' -r scripts/requirements-verification.txt
export APP_ENV=development AUTH_MODE=development
export AUTH_ISSUER=https://issuer.synthetic.invalid AUTH_AUDIENCE=forgeworks-api
export DEV_AUTH_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export ARTIFACT_SIGNING_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python scripts/development_token.py
APISHIELD_SEED_FIXTURE=1 PYTHONPATH=apps/api/src uvicorn apishield_agent.main:app --reload
```

The printed token lasts 15 minutes and belongs to the local synthetic tenant/user. Use a second terminal with the same explicit development environment to run python -W error -m pytest tests. Never enable fixtures or reuse the development token on hosted infrastructure or customer data.


## Static blueprint viewer
`apps/web/` contains a vanilla HTML/JS read-only viewer for the canonical analysis, job, and findings endpoints. Run the API and static server as documented in `apps/web/README.md`; the viewer requires an analysis ID and job ID from the analysis response. GitHub writes remain disabled.

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

CI runs on main and verifies the complete test tree, OpenAPI/event contracts, generated TypeScript client, implemented PostgreSQL MVP runtime, tenant RLS/concurrency and disposable logical backup/restore. These are scoped synthetic proofs; full G1-E and production operations remain open.

## Non-goals at this stage
No production deployment, customer data, code-execution agent, customer production access, financial mutation, license assertion or fake passing tests.

## Governance
The owner approved proceeding with GitHub bootstrap. Technical G1-E controls are still pending until their tests actually pass and evidence is reviewed. See `docs/governance/MASTER_G1_DECISION.md` for pre-approval baseline language; the owner approval is recorded here as a later decision.


## Engineering continuation

See [current changes and residual gaps](docs/evidence/ENGINEERING_CONTINUATION.md). Configure authentication explicitly; development fixture commands now require `AUTH_MODE=development`, `APP_ENV=development`, a locally generated `DEV_AUTH_SECRET` of at least 32 bytes, and issuer/audience configuration. Never reuse test fixture credentials outside tests.

## Current main engineering status

See [current G1/G2 evidence](docs/verification/CURRENT_GATE_EVIDENCE.md), [exact source receipt](docs/evidence/MAIN_VERIFICATION_2026-10-09.json), and [owner main authorization](docs/governance/ENGINEERING_MAIN_AUTHORIZATION_2026-10-09.md). PostgreSQL adapters exist for all five independent projects. Historical evidence retains its source SHA and narrower scope.

GitHub App webhook intake now verifies `sha256` signatures over the exact body, enforces UUID delivery IDs and a 1 MiB limit, rejects conflicting replays, and projects installation suspension/deletion through a separate least-privilege PostgreSQL role. Remote repository reads and pull-request writes remain disabled until an installed test GitHub App and approval-bound effect tests are available.


A bounded [TypeScript caller profile](docs/architecture/TYPESCRIPT_CALLER_PROFILE.md) can now propose actual source diffs for literal global-fetch endpoint relocations. It remains an offline review tool; product worker/approval integration and sandbox build proof are still unfinished.

## Hosted release verification

See [runtime identity, private telemetry and production acceptance](ops/runbooks/RUNTIME_RELEASE_VERIFICATION.md). Hosted releases expose a bounded source fingerprint and require a separate server-only metrics credential. Production startup requires separate infrastructure and an actual trusted, signed acceptance receipt. An unsigned template or passing synthetic CI does not establish production acceptance.


## Current owner specification and unified application

- **Owner design revision (2026-10-13):** [product specification](docs/specifications/PRODUCT_SPECIFICATION_2026-10-13.md). This is a **design target**, not proof every feature exists.
- **Five ForgeWorks products, one future application/domain:** [architecture](docs/platform/ONE_APP_FIVE_SERVICES.md). SealAngel Work is a separate planned repository/application/domain; neither domain name is configured by this documentation.
- **Actual implemented and verified behavior:** keep using [current scoped evidence](docs/verification/CURRENT_GATE_EVIDENCE.md) and the [hosted runbook](ops/runbooks/RUNTIME_RELEASE_VERIFICATION.md). Local tests, staging claims and production acceptance are different gates.
- The 2026-10-09 G2 bootstrap record remains historical and must not be mistaken for today's repository status.
