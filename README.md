# APIShield Agent

> **Analyze API changes before integrations break.**

Part of **ForgeWorks**, a collection of five complementary API services for software engineering and operations.

## What the product does

APIShield Agent compares defined API contracts, records structured analysis jobs, and surfaces changes that engineers can review before updating API consumers. It turns a contract-change review into a repeatable workflow with traceable findings.

**Who uses it:** Backend teams, platform engineers, and API maintainers.

## Capabilities and outputs

| Capability | Input / action | Output |
| --- | --- | --- |
| Contract comparison | Stored OpenAPI specifications and deterministic comparison fixtures | An analysis job, status, and structured change findings |
| Consumer change assistance | Supported literal global-fetch patterns in TypeScript source | A bounded, offline proposed source diff for endpoint relocations |
| Repository event intake | Signed GitHub App webhook payloads | Validated deliveries with replay and installation-state protections |
| Read-only review | Analysis and job identifiers | A local viewer for job state and findings |

## Example workflow

1. Submit a tenant-scoped comparison using the versioned API and an authorized development session.
2. Inspect the analysis job and findings to identify possible API compatibility issues.
3. Review any eligible TypeScript caller diff as a proposed change, not as an automatically applied patch.
4. Use the result as engineering evidence when planning a contract or client migration.

**What a team gets:** explicit inputs, a repeatable processing path, and inspectable outputs for review. The read-only viewer is in [apps/web/](apps/web/) and uses the existing analysis and job APIs.

## Technical design

- **API:** Python service with versioned REST/OpenAPI contracts and structured error handling.
- **Data:** PostgreSQL domain adapter and tenant-scoped data access controls.
- **Auth:** explicit development authentication for local use; never reuse local keys or sample identities on hosted infrastructure.
- **Verification:** automated code tests, contract checks, and scoped evidence documents. Their meaning is limited to the scenarios they exercised.

## Run locally

Install Python and the runtime/test dependencies from the repository root:

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

The generated token is short-lived and is only for local development with synthetic data. To run the test suite, use `python -W error -m pytest tests` with the same explicit development environment.

## API and technical references

- [Product scope](docs/product/PRODUCT_SCOPE.md)
- [Architecture](docs/architecture/)
- [OpenAPI contract](contracts/openapi.yaml) and [event schemas](contracts/events.schema.json)
- [Verification evidence](docs/verification/CURRENT_GATE_EVIDENCE.md)
- [Release verification runbook](ops/runbooks/RUNTIME_RELEASE_VERIFICATION.md)
- [One-app / five-services design](docs/platform/ONE_APP_FIVE_SERVICES.md)

## ForgeWorks service family

- [APIShield Agent](https://github.com/ivan-agentic-labs/forgeworks-apishield-agent) · API contract-change analysis
- [AccessFix AI](https://github.com/ivan-agentic-labs/forgeworks-accessfix-ai) · accessibility review
- [SpecForge AI](https://github.com/ivan-agentic-labs/forgeworks-specforge-ai) · requirements-to-API contracts
- [AgentTest Lab](https://github.com/ivan-agentic-labs/forgeworks-agenttest-lab) · AI agent evaluation
- [DataReconcile AI](https://github.com/ivan-agentic-labs/forgeworks-datareconcile-ai) · reconciliation and exceptions

The services have separate repositories and explicit interfaces. A single customer-facing ForgeWorks portal is an architectural direction, not a claim of independently verified live integration.

## Usage boundary

Contract comparison uses bounded inputs; the TypeScript proposal operates offline, and GitHub repository reads and PR writes are disabled. The README does not claim automatic modification of customer repositories or verified hosted customer acceptance. Consult the linked evidence register and runbook before claiming customer-level or production acceptance.
