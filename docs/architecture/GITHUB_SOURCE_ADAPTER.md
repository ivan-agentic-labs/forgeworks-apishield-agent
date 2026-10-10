# Read-only source adapter — engineering handoff

## Implemented and tested

The embedded and standalone durable workers can obtain before/head contract bytes from a GitHub App installation. The feature is disabled by default. No repository writes, draft PR creation, workflow changes or production deployment are performed by this adapter.

The adapter requests an installation token restricted to one provisioned repository ID and `contents:read`. It verifies the repository ID/full name, uses exact 40-character commit SHAs, validates the returned Git blob hash, parses sources offline and stores the exact analyzed bytes in immutable analysis snapshots. Unsupported schema constructs are reported explicitly. Redirects, path traversal, excessive permissions, unsafe file types and mutable refs fail closed.

## Runtime configuration, not repository secrets

Provide `APISHIELD_GITHUB_READS_ENABLED=1`, `APISHIELD_GITHUB_APP_ID`, `APISHIELD_GITHUB_APP_PRIVATE_KEY`, and `APISHIELD_GITHUB_SOURCE_MAP_JSON` through the runtime secret/configuration manager. Do not paste private keys into the repository, documentation, issues or CI logs.

The source map is a JSON object keyed by `tenant_uuid:internal_repository_uuid`. Each value requires:

| Field | Meaning |
|---|---|
| installation_id | Provisioned installation ID; must match the product repository record |
| repository_id | GitHub numeric repository ID; must match the GitHub metadata response |
| full_name | Exact GitHub owner/repository identity |
| contract_path | Relative path of the contract, without empty/dot/traversal segments |

Provision the product repository and membership through the separate migration/provisioning role. Do not infer this map from request parameters. Missing mappings fail closed when read mode is enabled; they do not fall back to fixture files. Local-path analysis is restricted to development/test.

Migrations 001–004 are required for the implemented PostgreSQL runtime. Workers must also have explicitly configured tenant enumeration. GitHub webhook delivery uses the separate least-privilege webhook login from migration 003; snapshot and tenant application roles remain separate from that login.

## Evidence boundaries

Injected-transport tests verify RS256 signing, least-privilege token requests, source integrity, failure handling and the worker-to-snapshot-to-proposal path. They do NOT demonstrate an installed product App, real token permissions, actual GitHub delivery or external repository reads. The connected ChatGPT GitHub account is not automatically the product App.

Live proof requires a registered/installed test App, provisioned identities/mappings, secrets outside git and an isolated runtime. Use synthetic repositories only. Repository write effects remain disabled even after read configuration is supplied. An offline TypeScript caller/path migration module is now available (see TYPESCRIPT_CALLER_PROFILE.md). Wiring its independently verified caller snapshots into the durable worker and approval records, approval-bound PR effects, real sandbox/provider execution and complete compatibility analysis remain unfinished implementation, not merely missing credentials.

## Reference specifications

- https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
- https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
- https://docs.github.com/en/rest/repos/contents#get-repository-content
