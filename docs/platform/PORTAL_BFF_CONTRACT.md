# Unified portal / BFF boundary, pre-implementation contract

**Stage:** proposed interface only. The BFF does not exist in the deployed
services. Portal source is under `apps/portal` in the APIShield repository as a
controlled frontend package, without merging any backend repositories.

## Routing

- Single HTTPS origin for public portal, with HSTS and TLS configured at edge.
- `GET /api/platform/status`: requires no credentials, returns only
  `{"schema":"forgeworks-portal-status-v1","environment":"staging","status":"reachable"}`
  on validated staging. Never returns tenant IDs, keys, infrastructure IDs,
  private service URLs or production acceptance claims.
- Reserved five routes: `/app/apishield-agent`, `/app/accessfix-ai`,
  `/app/specforge-ai`, `/app/agenttest-lab`,
  `/app/datareconcile-ai`. Until BFF/SSO is validated none is active.
- Business API routes remain `/api/<product>/v1/*` behind explicit
  service allowlists, *not* an open proxy taking a request-supplied URL.

## Auth and tenancy

A server-side portal session may resolve an authorized workspace and issue
a short-lived, product-audience-bound credential for each specific backend.
Each backend must independently verify issuer/audience, membership, role,
session validity, tenant ownership and request authorization. No wildcard
service tokens, tenant IDs from query parameters, or cross-tenant shared DB role.
CSRF controls are mandatory for cookie-authenticated mutations. Backends
must reject replay, revoked sessions and a conflicting workspace claim.

## Safety and acceptance

All five APIs must keep their existing independent repositories, RLS,
rollback plans and CI. This is a contract, not a shortcut to a production
rollout. Require authenticated own-tenant and cross-tenant tests before
enabling any business route; gateway readiness alone cannot satisfy G1-E.
