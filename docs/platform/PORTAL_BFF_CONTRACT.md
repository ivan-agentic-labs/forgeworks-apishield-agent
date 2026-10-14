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

## Offline route admission implementation (2026-10-14)

`apps/portal/bff_policy.py` is a pure, non-networking admission plan for
five fixed GET resource routes. It strictly rejects unknown products,
ambiguous or percent-encoded targets, URL/host injection, other HTTP verbs,
noncanonical UUIDs and unapproved routes. The returned plan marks
`forward_enabled=False`, and `can_forward` always denies even if an untrusted
caller passes an alleged identity or role. This module is intentionally not an
authenticated BFF and is not attached to any production HTTP handler. A real
proxy must implement and independently verify session, tenant membership,
service audience, CSRF/cookie semantics, request budgets, and private egress.
