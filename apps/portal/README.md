# ForgeWorks unified portal shell (staging-only source package)

This source-only, dependency-free HTML/CSS/JavaScript package is the first
shared frontend surface for five independent backend products. It has **not**
been deployed as the public portal and is deliberately not production-ready.

- Five ordered catalog entries and reserved same-origin `/app/<product>` routes.
- Security-lean HTML: restrictive static CSP, no third-party scripts, no
  localStorage/sessionStorage of tokens, no arbitrary remote URLs.
- Explicit status checking on a fixed same-origin `GET /api/platform/status`.
  The loopback preview serves development-only status; this is not an
  authenticated business BFF. "reachable" never means production accepted.
- Opt-in, bounded server-side five-product staging monitoring on
  `GET /api/platform/services`, with strict release identity verification,
  fixed HTTPS targets, no redirects, credentials, or arbitrary proxy URL.
- No login, tenant state, direct cross-origin provider calls, billing, SSO or
  customer content. Navigation to the five reserved application routes is
  intentionally disabled until BFF and service authorization exist.

## Preview only

From the repository root:

```bash
python apps/portal/dev_server.py --port 8080 --probe-staging
```

Open http://127.0.0.1:8080. The preview can read the five fixed staging
origins only when explicitly opted in; no business endpoints are proxied.
Without `--probe-staging`, the services endpoint returns HTTP 503 and makes
no upstream calls. Never expose this preview as a customer production app.

## Tests

```bash
node --check apps/portal/app.js
python -m unittest discover -s tests/platform -p 'test_portal_*.py' -v
python apps/portal/service_status.py --live-staging  # Requires network; staging only
```

## Next gates

1. Implement a versioned, same-origin BFF with strict route allowlisting and
   a service-specific audience per backend. Never forward a general portal
   token or trust browser-supplied tenant IDs.
2. Implement tested session lifecycle, CSRF prevention, workspace membership
   and per-service authorization. Verify with two real test tenants.
3. Add CSP and other security headers at the HTTP gateway, not only HTML meta.
4. Wire dedicated domain/TLS, monitoring, production infrastructure and
   independent acceptance only after the owner makes those decisions.

This package changes no existing API routes and has no effect on live Railway.

## BFF admission policy (offline only)

`bff_policy.py` contains a testable five-product, GET-only routing policy.
All forwarding remains disabled, even with caller-provided identity claims;
this is a deliberately safe partial implementation and is not a real gateway.
The test workflow rejects URL ambiguity, path injection and unauthorized
verbs before a backend transport could ever exist.

All fleet checks are selected-source identity and anonymous-boundary checks. They do **not** establish authentication, business functionality, production deployment or SLO.

## Local preview request boundary (2026-10-14)

The preview rejects repeated or non-loopback Host headers, authorization/cookie
credentials, GET/HEAD request-body framing, encoded path separators, path
parameters and excessive targets. These are defense-in-depth controls for the
local development-only server. They are **not** an authenticated customer proxy,
a deployed gateway, or production acceptance. All checks run in the offline
portal regression suite and preserve the five fixed read-only status routes.

## Offline BFF authorization preflight (not active)

The versioned read-only plan now records the actual product-specific backend
scope for each of the five allowed routes: `analysis:read`, `scan:read`,
`spec:read`, `evaluation:read` and `report:read`. A pure, offline
`preflight_read` checks a **hypothetical server-reviewed** membership and
session snapshot for tenant match, role, scope, expiration, and immutable
allowlisted route identity. It does not verify a bearer token, consult live
membership, perform session revocation or authorize real traffic. Any
application using it must FIRST independently authenticate and validate that
snapshot, and must enforce authorization again at the backend. `can_forward`
remains hardcoded false even when the offline preflight is true.

## Credential-free local monitoring

The preview frontend uses `credentials: 'omit'` for catalog and operational
status fetches, and the preview server rejects Cookie and Authorization
headers. No BFF session, login or customer data can be used here. A future
authenticated portal must implement independent verified sessions and CSRF
protections instead of weakening the preview security assumptions.
