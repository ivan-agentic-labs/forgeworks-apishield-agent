# G3 real authenticated tenant-isolation acceptance (owner authorized)

This is an **opt-in, read-only** acceptance harness. It is not part of the default
GitHub Actions staging check and **does not** fabricate positive test results.

## Prerequisites requiring owner authorization

- Two distinct, consenting Supabase staging test identities with verified,
  non-anonymous, non-expired sessions. Each must have a separate active product
  tenant membership with the appropriate read scope across all five ForgeWorks
  products. Do not reactivate revoked memberships or reuse production accounts.
- Two independently created and approved *synthetic business records* per
  product, one belonging to each staging test tenant. Record IDs must be
  canonical UUIDs and endpoints must return HTTP 200 to their owner.
- Secure access tokens obtained through the normal Supabase test sign-in flow,
  stored only in protected ephemeral environment/CI secrets. **Never put tokens
  in a GitHub issue, pull request, chat message, repository or committed file.**
- Permission to run 20 read-only staging API calls (four per product).

## Runtime configuration

Set `FORGEWORKS_G3_AUTH_ACCEPTANCE=yes` explicitly. Provide two independent
access tokens as `FORGEWORKS_G3_TENANT_A_TOKEN` and
`FORGEWORKS_G3_TENANT_B_TOKEN`.

Provide these **ten** UUID fixture variables, each sourced from an existing
authorized staging record, not invented identifiers:

| Product | Tenant A record | Tenant B record |
|---|---|---|
| APIShield Agent | `FORGEWORKS_G3_APISHIELD_TENANT_A_RESOURCE_ID` | `FORGEWORKS_G3_APISHIELD_TENANT_B_RESOURCE_ID` |
| AccessFix AI | `FORGEWORKS_G3_ACCESSFIX_TENANT_A_RESOURCE_ID` | `FORGEWORKS_G3_ACCESSFIX_TENANT_B_RESOURCE_ID` |
| SpecForge AI | `FORGEWORKS_G3_SPECFORGE_TENANT_A_RESOURCE_ID` | `FORGEWORKS_G3_SPECFORGE_TENANT_B_RESOURCE_ID` |
| AgentTest Lab | `FORGEWORKS_G3_AGENTTEST_TENANT_A_RESOURCE_ID` | `FORGEWORKS_G3_AGENTTEST_TENANT_B_RESOURCE_ID` |
| DataReconcile AI | `FORGEWORKS_G3_DATARECONCILE_TENANT_A_RESOURCE_ID` | `FORGEWORKS_G3_DATARECONCILE_TENANT_B_RESOURCE_ID` |

From a trusted environment with these values injected as process environment
variables, run:

```bash
python3 -W error scripts/probe_authenticated_tenant_isolation.py
```

The script refuses to make **any** request unless the full fixture set is
valid and opt-in is explicit. It requires a real HTTP 200 for each tenant's
own record, followed by HTTP 403/404 for both cross-tenant reads. An HTTP 401
or 5xx on any probe is a failure, not proof of isolation. It sends GET only
to the five pinned staging Railway HTTPS hosts, follows no redirects and
does not log access tokens, record IDs or response bodies.

The CI workflow executes **offline, synthetic tests of this harness**, without
real credentials. Those tests demonstrate guard behavior; they do not satisfy
this live G3 acceptance gate.

**Remaining independent acceptance:** creation of legally approved test users,
product memberships and data; real IdP/tenant test execution; scoped write
isolation, session revocation after login, operational recovery, provider and
finance-specific business acceptance, plus independent security review. None
are established by an offline acceptance-plan test.
