# ForgeWorks — One Application / Five Independent Product Services

**Architecture decision recorded:** 2026-10-13. **Status:** target architecture, not yet deployed as a unified application.

**One user-facing domain/application** (hostname still TBD):
- APIShield Agent
- AccessFix AI
- SpecForge AI
- AgentTest Lab
- DataReconcile AI

**Separate second application/domain:** SealAngel Work. It has its own product boundary and will have a separate repository named `forgeworks-sealangel-work` when provisioned. It is NOT a sixth feature inside the ForgeWorks portal.

## Integration shape
```text
ForgeWorks domain (TBD) --> shared web portal + authentication + workspace navigation
                         --> versioned API gateway/BFF
                               |--> APIShield service (independent repository)
                               |--> AccessFix service (independent repository)
                               |--> SpecForge service (independent repository)
                               |--> AgentTest service (independent repository)
                               +--> DataReconcile service (independent repository)

SealAngel domain (TBD)  --> SealAngel UI + API + worker + data plane (independent)
```

This **does not** imply a shared Postgres superuser, a shared unrestricted token or five production backends. Prefer a unified SSO identity with service-audience-bound, short-lived tokens and explicit `workspace_id` at every service boundary. Per-service authorization remains mandatory even if portal/BFF authenticates requests.

## Migration / acceptance sequence
1. Preserve the five existing backend repos, ownership boundaries, migrations, tests, and historical evidence.
2. Select a portal shell owner (new portal repository or controlled frontend package; decision pending) and domain names (no domain purchase implied).
3. Define SSO/BFF API contracts, tenant mapping, roles, separate service audiences, service health and unified navigation.
4. Prove product-specific authorization, API compatibility and failures using synthetic fixtures and staging.
5. Configure DNS/TLS only after ownership and rollout approval; do not connect customer data before privacy and security acceptance.

No project can claim release acceptance solely because the portal links to it.
