# ForgeWorks Supabase RLS advisor triage (read-only, 2026-10-14)

**Target:** Supabase ForgeWorks `fljekuwplgkrpdoajyhn`; do not confuse with SealAngel. No SQL mutations were performed. This is a permission/catalog snapshot, not a penetration-test receipt.

## Evidence observed directly

- Project state `ACTIVE_HEALTHY`, Postgres 17.11, region ap-northeast-2.
- Five ForgeWorks application schemas contain **62 ordinary tables**, and all 62 have `relrowsecurity=true` and `relforcerowsecurity=true`.
- Security advisor: `rls_enabled_no_policy` INFO 7 findings; `auth_leaked_password_protection` WARN 1 finding.
- For all seven advisor-listed tables, `policy_count=0`, **`anon_select_grant=false` and `authenticated_select_grant=false`**. These results narrow the current public-client exposure risk. Absent policies with forced RLS generally implement deny-all for roles subject to RLS; never add permissive placeholder policies simply to silence a linter.
- **No permission to infer application-role and service-role safety from those two role checks.** Review the runtime grants, bypass-RLS roles, effective search path, invoker/definer functions, and session-auth business operations independently.

| Schema | Table | Policy count | Anon SELECT | Authenticated SELECT |
| --- | --- | ---: | --- | --- |
| fw_accessfix_ai | tenants | 0 | false | false |
| fw_agenttest_lab | tenants | 0 | false | false |
| fw_apishield_agent | tenants | 0 | false | false |
| fw_apishield_agent | github_installation_states | 0 | false | false |
| fw_apishield_agent | github_webhook_deliveries | 0 | false | false |
| fw_datareconcile_ai | tenants | 0 | false | false |
| fw_specforge_ai | tenants | 0 | false | false |

## Reproducible read-only SQL

```sql
SELECT n.nspname AS schema_name, c.relname AS table_name,
       c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS force_rls,
       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid) AS policy_count,
       has_table_privilege('anon', c.oid, 'SELECT') AS anon_select_grant,
       has_table_privilege('authenticated', c.oid, 'SELECT') AS authenticated_select_grant
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'
  AND (n.nspname, c.relname) IN (
    ('fw_accessfix_ai', 'tenants'),
    ('fw_agenttest_lab', 'tenants'),
    ('fw_apishield_agent', 'tenants'),
    ('fw_apishield_agent', 'github_installation_states'),
    ('fw_apishield_agent', 'github_webhook_deliveries'),
    ('fw_datareconcile_ai', 'tenants'),
    ('fw_specforge_ai', 'tenants'))
ORDER BY schema_name, table_name;
```

## Remaining security gate

1. Get explicit architecture confirmation that these seven tables are intended to be inaccessible to direct public-role reads; document any separate privileged access path and test its authorization.
2. Enable leaked-password protection if supported by the intended Auth configuration; this is currently a warning and requires configuration authority. [Supabase guidance](https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection).
3. Do not alter privileges, RLS or Supabase Auth merely to reduce advisory counts. Run independent tests using two **new, explicitly authorized, active** staging test identities. All 16 observed product memberships were REVOKED at audit time.
4. Review remaining [hosted acceptance gates](HOSTED_ACCEPTANCE_GAP_2026-10-14.md). The repository's production acceptance template remains unsigned and NOT_ACCEPTED.

Sources: connected Supabase catalog SQL and Security Advisor on 2026-10-14; [RLS linter documentation](https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy).
