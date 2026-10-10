-- Apply under the migration role in the product schema after staging 001-007.
-- The webhook role has a revoke-only UPDATE policy. A PUBLIC tenant policy
-- would also apply to it and OR its WITH CHECK with that revoke-only guard.
-- Preserve the tenant predicate; restrict its audience to the application role.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';
ALTER POLICY repositories_tenant ON repositories TO fw_apishield_agent_rw;
