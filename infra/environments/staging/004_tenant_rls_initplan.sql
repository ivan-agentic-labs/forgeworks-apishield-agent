-- Query-constant tenant context optimization; same predicate and fail-closed NULL semantics.
-- Existing policy must exist; run under the migration role with
-- search_path fw_apishield_agent,pg_catalog (disposable CI uses public schema).
ALTER POLICY repositories_tenant ON repositories
  USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid)
  WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
