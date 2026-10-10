-- Twelve existing tenant equality policies. Does not change TO roles or commands.
-- Preserve webhook_revoke / webhook_visible_for_revoke policies unchanged.
-- Staging migration role search_path=fw_apishield_agent,pg_catalog.
ALTER POLICY analysis_findings_tenant ON analysis_findings USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
ALTER POLICY analysis_jobs_tenant ON analysis_jobs USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
ALTER POLICY tenant_boundary ON analysis_source_snapshots USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
ALTER POLICY runtime_tenant ON approvals USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
ALTER POLICY runtime_tenant ON artifacts USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
ALTER POLICY runtime_tenant ON audit_events USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
ALTER POLICY runtime_tenant ON commands USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
ALTER POLICY runtime_tenant ON idempotency USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
ALTER POLICY runtime_tenant ON memberships USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
ALTER POLICY patch_content_tenant ON proposal_patch_content USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
ALTER POLICY runtime_tenant ON proposals USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
ALTER POLICY runtime_tenant ON pull_requests USING (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid) WITH CHECK (tenant_id = NULLIF((SELECT current_setting('app.tenant_id', true)), '')::uuid);
