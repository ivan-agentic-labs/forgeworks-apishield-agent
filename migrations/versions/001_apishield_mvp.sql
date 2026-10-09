-- APIShield MVP migration. Apply only to an isolated disposable PostgreSQL database.
-- 30_fk_addendum_REVIEW_ONLY.sql is intentionally not included.
CREATE TABLE IF NOT EXISTS tenants (id uuid PRIMARY KEY, slug text UNIQUE NOT NULL, status text NOT NULL);
CREATE TABLE IF NOT EXISTS memberships (tenant_id uuid NOT NULL REFERENCES tenants(id), user_id text NOT NULL, role text NOT NULL, status text NOT NULL, PRIMARY KEY (tenant_id,user_id));
CREATE TABLE IF NOT EXISTS repositories (tenant_id uuid NOT NULL, id uuid NOT NULL, installation_id bigint NOT NULL, default_branch text NOT NULL, permission_state text NOT NULL, PRIMARY KEY (tenant_id,id), FOREIGN KEY (tenant_id) REFERENCES tenants(id));
CREATE TABLE IF NOT EXISTS analysis_jobs (tenant_id uuid NOT NULL, id uuid NOT NULL, job_id uuid NOT NULL, repository_id uuid NOT NULL, base_sha text NOT NULL, head_sha text NOT NULL, capability_profile text NOT NULL, status text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), completed_at timestamptz, version integer NOT NULL DEFAULT 1, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,job_id), FOREIGN KEY (tenant_id,repository_id) REFERENCES repositories(tenant_id,id));
CREATE TABLE IF NOT EXISTS analysis_findings (tenant_id uuid NOT NULL, id uuid NOT NULL, analysis_id uuid NOT NULL, rule_id text NOT NULL, severity text NOT NULL, openapi_pointer text NOT NULL, evidence_digest char(64) NOT NULL, coverage text NOT NULL, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,analysis_id,rule_id,openapi_pointer), FOREIGN KEY (tenant_id,analysis_id) REFERENCES analysis_jobs(tenant_id,id));
CREATE TABLE IF NOT EXISTS audit_events (tenant_id uuid NOT NULL, id uuid NOT NULL, event_type text NOT NULL, aggregate_id uuid NOT NULL, payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant_id,id));
ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY repositories_tenant ON repositories USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
CREATE POLICY analysis_jobs_tenant ON analysis_jobs USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
CREATE POLICY analysis_findings_tenant ON analysis_findings USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
