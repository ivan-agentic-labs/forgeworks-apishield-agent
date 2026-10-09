-- Staging only: fresh private schema in the connected Supabase project.
-- Apply exactly once through the migration/provisioning role. Never at app startup.
CREATE SCHEMA fw_apishield_agent;
REVOKE ALL ON SCHEMA fw_apishield_agent FROM PUBLIC, anon, authenticated;
SET LOCAL search_path TO fw_apishield_agent, pg_catalog;
ALTER DEFAULT PRIVILEGES IN SCHEMA fw_apishield_agent REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA fw_apishield_agent REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon, authenticated;
-- Source: 001_apishield_mvp.sql
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

-- Source: 002_apishield_runtime.sql
-- Extends the implemented MVP schema for PostgreSQL runtime. No auto-application.
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS before_contract text;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS after_contract text;
ALTER TABLE analysis_jobs ADD COLUMN IF NOT EXISTS attempt_count integer NOT NULL DEFAULT 0;
ALTER TABLE analysis_jobs ADD COLUMN IF NOT EXISTS last_error_code text;
ALTER TABLE analysis_jobs ADD COLUMN IF NOT EXISTS lease_until timestamptz;
ALTER TABLE analysis_jobs ADD COLUMN IF NOT EXISTS lease_token text;
ALTER TABLE analysis_jobs ADD COLUMN IF NOT EXISTS result_digest text;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fw_apishield_agent_rw') THEN
  CREATE ROLE fw_apishield_agent_rw NOLOGIN NOSUPERUSER NOBYPASSRLS;
 END IF;
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fw_apishield_agent_rw' AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
  RAISE EXCEPTION 'Unsafe existing application group role';
 END IF;
END $$;
CREATE TABLE IF NOT EXISTS idempotency (tenant_id uuid NOT NULL, actor TEXT NOT NULL, key TEXT NOT NULL, request_sha TEXT NOT NULL, analysis_id uuid NOT NULL, PRIMARY KEY (tenant_id,actor,key), FOREIGN KEY (tenant_id) REFERENCES tenants(id));
CREATE TABLE IF NOT EXISTS commands (tenant_id uuid NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, key TEXT NOT NULL, request_sha TEXT NOT NULL, resource_id uuid NOT NULL, PRIMARY KEY (tenant_id,actor,action,key), FOREIGN KEY (tenant_id) REFERENCES tenants(id));
CREATE TABLE IF NOT EXISTS artifacts (tenant_id uuid NOT NULL, id uuid NOT NULL, kind TEXT NOT NULL, filename TEXT NOT NULL, declared_media_type TEXT, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, status TEXT NOT NULL, object_generation TEXT, rejected_reason TEXT, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, PRIMARY KEY (tenant_id,id), FOREIGN KEY (tenant_id) REFERENCES tenants(id));
CREATE TABLE IF NOT EXISTS proposals (tenant_id uuid NOT NULL, id uuid NOT NULL, analysis_id uuid NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, base_sha TEXT NOT NULL, patch_sha256 TEXT NOT NULL, sandbox_status TEXT NOT NULL, approval_status TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (tenant_id,id), FOREIGN KEY (tenant_id) REFERENCES tenants(id));
CREATE TABLE IF NOT EXISTS approvals (tenant_id uuid NOT NULL, id uuid NOT NULL, proposal_id uuid NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, patch_sha256 TEXT NOT NULL, base_sha TEXT NOT NULL, reviewer_id uuid NOT NULL, expires_at TEXT NOT NULL, PRIMARY KEY (tenant_id,id), FOREIGN KEY (tenant_id) REFERENCES tenants(id));
CREATE TABLE IF NOT EXISTS pull_requests (tenant_id uuid NOT NULL, id uuid NOT NULL, proposal_id uuid NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, github_pr_node_id uuid NOT NULL, draft INTEGER NOT NULL, external_effect_key TEXT NOT NULL, PRIMARY KEY (tenant_id,id), FOREIGN KEY (tenant_id) REFERENCES tenants(id));
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_tenant ON memberships;
CREATE POLICY runtime_tenant ON memberships TO fw_apishield_agent_rw USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON memberships TO fw_apishield_agent_rw;
ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE repositories FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_tenant ON repositories;
CREATE POLICY runtime_tenant ON repositories TO fw_apishield_agent_rw USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON repositories TO fw_apishield_agent_rw;
ALTER TABLE analysis_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_tenant ON analysis_jobs;
CREATE POLICY runtime_tenant ON analysis_jobs TO fw_apishield_agent_rw USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON analysis_jobs TO fw_apishield_agent_rw;
ALTER TABLE analysis_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_tenant ON analysis_findings;
CREATE POLICY runtime_tenant ON analysis_findings TO fw_apishield_agent_rw USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON analysis_findings TO fw_apishield_agent_rw;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_tenant ON audit_events;
CREATE POLICY runtime_tenant ON audit_events TO fw_apishield_agent_rw USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_events TO fw_apishield_agent_rw;
ALTER TABLE idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_tenant ON idempotency;
CREATE POLICY runtime_tenant ON idempotency TO fw_apishield_agent_rw USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON idempotency TO fw_apishield_agent_rw;
ALTER TABLE commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE commands FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_tenant ON commands;
CREATE POLICY runtime_tenant ON commands TO fw_apishield_agent_rw USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON commands TO fw_apishield_agent_rw;
ALTER TABLE artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifacts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_tenant ON artifacts;
CREATE POLICY runtime_tenant ON artifacts TO fw_apishield_agent_rw USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON artifacts TO fw_apishield_agent_rw;
ALTER TABLE proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_tenant ON proposals;
CREATE POLICY runtime_tenant ON proposals TO fw_apishield_agent_rw USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON proposals TO fw_apishield_agent_rw;
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_tenant ON approvals;
CREATE POLICY runtime_tenant ON approvals TO fw_apishield_agent_rw USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON approvals TO fw_apishield_agent_rw;
ALTER TABLE pull_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pull_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS runtime_tenant ON pull_requests;
CREATE POLICY runtime_tenant ON pull_requests TO fw_apishield_agent_rw USING (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid) WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true),'')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON pull_requests TO fw_apishield_agent_rw;
GRANT USAGE ON SCHEMA fw_apishield_agent TO fw_apishield_agent_rw;
REVOKE ALL ON tenants FROM fw_apishield_agent_rw;
REVOKE UPDATE, DELETE ON audit_events FROM fw_apishield_agent_rw;
ALTER TABLE idempotency ADD CONSTRAINT idempotency_analysis_fk FOREIGN KEY (tenant_id,analysis_id) REFERENCES analysis_jobs(tenant_id,id);
ALTER TABLE proposals ADD CONSTRAINT proposals_analysis_fk FOREIGN KEY (tenant_id,analysis_id) REFERENCES analysis_jobs(tenant_id,id);
ALTER TABLE approvals ADD CONSTRAINT approvals_proposal_fk FOREIGN KEY (tenant_id,proposal_id) REFERENCES proposals(tenant_id,id);
ALTER TABLE pull_requests ADD CONSTRAINT pull_requests_proposal_fk FOREIGN KEY (tenant_id,proposal_id) REFERENCES proposals(tenant_id,id);
CREATE UNIQUE INDEX IF NOT EXISTS pull_requests_effect_unique ON pull_requests(tenant_id,external_effect_key);
REVOKE INSERT, UPDATE, DELETE ON memberships FROM fw_apishield_agent_rw;
CREATE TABLE IF NOT EXISTS proposal_patch_content(tenant_id uuid NOT NULL,id uuid NOT NULL,patch_text text NOT NULL,PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,id) REFERENCES proposals(tenant_id,id));
ALTER TABLE proposal_patch_content ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposal_patch_content FORCE ROW LEVEL SECURITY;
CREATE POLICY patch_content_tenant ON proposal_patch_content TO fw_apishield_agent_rw USING(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
GRANT SELECT, INSERT ON proposal_patch_content TO fw_apishield_agent_rw;

-- Source: 003_github_webhook_inbox.sql
-- Dedicated GitHub App webhook inbox and revocation projection.
-- Apply with the migration owner. The API runtime role receives no access.
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fw_apishield_webhook') THEN
  CREATE ROLE fw_apishield_webhook NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
 END IF;
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='fw_apishield_webhook' AND (rolsuper OR rolbypassrls OR rolcanlogin OR rolcreaterole OR rolcreatedb)) THEN
  RAISE EXCEPTION 'Unsafe existing webhook group role';
 END IF;
END $$;

CREATE TABLE IF NOT EXISTS github_webhook_deliveries (
 delivery_id uuid PRIMARY KEY,
 event text NOT NULL,
 payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
 received_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS github_installation_states (
 installation_id bigint PRIMARY KEY CHECK (installation_id > 0),
 state text NOT NULL CHECK (state IN ('ACTIVE','SUSPENDED','DELETED')),
 updated_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON github_webhook_deliveries, github_installation_states FROM PUBLIC, fw_apishield_agent_rw;
GRANT SELECT, INSERT ON github_webhook_deliveries TO fw_apishield_webhook;
GRANT SELECT, INSERT, UPDATE ON github_installation_states TO fw_apishield_webhook;
DROP POLICY IF EXISTS webhook_revoke ON repositories;
DROP POLICY IF EXISTS webhook_visible_for_revoke ON repositories;
CREATE POLICY webhook_visible_for_revoke ON repositories FOR SELECT TO fw_apishield_webhook
 USING (true);
CREATE POLICY webhook_revoke ON repositories FOR UPDATE TO fw_apishield_webhook
 USING (true) WITH CHECK (permission_state = 'REVOKED');
GRANT SELECT(installation_id,permission_state), UPDATE(permission_state) ON repositories TO fw_apishield_webhook;

-- Source: 004_analysis_source_snapshots.sql
-- Bind proposals to the exact contract bytes analyzed by the durable worker.
CREATE TABLE analysis_source_snapshots(
 tenant_id uuid NOT NULL, analysis_id uuid NOT NULL,
 before_base64 text NOT NULL, after_base64 text NOT NULL,
 before_sha char(64) NOT NULL, after_sha char(64) NOT NULL,
 PRIMARY KEY(tenant_id,analysis_id),
 FOREIGN KEY(tenant_id,analysis_id) REFERENCES analysis_jobs(tenant_id,id)
);
ALTER TABLE analysis_source_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_source_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_boundary ON analysis_source_snapshots USING(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('app.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON analysis_source_snapshots TO fw_apishield_agent_rw;

-- Auth-managed tables remain untouched. Return only a boolean for the JWT-bound user.
CREATE FUNCTION fw_apishield_agent.session_active(session_id uuid, user_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
 SELECT auth.uid() = $2 AND EXISTS (
   SELECT 1 FROM auth.sessions s JOIN auth.users u ON u.id=s.user_id
   WHERE s.id=$1 AND s.user_id=$2
     AND (s.not_after IS NULL OR s.not_after > now())
     AND u.deleted_at IS NULL AND (u.banned_until IS NULL OR u.banned_until <= now())
 );
$$;
REVOKE ALL ON FUNCTION fw_apishield_agent.session_active(uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION fw_apishield_agent.session_active(uuid, uuid) TO fw_apishield_agent_rw;
GRANT USAGE ON SCHEMA fw_apishield_agent TO fw_apishield_agent_rw;
-- Restrict all product tables, including unexposed tenants, as defense in depth.
DO $$ DECLARE t record; BEGIN
 FOR t IN SELECT tablename FROM pg_tables WHERE schemaname='fw_apishield_agent' LOOP
   EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY','fw_apishield_agent',t.tablename);
   EXECUTE format('ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY','fw_apishield_agent',t.tablename);
   EXECUTE format('REVOKE ALL ON %I.%I FROM PUBLIC, anon, authenticated','fw_apishield_agent',t.tablename);
 END LOOP;
END $$;
RESET search_path;
