-- REVIEW CANDIDATE ONLY. SQLAlchemy PostgreSQL dialect compilation, NO live PostgreSQL.
-- NOT APPROVED AS EXECUTABLE MIGRATION. fw_apishield_agent_rw must be created with NOLOGIN,
-- checked grants and no table ownership or BYPASSRLS. A distinct migration
-- owner deploys schema. API service must authenticate membership, set SET LOCAL
-- app.tenant_id within transaction, and never pass SQL through to users.
-- Global tenants/users need dedicated authorization rules (not generic RLS).
-- No automatic fw_apishield_agent_rw GRANT is provided; least-privilege permissions undecided.
-- Audit events require retention controls and legal review.
-- PostgreSQL version/vendor and migration ordering are not yet approved.

CREATE TABLE tenants (
	id UUID NOT NULL, 
	slug TEXT NOT NULL, 
	status TEXT NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (slug)
)

;


CREATE TABLE users (
	id UUID NOT NULL, 
	issuer TEXT NOT NULL, 
	subject TEXT NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_users_issuer_sub UNIQUE (issuer, subject)
)

;


CREATE TABLE artifact_references (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	object_key TEXT NOT NULL, 
	sha256 CHAR(64) NOT NULL, 
	media_type TEXT NOT NULL, 
	status TEXT NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE, 
	CONSTRAINT pk_artifact_references PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_artifact_references_tenant FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT uq_artifact_key UNIQUE (tenant_id, object_key)
)

;


CREATE TABLE audit_events (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	actor_key TEXT NOT NULL, 
	action TEXT NOT NULL, 
	resource_key TEXT NOT NULL, 
	data_class TEXT NOT NULL, 
	trace_id TEXT, 
	payload JSONB NOT NULL, 
	CONSTRAINT pk_audit_events PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_audit_events_tenant FOREIGN KEY(tenant_id) REFERENCES tenants (id)
)

;


CREATE TABLE github_installations (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	github_installation_id BIGINT NOT NULL, 
	account_login TEXT NOT NULL, 
	permissions_digest CHAR(64) NOT NULL, 
	status TEXT NOT NULL, 
	verified_at TIMESTAMP WITH TIME ZONE, 
	CONSTRAINT pk_github_installations_tenant_id_id PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_github_installations_tenant_id FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT uq_github_installations_tenant_id_github_installation_id UNIQUE (tenant_id, github_installation_id)
)

;


CREATE TABLE idempotency_records (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	actor_key TEXT NOT NULL, 
	command_name TEXT NOT NULL, 
	idempotency_key TEXT NOT NULL, 
	request_sha256 CHAR(64) NOT NULL, 
	response_status INTEGER, 
	response_json JSONB, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	CONSTRAINT pk_idempotency_records PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_idempotency_records_tenant FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT uq_idempotency_scope UNIQUE (tenant_id, actor_key, command_name, idempotency_key)
)

;


CREATE TABLE inbox_receipts (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	consumer_name TEXT NOT NULL, 
	event_key TEXT NOT NULL, 
	processed_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	CONSTRAINT pk_inbox_receipts PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_inbox_receipts_tenant FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT uq_inbox_dedupe UNIQUE (tenant_id, consumer_name, event_key)
)

;


CREATE TABLE jobs (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	kind TEXT NOT NULL, 
	status TEXT NOT NULL, 
	version INTEGER DEFAULT 1 NOT NULL, 
	created_by UUID, 
	CONSTRAINT pk_jobs PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_jobs_tenant FOREIGN KEY(tenant_id) REFERENCES tenants (id)
)

;


CREATE TABLE memberships (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	user_id UUID NOT NULL, 
	role TEXT NOT NULL, 
	status TEXT NOT NULL, 
	CONSTRAINT pk_memberships PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_memberships_tenant FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT fk_memberships_user FOREIGN KEY(user_id) REFERENCES users (id), 
	CONSTRAINT uq_memberships_user UNIQUE (tenant_id, user_id)
)

;


CREATE TABLE outbox_events (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	event_type TEXT NOT NULL, 
	event_version INTEGER DEFAULT 1 NOT NULL, 
	payload JSONB NOT NULL, 
	event_key TEXT NOT NULL, 
	delivered_at TIMESTAMP WITH TIME ZONE, 
	CONSTRAINT pk_outbox_events PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_outbox_events_tenant FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT uq_outbox_key UNIQUE (tenant_id, event_key)
)

;


CREATE TABLE test_executions (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	analysis_job_id UUID NOT NULL, 
	proposal_id UUID NOT NULL, 
	runner_execution_id TEXT NOT NULL, 
	base_sha TEXT NOT NULL, 
	patch_sha256 CHAR(64) NOT NULL, 
	status TEXT NOT NULL, 
	evidence_digest CHAR(64), 
	started_at TIMESTAMP WITH TIME ZONE, 
	finished_at TIMESTAMP WITH TIME ZONE, 
	CONSTRAINT pk_test_executions_tenant_id_id PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_test_executions_tenant_id FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT uq_test_executions_tenant_id_runner_execution_id UNIQUE (tenant_id, runner_execution_id)
)

;


CREATE TABLE repositories (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	installation_ref_id UUID NOT NULL, 
	github_node_id TEXT NOT NULL, 
	default_branch TEXT NOT NULL, 
	permission_state TEXT NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	CONSTRAINT pk_repositories_tenant_id_id PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_repositories_tenant_id FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT fk_repositories_tenant_id_installation_ref_id FOREIGN KEY(tenant_id, installation_ref_id) REFERENCES github_installations (tenant_id, id), 
	CONSTRAINT uq_repositories_tenant_id_github_node_id UNIQUE (tenant_id, github_node_id)
)

;


CREATE TABLE analysis_jobs (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	repository_id UUID NOT NULL, 
	base_sha TEXT NOT NULL, 
	head_sha TEXT NOT NULL, 
	status TEXT NOT NULL, 
	profile_version TEXT NOT NULL, 
	version INTEGER DEFAULT 1 NOT NULL, 
	CONSTRAINT pk_analysis_jobs_tenant_id_id PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_analysis_jobs_tenant_id FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT fk_analysis_jobs_tenant_id_repository_id FOREIGN KEY(tenant_id, repository_id) REFERENCES repositories (tenant_id, id)
)

;


CREATE TABLE contract_snapshots (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	repository_id UUID NOT NULL, 
	commit_sha TEXT NOT NULL, 
	oas_sha256 CHAR(64) NOT NULL, 
	profile_version TEXT NOT NULL, 
	artifact_key TEXT NOT NULL, 
	CONSTRAINT pk_contract_snapshots_tenant_id_id PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_contract_snapshots_tenant_id FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT fk_contract_snapshots_tenant_id_repository_id FOREIGN KEY(tenant_id, repository_id) REFERENCES repositories (tenant_id, id), 
	CONSTRAINT uq_contract_snapshots_tenant_id_repository_id_commit__020717af UNIQUE (tenant_id, repository_id, commit_sha, oas_sha256)
)

;


CREATE TABLE analysis_findings (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	analysis_id UUID NOT NULL, 
	rule_id TEXT NOT NULL, 
	openapi_pointer TEXT NOT NULL, 
	coverage TEXT NOT NULL, 
	evidence_sha256 CHAR(64) NOT NULL, 
	CONSTRAINT pk_analysis_findings_tenant_id_id PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_analysis_findings_tenant_id FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT fk_analysis_findings_tenant_id_analysis_id FOREIGN KEY(tenant_id, analysis_id) REFERENCES analysis_jobs (tenant_id, id), 
	CONSTRAINT uq_analysis_findings_tenant_id_analysis_id_rule_id_op_064f8243 UNIQUE (tenant_id, analysis_id, rule_id, openapi_pointer)
)

;


CREATE TABLE patch_proposals (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	version INTEGER DEFAULT 1 NOT NULL, 
	analysis_id UUID NOT NULL, 
	base_sha TEXT NOT NULL, 
	patch_sha256 CHAR(64) NOT NULL, 
	sandbox_status TEXT NOT NULL, 
	approval_status TEXT NOT NULL, 
	artifact_key TEXT NOT NULL, 
	CONSTRAINT pk_patch_proposals_tenant_id_id PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_patch_proposals_tenant_id FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT fk_patch_proposals_tenant_id_analysis_id FOREIGN KEY(tenant_id, analysis_id) REFERENCES analysis_jobs (tenant_id, id), 
	CONSTRAINT uq_patch_proposals_tenant_id_analysis_id_patch_sha256 UNIQUE (tenant_id, analysis_id, patch_sha256), 
	CONSTRAINT ck_patch_proposals_version CHECK (version >= 1)
)

;


CREATE TABLE approvals (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	proposal_id UUID NOT NULL, 
	actor_id UUID NOT NULL, 
	decision TEXT NOT NULL, 
	proposal_version INTEGER NOT NULL, 
	reviewed_patch_sha256 CHAR(64) NOT NULL, 
	reviewed_base_sha TEXT NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	revoked_at TIMESTAMP WITH TIME ZONE, 
	CONSTRAINT pk_approvals_tenant_id_id PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_approvals_tenant_id FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT fk_approvals_tenant_id_proposal_id FOREIGN KEY(tenant_id, proposal_id) REFERENCES patch_proposals (tenant_id, id), 
	CONSTRAINT uq_approvals_tenant_id_proposal_id_reviewed_patch_sha_94330c6c UNIQUE (tenant_id, proposal_id, reviewed_patch_sha256, actor_id), 
	CONSTRAINT ck_approvals_decision CHECK (decision IN ('approve','reject')), 
	CONSTRAINT ck_approvals_proposal_version CHECK (proposal_version >= 1)
)

;


CREATE TABLE pr_effects (
	tenant_id UUID NOT NULL, 
	id UUID NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	proposal_id UUID NOT NULL, 
	approval_id UUID NOT NULL, 
	external_key TEXT NOT NULL, 
	github_pr_node_id TEXT, 
	status TEXT NOT NULL, 
	CONSTRAINT pk_pr_effects_tenant_id_id PRIMARY KEY (tenant_id, id), 
	CONSTRAINT fk_pr_effects_tenant_id FOREIGN KEY(tenant_id) REFERENCES tenants (id), 
	CONSTRAINT fk_pr_effects_tenant_id_proposal_id FOREIGN KEY(tenant_id, proposal_id) REFERENCES patch_proposals (tenant_id, id), 
	CONSTRAINT fk_pr_effects_tenant_id_approval_id FOREIGN KEY(tenant_id, approval_id) REFERENCES approvals (tenant_id, id), 
	CONSTRAINT uq_pr_effects_tenant_id_proposal_id UNIQUE (tenant_id, proposal_id), 
	CONSTRAINT uq_pr_effects_tenant_id_external_key UNIQUE (tenant_id, external_key)
)

;

-- INDEXES
CREATE INDEX "ix_analysis_jobs_tenant_id_repository_id_created_at_DESC" ON analysis_jobs (tenant_id, repository_id, created_at DESC);

-- RLS POLICIES (candidate, role not yet provisioned)
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY p_memberships_tenant ON memberships FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY p_jobs_tenant ON jobs FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox_events FORCE ROW LEVEL SECURITY;
CREATE POLICY p_outbox_events_tenant ON outbox_events FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE inbox_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE inbox_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY p_inbox_receipts_tenant ON inbox_receipts FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE idempotency_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_records FORCE ROW LEVEL SECURITY;
CREATE POLICY p_idempotency_records_tenant ON idempotency_records FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
-- Audit is append-only for the application role; owner/retention procedure is separate.
CREATE POLICY p_audit_events_read ON audit_events FOR SELECT TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY p_audit_events_append ON audit_events FOR INSERT TO fw_apishield_agent_rw WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE artifact_references ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_references FORCE ROW LEVEL SECURITY;
CREATE POLICY p_artifact_references_tenant ON artifact_references FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;
ALTER TABLE repositories FORCE ROW LEVEL SECURITY;
CREATE POLICY p_repositories_tenant ON repositories FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE contract_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE contract_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY p_contract_snapshots_tenant ON contract_snapshots FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE analysis_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY p_analysis_jobs_tenant ON analysis_jobs FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE analysis_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY p_analysis_findings_tenant ON analysis_findings FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE patch_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE patch_proposals FORCE ROW LEVEL SECURITY;
CREATE POLICY p_patch_proposals_tenant ON patch_proposals FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY p_approvals_tenant ON approvals FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE pr_effects ENABLE ROW LEVEL SECURITY;
ALTER TABLE pr_effects FORCE ROW LEVEL SECURITY;
CREATE POLICY p_pr_effects_tenant ON pr_effects FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE github_installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE github_installations FORCE ROW LEVEL SECURITY;
CREATE POLICY p_github_installations_tenant ON github_installations FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
ALTER TABLE test_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE test_executions FORCE ROW LEVEL SECURITY;
CREATE POLICY p_test_executions_tenant ON test_executions FOR ALL TO fw_apishield_agent_rw USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
