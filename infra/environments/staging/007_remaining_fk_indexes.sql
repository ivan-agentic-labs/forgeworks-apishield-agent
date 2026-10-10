-- Additive FK lookup indexes for this product's small staging tables.
-- Apply after bootstrap and prior numbered staging migrations, in one transaction
-- with search_path set to the product schema, pg_catalog. Fail on lock contention.
SET LOCAL lock_timeout = '3s';
SET LOCAL statement_timeout = '30s';
CREATE INDEX IF NOT EXISTS idx_approvals_tenant_proposal ON approvals (tenant_id, proposal_id);
CREATE INDEX IF NOT EXISTS idx_idempotency_tenant_analysis ON idempotency (tenant_id, analysis_id);
CREATE INDEX IF NOT EXISTS idx_proposals_tenant_analysis ON proposals (tenant_id, analysis_id);
CREATE INDEX IF NOT EXISTS idx_pull_requests_tenant_proposal ON pull_requests (tenant_id, proposal_id);
