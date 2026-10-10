-- Additive index for analysis jobs by authorized repository. Apply only with the migration role
-- and search_path set to this product's private schema, pg_catalog.
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_tenant_repository ON analysis_jobs (tenant_id, repository_id);
