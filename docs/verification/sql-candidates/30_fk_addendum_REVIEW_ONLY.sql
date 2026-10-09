-- DESIGN-ONLY SQL. NOT VALIDATED BY A LIVE POSTGRESQL INSTANCE.
-- Review business semantics, existing data, and ON DELETE decision before adoption.
-- Apply after 10_schema_candidate.sql, on an isolated disposable database only.

ALTER TABLE test_executions
  ADD CONSTRAINT fk_g1_test_executions_analysis_job_id
  FOREIGN KEY (tenant_id, analysis_job_id)
  REFERENCES analysis_jobs (tenant_id, id)
  ON DELETE RESTRICT;

ALTER TABLE test_executions
  ADD CONSTRAINT fk_g1_test_executions_proposal_id
  FOREIGN KEY (tenant_id, proposal_id)
  REFERENCES patch_proposals (tenant_id, id)
  ON DELETE RESTRICT;
