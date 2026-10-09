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
