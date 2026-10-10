-- These runtime_tenant policies duplicate the tenant equality restrictions
-- of the matching ALL / TO PUBLIC tenant policies on the same tables.
-- PostgreSQL ORs permissive policies. Keeping one identical PUBLIC predicate
-- retains the tenant boundary for fw_apishield_agent_rw.
-- Existing webhook-specific policies stay in place. Validate disposable
-- runtime/webhook/negative-tenant tests before staging deployment.
-- Run only with search_path=fw_apishield_agent,pg_catalog and migration role.
DROP POLICY runtime_tenant ON analysis_findings;
DROP POLICY runtime_tenant ON analysis_jobs;
DROP POLICY runtime_tenant ON repositories;
