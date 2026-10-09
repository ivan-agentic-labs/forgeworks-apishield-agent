-- DESIGN CANDIDATE FOR DISPOSABLE PROOF ONLY.
-- Privileges apply exclusively to tenant-scoped tables protected by RLS.
-- Keep global `tenants` and `users` restricted to a separately audited provisioning path.
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE artifact_references TO fw_apishield_agent_rw;
-- Audit events: append-only for application role, no direct update/delete.
REVOKE ALL ON TABLE audit_events FROM PUBLIC;
REVOKE UPDATE, DELETE ON TABLE audit_events FROM fw_apishield_agent_rw;
GRANT SELECT, INSERT ON TABLE audit_events TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE github_installations TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE idempotency_records TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE inbox_receipts TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE jobs TO fw_apishield_agent_rw;
-- G1-D conditional restriction: membership writes disabled for generic app role.
-- Identity/admin provisioning service requires a separate reviewed role and authz gate.
REVOKE INSERT, UPDATE, DELETE ON TABLE memberships FROM fw_apishield_agent_rw;
GRANT SELECT ON TABLE memberships TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE outbox_events TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE test_executions TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE repositories TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE analysis_jobs TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE contract_snapshots TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE analysis_findings TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE patch_proposals TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE approvals TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE pr_effects TO fw_apishield_agent_rw;

-- Global identity tables must not be readable via PUBLIC (disposable-proof safeguard).
REVOKE ALL ON TABLE users, tenants FROM PUBLIC;
