-- Webhook inbox tables: keep RLS enabled + forced, and give the dedicated
-- webhook role explicit policies. Without these, FORCE RLS with zero policies
-- denies every webhook query (found in audit 2026-10-20).
-- Apply with the migration owner. The API runtime role still receives no access.
ALTER TABLE github_webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE github_webhook_deliveries FORCE ROW LEVEL SECURITY;
ALTER TABLE github_installation_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE github_installation_states FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS webhook_deliveries_select ON github_webhook_deliveries;
DROP POLICY IF EXISTS webhook_deliveries_insert ON github_webhook_deliveries;
CREATE POLICY webhook_deliveries_select ON github_webhook_deliveries FOR SELECT TO fw_apishield_webhook
 USING (true);
CREATE POLICY webhook_deliveries_insert ON github_webhook_deliveries FOR INSERT TO fw_apishield_webhook
 WITH CHECK (true);

DROP POLICY IF EXISTS webhook_installations_select ON github_installation_states;
DROP POLICY IF EXISTS webhook_installations_insert ON github_installation_states;
DROP POLICY IF EXISTS webhook_installations_update ON github_installation_states;
CREATE POLICY webhook_installations_select ON github_installation_states FOR SELECT TO fw_apishield_webhook
 USING (true);
CREATE POLICY webhook_installations_insert ON github_installation_states FOR INSERT TO fw_apishield_webhook
 WITH CHECK (state IN ('ACTIVE','SUSPENDED','DELETED'));
CREATE POLICY webhook_installations_update ON github_installation_states FOR UPDATE TO fw_apishield_webhook
 USING (true) WITH CHECK (state IN ('ACTIVE','SUSPENDED','DELETED'));
