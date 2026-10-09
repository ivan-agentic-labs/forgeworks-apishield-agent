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
