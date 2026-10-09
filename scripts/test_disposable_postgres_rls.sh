#!/usr/bin/env bash
set -euo pipefail

# This test is intentionally destructive to the named disposable database only.
[[ "${G1_DISPOSABLE_DB:-}" == 'yes' ]] || { echo 'G1_DISPOSABLE_DB=yes required' >&2; exit 2; }
[[ "${PGHOST:-}" == '127.0.0.1' ]] || { echo 'only 127.0.0.1 is allowed' >&2; exit 2; }
[[ "${PGDATABASE:-}" == 'forgeworks_g1' ]] || { echo 'only disposable database forgeworks_g1 is allowed' >&2; exit 2; }
command -v psql >/dev/null || { echo 'psql unavailable' >&2; exit 2; }

root="$(cd "$(dirname "$0")/.." && pwd)"
psql_args=(-X -v ON_ERROR_STOP=1)

# Refuse a reused database: this proof must start with no application tables.
table_count="$(psql "${psql_args[@]}" -Atqc "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r','p','m');")"
[[ "$table_count" == "0" ]] || { echo "database is not empty (public table count: $table_count)" >&2; exit 2; }

psql "${psql_args[@]}" -f "$root/migrations/versions/001_apishield_mvp.sql"
psql "${psql_args[@]}" <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fw_apishield_agent_rw') THEN
    CREATE ROLE fw_apishield_agent_rw NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname = 'fw_apishield_agent_rw'
      AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'unsafe database role attributes: fw_apishield_agent_rw';
  END IF;
END $$;
GRANT USAGE ON SCHEMA public TO fw_apishield_agent_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON repositories, analysis_jobs, analysis_findings TO fw_apishield_agent_rw;

DO $$
DECLARE owner_name text;
BEGIN
  SELECT pg_get_userbyid(c.relowner) INTO owner_name FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relname = 'analysis_jobs';
  IF owner_name = 'fw_apishield_agent_rw' THEN
    RAISE EXCEPTION 'application role must not own analysis_jobs';
  END IF;
END $$;

INSERT INTO tenants (id, slug, status) VALUES
  ('00000000-0000-0000-0000-0000000000a1', 'rls-tenant-a', 'active'),
  ('00000000-0000-0000-0000-0000000000b1', 'rls-tenant-b', 'active');
INSERT INTO repositories (tenant_id, id, installation_id, default_branch, permission_state) VALUES
  ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-0000000000a2', 1, 'main', 'verified'),
  ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-0000000000b2', 2, 'main', 'verified');
INSERT INTO analysis_jobs (tenant_id, id, job_id, repository_id, base_sha, head_sha, capability_profile, status)
VALUES
  ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-0000000000a3', '00000000-0000-0000-0000-0000000000a4', '00000000-0000-0000-0000-0000000000a2', repeat('a', 40), repeat('b', 40), 'rls-test', 'SUCCEEDED'),
  ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-0000000000b3', '00000000-0000-0000-0000-0000000000b4', '00000000-0000-0000-0000-0000000000b2', repeat('c', 40), repeat('d', 40), 'rls-test', 'SUCCEEDED');
INSERT INTO analysis_findings (tenant_id, id, analysis_id, rule_id, severity, openapi_pointer, evidence_digest, coverage)
VALUES
  ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-0000000000a5', '00000000-0000-0000-0000-0000000000a3', 'RLS_A', 'low', '#/paths/a', repeat('a', 64), 'covered'),
  ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-0000000000b5', '00000000-0000-0000-0000-0000000000b3', 'RLS_B', 'low', '#/paths/b', repeat('b', 64), 'covered');

SET ROLE fw_apishield_agent_rw;
SET app.tenant_id = '00000000-0000-0000-0000-0000000000a1';
DO $$
DECLARE repository_count integer;
DECLARE job_count integer;
DECLARE finding_count integer;
BEGIN
  SELECT count(*) INTO repository_count FROM repositories;
  SELECT count(*) INTO job_count FROM analysis_jobs;
  SELECT count(*) INTO finding_count FROM analysis_findings;
  IF repository_count <> 1 OR job_count <> 1 OR finding_count <> 1 THEN
    RAISE EXCEPTION 'tenant isolation failed: repositories %, jobs %, findings %', repository_count, job_count, finding_count;
  END IF;
END $$;

-- The application role cannot write a row for another tenant while scoped to A.
DO $$
BEGIN
  BEGIN
    INSERT INTO analysis_jobs (tenant_id, id, job_id, repository_id, base_sha, head_sha, capability_profile, status)
    VALUES ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-0000000000b6', '00000000-0000-0000-0000-0000000000b7', '00000000-0000-0000-0000-0000000000b2', repeat('e', 40), repeat('f', 40), 'rls-test', 'PENDING');
    RAISE EXCEPTION 'cross-tenant insert unexpectedly succeeded';
  EXCEPTION WHEN insufficient_privilege THEN
    NULL;
  END;
END $$;
RESET ROLE;
SELECT 'RLS tenant-isolation negative test: PASS' AS result;
SQL
