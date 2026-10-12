"""Compare logical backup/restore of fresh CI databases; never production or customer data."""
import hashlib
import importlib
import json
import os
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo


def snapshot(dsn):
    result = {}
    with psycopg.connect(dsn) as db:
        tables = [row[0] for row in db.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")]
        for table in tables:
            rows = db.execute(sql.SQL("SELECT to_jsonb(t) FROM {} t").format(sql.Identifier('public',table))).fetchall()
            documents = sorted(json.dumps(row[0], sort_keys=True, separators=(',',':')) for row in rows)
            columns = db.execute("SELECT column_name,data_type,is_nullable,column_default FROM information_schema.columns WHERE table_schema='public' AND table_name=%s ORDER BY ordinal_position",(table,)).fetchall()
            constraints = db.execute("SELECT conname,pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid=%s::regclass ORDER BY conname",('public.'+table,)).fetchall()
            flags = db.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=%s::regclass",('public.'+table,)).fetchone()
            policies = db.execute("SELECT polname,polpermissive,polcmd,pg_get_expr(polqual,polrelid),pg_get_expr(polwithcheck,polrelid),ARRAY(SELECT rolname FROM pg_roles WHERE oid=ANY(polroles) ORDER BY rolname) FROM pg_policy WHERE polrelid=%s::regclass ORDER BY polname",('public.'+table,)).fetchall()
            triggers = db.execute("SELECT tgname,pg_get_triggerdef(oid),tgenabled,pg_get_functiondef(tgfoid) FROM pg_trigger WHERE tgrelid=%s::regclass AND NOT tgisinternal ORDER BY tgname",('public.'+table,)).fetchall()
            grants = db.execute("SELECT grantee,privilege_type,is_grantable FROM information_schema.role_table_grants WHERE table_schema='public' AND table_name=%s ORDER BY grantee,privilege_type,is_grantable",(table,)).fetchall()
            result[table] = {'rows':len(rows),'sha256':hashlib.sha256(json.dumps(documents,separators=(',',':')).encode()).hexdigest(),'columns':columns,'constraints':constraints,'rls_flags':flags,'rls_policies':policies,'triggers_and_functions':triggers,'grants':grants}
    return result



def schema_catalog(dsn):
    """Verify DB objects omitted by table/data-only digests after pg_restore.

    A database whose rows and policies match can still be unusable if an
    index, sequence, user function, view or extension disappeared. Snapshot
    definitions from both disposable databases using the *same* owner role.
    """
    queries = {
        "indexes": """
            SELECT schemaname, tablename, indexname, indexdef
              FROM pg_indexes WHERE schemaname='public'
              ORDER BY schemaname, tablename, indexname
        """,
        "sequences": """
            SELECT schemaname, sequencename, data_type, start_value,
                   min_value, max_value, increment_by, cycle, cache_size, last_value
              FROM pg_sequences WHERE schemaname='public'
              ORDER BY schemaname, sequencename
        """,
        "views": """
            SELECT schemaname, viewname, definition
              FROM pg_views WHERE schemaname='public'
              ORDER BY schemaname, viewname
        """,
        "functions": """
            SELECT p.proname, pg_get_function_identity_arguments(p.oid),
                   pg_get_functiondef(p.oid)
              FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
             WHERE n.nspname='public'
             ORDER BY p.proname, pg_get_function_identity_arguments(p.oid)
        """,
        "extensions": """
            SELECT extname, extversion FROM pg_extension ORDER BY extname
        """,
    }
    with psycopg.connect(dsn) as db:
        return {kind: db.execute(query).fetchall() for kind, query in queries.items()}


def main():
    info = conninfo_to_dict(os.environ['FW_DISPOSABLE_OWNER_DSN'])
    if os.getenv('G1_DISPOSABLE_DB')!='yes' or info.get('host') not in {'localhost','127.0.0.1'} or info.get('dbname')!='forgeworks_runtime':
        raise SystemExit('Refusing non-disposable database configuration')
    restored = {**info,'dbname':'forgeworks_restore'}
    before, after = snapshot(make_conninfo(**info)), snapshot(make_conninfo(**restored))
    if not before or before!=after:
        raise SystemExit('RESTORED_TABLE_OR_POLICY_DRIFT: logical data, table definitions or RLS differ')
    catalog_before = schema_catalog(make_conninfo(**info))
    catalog_after = schema_catalog(make_conninfo(**restored))
    if catalog_before != catalog_after:
        raise SystemExit('RESTORED_SCHEMA_OBJECT_DRIFT: indexes, sequences, views, functions or extensions differ')
    module = importlib.import_module(os.environ['FW_PRODUCT_MODULE']+'.infrastructure.postgres_store')
    login = {**restored,'user':'fw_runtime_test','password':'synthetic-local-runtime-test-only'}
    store = module.PostgresStore(make_conninfo(**login))
    tenant='00000000-0000-0000-0000-000000000001'
    actor='00000000-0000-0000-0000-000000000010'
    assert store.member(tenant,actor)
    assert not store.member(tenant,'unmapped-oidc-subject')
    with psycopg.connect(make_conninfo(**login)) as db:
        db.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(module.ROLE)))
        assert db.execute('SELECT count(*) FROM memberships').fetchone()[0]==0
    print(json.dumps({'check':'disposable logical restore and restored membership/RLS','tables':len(before),'rows':sum(x['rows'] for x in before.values()),'schema_objects':sum(len(objects) for objects in catalog_before.values()),'result':'PASS','limits':'Disposable catalog/row/RLS only, not PITR, regional failover, production RTO/RPO or operational signoff'},sort_keys=True))


if __name__=='__main__':
    main()
