"""PostgreSQL runtime adapter; migrations are applied separately by the migration role."""
from __future__ import annotations

import inspect
import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from functools import wraps
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row

from apishield_agent.infrastructure.store import Store, now, later

TENANT_CONTEXT = ContextVar("apishield_tenant", default=None)
ROLE = "fw_apishield_agent_rw"
ALIASES = {"analyses": "analysis_jobs", "findings": "analysis_findings", "events": "audit_events"}


class Row(dict):
    def __getitem__(self, key):
        return list(self.values())[key] if isinstance(key, int) else super().__getitem__(key)


def normalize(row):
    if row is None:
        return None
    return Row({key: str(value) if isinstance(value, UUID) else value.isoformat().replace("+00:00", "Z") if isinstance(value, datetime) else value for key, value in row.items()})


class Cursor:
    def __init__(self, cursor):
        self.cursor = cursor
        self.rowcount = cursor.rowcount

    def fetchone(self):
        return normalize(self.cursor.fetchone())

    def fetchall(self):
        return [normalize(row) for row in self.cursor.fetchall()]


class Connection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, statement, parameters=()):
        for source, target in ALIASES.items():
            statement = re.sub(r"\b" + source + r"\b", target, statement)
        statement = statement.replace("ORDER BY rowid", "ORDER BY id")
        if statement.startswith("INSERT OR IGNORE INTO"):
            statement = statement.replace("INSERT OR IGNORE INTO", "INSERT INTO", 1) + " ON CONFLICT DO NOTHING"
        statement = statement.replace("?", "%s")
        try:
            # A savepoint preserves SQLite's recoverable statement-failure semantics.
            with self.connection.transaction():
                cursor = self.connection.execute(statement, parameters)
            return Cursor(cursor)
        except psycopg.IntegrityError as error:
            raise sqlite3.IntegrityError("Database integrity constraint rejected the command") from error


def tenant_method(method):
    @wraps(method)
    def wrapped(self, tenant, *args, **kwargs):
        tenant = str(UUID(str(tenant)))
        token = TENANT_CONTEXT.set(tenant)
        try:
            return method(self, tenant, *args, **kwargs)
        finally:
            TENANT_CONTEXT.reset(token)
    return wrapped


class PostgresStore(Store):
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.lock = threading.RLock()
        with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5) as db:
            role = db.execute("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname=current_user").fetchone()
            if any(role.values()):
                raise ValueError("Runtime must not use a superuser, BYPASSRLS, CREATEROLE or CREATEDB role")
            if not db.execute("SELECT pg_has_role(current_user, %s, 'MEMBER') AS allowed", (ROLE,)).fetchone()["allowed"]:
                raise ValueError("Runtime login must be a member of the tenant application role")
            if db.execute("SELECT 1 FROM pg_tables WHERE schemaname=current_schema() AND tableowner IN (current_user, %s) AND tablename IN ('tenants','analysis_jobs','repositories','memberships','analysis_findings','audit_events','artifacts','proposals','approvals','pull_requests','idempotency','commands','proposal_patch_content','github_webhook_deliveries','github_installation_states','analysis_source_snapshots')", (ROLE,)).fetchone():
                raise ValueError("Runtime must not own product tables")
            attributes = db.execute("SELECT rolsuper, rolbypassrls, rolcanlogin, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname=%s", (ROLE,)).fetchone()
            if not attributes or any(attributes.values()):
                raise ValueError("Tenant group role must be NOLOGIN, NOSUPERUSER and NOBYPASSRLS")
            if not db.execute("SELECT 1 FROM information_schema.columns WHERE table_name='analysis_jobs' AND column_name='lease_token'").fetchone():
                raise ValueError("Apply migration 002 with the migration role before starting runtime")
            if not db.execute("SELECT to_regclass('analysis_source_snapshots') AS present").fetchone()['present']:
                raise ValueError('Apply migration 004 before starting snapshot-backed analysis runtime')

    @tenant_method
    def session_active(self, tenant, user, session_id):
        with self.conn() as db:
            db.execute("SELECT set_config('request.jwt.claim.sub', ?, true)", (str(UUID(user)),))
            row = db.execute("SELECT session_active(?, ?) AS active", (str(UUID(session_id)), str(UUID(user)))).fetchone()
            return bool(row["active"])

    @tenant_method
    def member(self, tenant, user):
        try:
            user = str(UUID(str(user)))
        except ValueError:
            return False  # No provisioned UUID identity mapping; fail closed before SQL.
        with self.conn() as db:
            return db.execute("SELECT 1 FROM memberships WHERE tenant_id=? AND user_id=? AND status='ACTIVE'", (tenant, user)).fetchone() is not None

    @contextmanager
    def conn(self, tenant=None):
        tenant = tenant or TENANT_CONTEXT.get()
        if tenant is None:
            raise ValueError("A transaction requires an explicit tenant context")
        tenant = str(UUID(str(tenant)))
        with psycopg.connect(self.dsn, row_factory=dict_row, connect_timeout=5) as db:
            db.execute("SET LOCAL ROLE fw_apishield_agent_rw")
            db.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant,))
            yield Connection(db)
        # The connection is closed and its transaction-local context cannot leak.

    def seed_demo(self, before, after):
        raise ValueError("PostgreSQL identity provisioning requires the separate migration/provisioning role")

    def worker_tenants(self):
        return [str(UUID(value.strip())) for value in os.getenv("APISHIELD_WORKER_TENANTS", "").split(",") if value.strip()]

    def claim_pending(self, lease_seconds=30):
        for tenant in self.worker_tenants():
            with self.conn(tenant) as db:
                db.execute("UPDATE analyses SET status='FAILED_TERMINAL', last_error_code='STALE_LEASE', version=version+1, lease_until=NULL WHERE status='RUNNING' AND lease_until IS NOT NULL AND lease_until < ?", (now(),))
                row = db.execute("SELECT * FROM analyses WHERE status='PENDING' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED").fetchone()
                if row:
                    token = str(uuid4())
                    return db.execute("UPDATE analyses SET status='RUNNING', attempt_count=attempt_count+1, version=version+1, lease_until=?, lease_token=? WHERE tenant_id=? AND id=? AND status='PENDING' RETURNING *", (later(lease_seconds), token, tenant, row["id"])).fetchone()
        return None

    def pending(self):
        rows = []
        for tenant in self.worker_tenants():
            with self.conn(tenant) as db:
                rows.extend(db.execute("SELECT * FROM analyses WHERE status='PENDING' ORDER BY created_at").fetchall())
        return rows

    @tenant_method
    def create_analysis(self, tenant, actor, repo, base, head, profile, idem_key, request_sha):
        with self.conn() as db:
            db.execute("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", (f"{tenant}:{actor}:{idem_key}",))
            old = db.execute("SELECT * FROM idempotency WHERE tenant_id=? AND actor=? AND key=?", (tenant, actor, idem_key)).fetchone()
            if old:
                if old["request_sha"] != request_sha:
                    raise ValueError("IDEMPOTENCY_CONFLICT")
                return db.execute("SELECT * FROM analyses WHERE tenant_id=? AND id=?", (tenant, old["analysis_id"])).fetchone()
            aid, jid = str(uuid4()), str(uuid4())
            db.execute("INSERT INTO analyses(tenant_id,id,job_id,repository_id,base_sha,head_sha,capability_profile,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (tenant, aid, jid, repo, base, head, profile, "PENDING", now()))
            db.execute("INSERT INTO idempotency VALUES(?,?,?,?,?)", (tenant, actor, idem_key, request_sha, aid))
            return db.execute("SELECT * FROM analyses WHERE tenant_id=? AND id=?", (tenant, aid)).fetchone()


# The inherited domain commands all open their transactions inside a verified,
# explicit tenant context. No connection-wide or process-global tenant state.
for name, method in inspect.getmembers(Store, predicate=inspect.isfunction):
    parameters = list(inspect.signature(method).parameters)
    if len(parameters) > 1 and parameters[1] == "tenant" and name not in PostgresStore.__dict__:
        setattr(PostgresStore, name, tenant_method(method))
