from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TENANT = "00000000-0000-0000-0000-000000000001"
USER = "00000000-0000-0000-0000-000000000010"
REPOSITORY = "11111111-1111-1111-1111-111111111111"


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Store:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._init_schema()

    def conn(self):
        c = sqlite3.connect(self.path, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def _init_schema(self):
        with self.lock, self.conn() as c:
            c.executescript("""
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, slug TEXT UNIQUE NOT NULL, status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS memberships (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY (tenant_id,user_id));
            CREATE TABLE IF NOT EXISTS repositories (tenant_id TEXT NOT NULL, id TEXT NOT NULL, installation_id INTEGER NOT NULL, default_branch TEXT NOT NULL, permission_state TEXT NOT NULL, before_contract TEXT, after_contract TEXT, PRIMARY KEY (tenant_id,id));
            CREATE TABLE IF NOT EXISTS analyses (tenant_id TEXT NOT NULL, id TEXT NOT NULL, job_id TEXT NOT NULL, repository_id TEXT NOT NULL, base_sha TEXT NOT NULL, head_sha TEXT NOT NULL, capability_profile TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT, version INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,job_id));
            CREATE TABLE IF NOT EXISTS findings (tenant_id TEXT NOT NULL, id TEXT NOT NULL, analysis_id TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL, openapi_pointer TEXT NOT NULL, evidence_digest TEXT NOT NULL, coverage TEXT NOT NULL, UNIQUE (tenant_id,analysis_id,rule_id,openapi_pointer));
            CREATE TABLE IF NOT EXISTS idempotency (tenant_id TEXT NOT NULL, actor TEXT NOT NULL, key TEXT NOT NULL, request_sha TEXT NOT NULL, analysis_id TEXT NOT NULL, PRIMARY KEY (tenant_id,actor,key));
            CREATE TABLE IF NOT EXISTS events (tenant_id TEXT NOT NULL, id TEXT PRIMARY KEY, event_type TEXT NOT NULL, aggregate_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL);
            """)

    def seed_demo(self, before: str, after: str):
        with self.lock, self.conn() as c:
            c.execute("INSERT OR IGNORE INTO tenants VALUES (?,?,?)", (TENANT, "synthetic-demo", "ACTIVE"))
            c.execute("INSERT OR IGNORE INTO memberships VALUES (?,?,?,?)", (TENANT, USER, "editor", "ACTIVE"))
            c.execute("INSERT OR REPLACE INTO repositories VALUES (?,?,?,?,?,?,?)", (TENANT, REPOSITORY, 1, "main", "READ", before, after))

    def get_repo(self, tenant: str, installation: int, repo: str):
        with self.conn() as c:
            return c.execute("SELECT * FROM repositories WHERE tenant_id=? AND installation_id=? AND id=?", (tenant, installation, repo)).fetchone()

    def member(self, tenant: str, user: str) -> bool:
        with self.conn() as c:
            return c.execute("SELECT 1 FROM memberships WHERE tenant_id=? AND user_id=? AND status='ACTIVE'", (tenant,user)).fetchone() is not None

    def get_idempotent(self, tenant, actor, key):
        with self.conn() as c: return c.execute("SELECT * FROM idempotency WHERE tenant_id=? AND actor=? AND key=?", (tenant,actor,key)).fetchone()

    def get_analysis(self, tenant, aid):
        with self.conn() as c: return c.execute("SELECT * FROM analyses WHERE tenant_id=? AND id=?", (tenant,aid)).fetchone()

    def create_analysis(self, tenant, actor, repo, base, head, profile, idem_key, request_sha):
        aid, jid = str(uuid.uuid4()), str(uuid.uuid4())
        with self.lock, self.conn() as c:
            c.execute("INSERT INTO analyses(tenant_id,id,job_id,repository_id,base_sha,head_sha,capability_profile,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (tenant,aid,jid,repo,base,head,profile,"PENDING",now()))
            c.execute("INSERT INTO idempotency VALUES(?,?,?,?,?)", (tenant,actor,idem_key,request_sha,aid))
        return self.get_analysis(tenant, aid)

    def finish(self, tenant, aid, findings):
        with self.lock, self.conn() as c:
            for f in findings:
                c.execute("INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?)", (tenant,str(uuid.uuid4()),aid,f.rule_id,f.severity,f.pointer,f.evidence_digest,f.coverage))
            c.execute("UPDATE analyses SET status='SUCCEEDED',completed_at=? WHERE tenant_id=? AND id=?", (now(),tenant,aid))
            payload = {"analysis_id": aid, "finding_count": len(findings), "unsupported_count": 0, "result_digest": hashlib.sha256(json.dumps([f.__dict__ for f in findings],sort_keys=True).encode()).hexdigest()}
            c.execute("INSERT INTO events VALUES(?,?,?,?,?,?)", (tenant,str(uuid.uuid4()),"analysis.completed",aid,json.dumps(payload),now()))

    def findings(self, tenant, aid):
        with self.conn() as c: return c.execute("SELECT * FROM findings WHERE tenant_id=? AND analysis_id=? ORDER BY rowid", (tenant,aid)).fetchall()

    def pending(self):
        with self.conn() as c: return c.execute("SELECT * FROM analyses WHERE status='PENDING'").fetchall()
