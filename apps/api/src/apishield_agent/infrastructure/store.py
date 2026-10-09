from __future__ import annotations

import hashlib
import difflib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

TENANT = "00000000-0000-0000-0000-000000000001"
USER = "00000000-0000-0000-0000-000000000010"
REPOSITORY = "11111111-1111-1111-1111-111111111111"


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def later(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def stable_uuid(value: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"apishield:{value}"))


class Store:
    """SQLite development adapter; production PostgreSQL/RLS remains a gate."""

    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._init_schema()

    def conn(self, tenant=None):
        c = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def _init_schema(self):
        with self.lock, self.conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, slug TEXT UNIQUE NOT NULL, status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS memberships (tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY (tenant_id,user_id));
            CREATE TABLE IF NOT EXISTS repositories (tenant_id TEXT NOT NULL, id TEXT NOT NULL, installation_id INTEGER NOT NULL, default_branch TEXT NOT NULL, permission_state TEXT NOT NULL, before_contract TEXT, after_contract TEXT, PRIMARY KEY (tenant_id,id));
            CREATE TABLE IF NOT EXISTS analyses (tenant_id TEXT NOT NULL, id TEXT NOT NULL, job_id TEXT NOT NULL, repository_id TEXT NOT NULL, base_sha TEXT NOT NULL, head_sha TEXT NOT NULL, capability_profile TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT, version INTEGER NOT NULL DEFAULT 1, attempt_count INTEGER NOT NULL DEFAULT 0, last_error_code TEXT, lease_until TEXT, lease_token TEXT, result_digest TEXT, PRIMARY KEY (tenant_id,id), UNIQUE (tenant_id,job_id));
            CREATE TABLE IF NOT EXISTS findings (tenant_id TEXT NOT NULL, id TEXT NOT NULL, analysis_id TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL, openapi_pointer TEXT NOT NULL, evidence_digest TEXT NOT NULL, coverage TEXT NOT NULL, UNIQUE (tenant_id,analysis_id,rule_id,openapi_pointer));
            CREATE TABLE IF NOT EXISTS idempotency (tenant_id TEXT NOT NULL, actor TEXT NOT NULL, key TEXT NOT NULL, request_sha TEXT NOT NULL, analysis_id TEXT NOT NULL, PRIMARY KEY (tenant_id,actor,key));
            CREATE TABLE IF NOT EXISTS commands (tenant_id TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, key TEXT NOT NULL, request_sha TEXT NOT NULL, resource_id TEXT NOT NULL, PRIMARY KEY (tenant_id,actor,action,key));
            CREATE TABLE IF NOT EXISTS events (tenant_id TEXT NOT NULL, id TEXT PRIMARY KEY, event_type TEXT NOT NULL, aggregate_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE (tenant_id,event_type,aggregate_id));
            CREATE TABLE IF NOT EXISTS artifacts (tenant_id TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL, filename TEXT NOT NULL, declared_media_type TEXT, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, status TEXT NOT NULL, object_generation TEXT, rejected_reason TEXT, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, PRIMARY KEY (tenant_id,id));
            CREATE TABLE IF NOT EXISTS proposals (tenant_id TEXT NOT NULL, id TEXT NOT NULL, analysis_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, base_sha TEXT NOT NULL, patch_sha256 TEXT NOT NULL, sandbox_status TEXT NOT NULL, approval_status TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (tenant_id,id));
            CREATE TABLE IF NOT EXISTS proposal_patch_content (tenant_id TEXT NOT NULL, id TEXT NOT NULL, patch_text TEXT NOT NULL, PRIMARY KEY (tenant_id,id));
            CREATE TABLE IF NOT EXISTS approvals (tenant_id TEXT NOT NULL, id TEXT NOT NULL, proposal_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, patch_sha256 TEXT NOT NULL, base_sha TEXT NOT NULL, reviewer_id TEXT NOT NULL, expires_at TEXT NOT NULL, PRIMARY KEY (tenant_id,id));
            CREATE TABLE IF NOT EXISTS pull_requests (tenant_id TEXT NOT NULL, id TEXT NOT NULL, proposal_id TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, github_pr_node_id TEXT NOT NULL, draft INTEGER NOT NULL, external_effect_key TEXT NOT NULL, PRIMARY KEY (tenant_id,id));
            """)
            for sql in ("ALTER TABLE analyses ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0", "ALTER TABLE analyses ADD COLUMN last_error_code TEXT", "ALTER TABLE analyses ADD COLUMN lease_until TEXT", "ALTER TABLE analyses ADD COLUMN lease_token TEXT", "ALTER TABLE analyses ADD COLUMN result_digest TEXT"):
                try:
                    c.execute(sql)
                except sqlite3.OperationalError:
                    pass

    def seed_demo(self, before: str, after: str):
        with self.lock, self.conn() as c:
            c.execute("INSERT OR IGNORE INTO tenants VALUES (?,?,?)", (TENANT, "synthetic-demo", "ACTIVE"))
            c.execute("INSERT OR IGNORE INTO memberships VALUES (?,?,?,?)", (TENANT, USER, "editor", "ACTIVE"))
            c.execute("INSERT OR REPLACE INTO repositories VALUES (?,?,?,?,?,?,?)", (TENANT, REPOSITORY, 1, "main", "READ", before, after))

    def member(self, tenant, user):
        with self.conn() as c:
            return c.execute("SELECT 1 FROM memberships WHERE tenant_id=? AND user_id=? AND status='ACTIVE'", (tenant, user)).fetchone() is not None

    def get_repo(self, tenant, installation, repo):
        with self.conn() as c:
            return c.execute("SELECT * FROM repositories WHERE tenant_id=? AND installation_id=? AND id=?", (tenant, installation, repo)).fetchone()

    def get_repository(self, tenant, repository_id):
        with self.conn(tenant) as db:
            return db.execute("SELECT * FROM repositories WHERE tenant_id=? AND id=?", (tenant, repository_id)).fetchone()

    def get_idempotent(self, tenant, actor, key):
        with self.conn() as c:
            return c.execute("SELECT * FROM idempotency WHERE tenant_id=? AND actor=? AND key=?", (tenant, actor, key)).fetchone()

    def command(self, tenant, actor, action, key):
        with self.conn() as c:
            return c.execute("SELECT * FROM commands WHERE tenant_id=? AND actor=? AND action=? AND key=?", (tenant, actor, action, key)).fetchone()

    def create_command(self, tenant, actor, action, key, request_sha, resource_id):
        with self.lock, self.conn() as c:
            c.execute("INSERT INTO commands VALUES(?,?,?,?,?,?)", (tenant, actor, action, key, request_sha, resource_id))

    def get_analysis(self, tenant, aid):
        with self.conn() as c:
            return c.execute("SELECT * FROM analyses WHERE tenant_id=? AND id=?", (tenant, aid)).fetchone()

    def create_analysis(self, tenant, actor, repo, base, head, profile, idem_key, request_sha):
        aid, jid = str(uuid.uuid4()), str(uuid.uuid4())
        with self.lock, self.conn() as c:
            existing = c.execute("SELECT * FROM idempotency WHERE tenant_id=? AND actor=? AND key=?", (tenant, actor, idem_key)).fetchone()
            if existing:
                if existing["request_sha"] != request_sha:
                    raise ValueError("IDEMPOTENCY_CONFLICT")
                return self.get_analysis(tenant, existing["analysis_id"])
            c.execute("INSERT INTO analyses(tenant_id,id,job_id,repository_id,base_sha,head_sha,capability_profile,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)", (tenant, aid, jid, repo, base, head, profile, "PENDING", now()))
            try:
                c.execute("INSERT INTO idempotency VALUES(?,?,?,?,?)", (tenant, actor, idem_key, request_sha, aid))
            except sqlite3.IntegrityError:
                # A concurrent submit can win between the read and insert. The
                # unique command record is the source of truth; return its job
                # rather than exposing a duplicate analysis.
                c.execute("DELETE FROM analyses WHERE tenant_id=? AND id=?", (tenant, aid))
                existing = c.execute("SELECT * FROM idempotency WHERE tenant_id=? AND actor=? AND key=?", (tenant, actor, idem_key)).fetchone()
                return self.get_analysis(tenant, existing["analysis_id"]) if existing else None
        return self.get_analysis(tenant, aid)

    def claim_pending(self, lease_seconds=30):
        with self.lock, self.conn() as c:
            c.execute("UPDATE analyses SET status='FAILED_TERMINAL', last_error_code='STALE_LEASE', version=version+1, lease_until=NULL WHERE status='RUNNING' AND lease_until IS NOT NULL AND lease_until < ?", (now(),))
            row = c.execute("SELECT * FROM analyses WHERE status='PENDING' ORDER BY created_at LIMIT 1").fetchone()
            if not row:
                return None
            lease_token = str(uuid.uuid4())
            updated = c.execute("UPDATE analyses SET status='RUNNING', attempt_count=attempt_count+1, version=version+1, lease_until=?, lease_token=? WHERE tenant_id=? AND id=? AND status='PENDING'", (later(lease_seconds), lease_token, row['tenant_id'], row['id']))
            return c.execute("SELECT * FROM analyses WHERE tenant_id=? AND id=?", (row['tenant_id'], row['id'])).fetchone() if updated.rowcount else None

    def pending(self):
        with self.conn() as c:
            return c.execute("SELECT * FROM analyses WHERE status='PENDING' ORDER BY created_at").fetchall()

    def finish(self, tenant, aid, findings, lease_token=None):
        digest = hashlib.sha256(json.dumps([f.__dict__ for f in findings], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.lock, self.conn() as c:
            row = c.execute("SELECT status, lease_token FROM analyses WHERE tenant_id=? AND id=?", (tenant, aid)).fetchone()
            if not row or row['status'] in {'SUCCEEDED', 'FAILED_TERMINAL', 'CANCELLED'}:
                return False
            if lease_token is not None and (row['status'] != 'RUNNING' or row['lease_token'] != lease_token):
                return False
            for f in findings:
                c.execute("INSERT OR IGNORE INTO findings VALUES(?,?,?,?,?,?,?,?)", (tenant, str(uuid.uuid4()), aid, f.rule_id, f.severity, f.pointer, f.evidence_digest, f.coverage))
            c.execute("UPDATE analyses SET status='SUCCEEDED', completed_at=?, version=version+1, lease_until=NULL, lease_token=NULL, result_digest=? WHERE tenant_id=? AND id=? AND status IN ('PENDING','RUNNING')", (now(), digest, tenant, aid))
            payload = {'analysis_id': aid, 'finding_count': len(findings), 'unsupported_count': 0, 'result_digest': digest}
            c.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?)", (tenant, stable_uuid(f'analysis.completed:{tenant}:{aid}'), 'analysis.completed', aid, json.dumps(payload, sort_keys=True), now()))
            return True

    def fail(self, tenant, aid, error_code, lease_token=None, max_attempts=3):
        """Release a worker lease for retry, or make the job terminal.

        The lease token makes a late worker completion/failure a no-op after a
        lease has been fenced. Retries are explicit and bounded.
        """
        with self.lock, self.conn() as c:
            row = c.execute("SELECT status, lease_token, attempt_count FROM analyses WHERE tenant_id=? AND id=?", (tenant, aid)).fetchone()
            if not row or row["status"] != "RUNNING" or (lease_token is not None and row["lease_token"] != lease_token):
                return False
            terminal = row["attempt_count"] >= max_attempts
            status = "FAILED_TERMINAL" if terminal else "PENDING"
            c.execute("UPDATE analyses SET status=?, last_error_code=?, version=version+1, lease_until=NULL, lease_token=NULL WHERE tenant_id=? AND id=? AND status='RUNNING' AND lease_token=?", (status, error_code, tenant, aid, row["lease_token"]))
            return True

    def findings(self, tenant, aid, offset=0, limit=50):
        with self.conn() as c:
            return c.execute("SELECT * FROM findings WHERE tenant_id=? AND analysis_id=? ORDER BY rowid LIMIT ? OFFSET ?", (tenant, aid, limit, offset)).fetchall()

    def finding_count(self, tenant, aid):
        with self.conn() as c:
            return int(c.execute("SELECT COUNT(*) FROM findings WHERE tenant_id=? AND analysis_id=?", (tenant, aid)).fetchone()[0])

    def create_artifact(self, tenant, kind, filename, media_type, sha256, size_bytes):
        aid = str(uuid.uuid4())
        with self.lock, self.conn() as c:
            c.execute("INSERT INTO artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (tenant, aid, kind, filename, media_type, sha256, size_bytes, 'INTENT_ISSUED', None, None, now(), later(900)))
        return self.artifact(tenant, aid)

    def artifact(self, tenant, aid):
        with self.conn() as c:
            return c.execute("SELECT * FROM artifacts WHERE tenant_id=? AND id=?", (tenant, aid)).fetchone()

    def commit_artifact(self, tenant, aid, sha256, size_bytes, generation):
        with self.lock, self.conn() as c:
            row = c.execute("SELECT * FROM artifacts WHERE tenant_id=? AND id=?", (tenant, aid)).fetchone()
            if not row:
                return None, 'NOT_FOUND'
            if row['sha256'] != sha256 or row['size_bytes'] != size_bytes:
                c.execute("UPDATE artifacts SET status='REJECTED', rejected_reason='DIGEST_OR_SIZE_MISMATCH' WHERE tenant_id=? AND id=?", (tenant, aid))
                return c.execute("SELECT * FROM artifacts WHERE tenant_id=? AND id=?", (tenant, aid)).fetchone(), 'DIGEST_MISMATCH'
            if row['status'] == 'AVAILABLE' and row['object_generation'] == generation:
                return row, None
            if row['status'] != 'INTENT_ISSUED':
                return row, 'INVALID_ARTIFACT_STATE'
            c.execute("UPDATE artifacts SET status='AVAILABLE', object_generation=? WHERE tenant_id=? AND id=?", (generation, tenant, aid))
            return c.execute("SELECT * FROM artifacts WHERE tenant_id=? AND id=?", (tenant, aid)).fetchone(), None

    def create_proposal(self, tenant, analysis_id, target_language):
        analysis = self.get_analysis(tenant, analysis_id)
        if not analysis:
            return None
        repo = self.get_repository(tenant, analysis["repository_id"])
        if not repo:
            return None
        before = Path(repo["before_contract"]).read_text(encoding="utf-8")
        after = Path(repo["after_contract"]).read_text(encoding="utf-8")
        if max(len(before.encode()), len(after.encode())) > 2 * 1024 * 1024:
            raise ValueError("CONTRACT_TOO_LARGE")
        patch_text = "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True), fromfile="contracts/before.yaml", tofile="contracts/after.yaml"))
        patch = hashlib.sha256(patch_text.encode()).hexdigest()
        pid = str(uuid.uuid4())
        with self.lock, self.conn() as c:
            c.execute("INSERT INTO proposals VALUES(?,?,?,?,?,?,?,?,?,?)", (tenant, pid, analysis_id, 'READY', now(), analysis['base_sha'], patch, 'NOT_RUN', 'PENDING', 1))
            c.execute("INSERT INTO proposal_patch_content VALUES(?,?,?)", (tenant, pid, patch_text))
        return self.proposal(tenant, pid)

    def proposal(self, tenant, pid):
        with self.conn() as c:
            return c.execute("SELECT * FROM proposals WHERE tenant_id=? AND id=?", (tenant, pid)).fetchone()

    def proposal_patch(self, tenant, proposal_id):
        with self.conn(tenant) as db:
            return db.execute("SELECT * FROM proposal_patch_content WHERE tenant_id=? AND id=?", (tenant, proposal_id)).fetchone()

    def approve(self, tenant, pid, patch, base, decision, expected_version, reviewer):
        with self.lock, self.conn() as c:
            p = c.execute("SELECT * FROM proposals WHERE tenant_id=? AND id=?", (tenant, pid)).fetchone()
            if not p:
                return None, 'NOT_FOUND'
            if p['version'] != expected_version:
                return p, 'STALE_VERSION'
            if p['patch_sha256'] != patch or p['base_sha'] != base:
                return p, 'STALE_ARTIFACT'
            status = 'APPROVED' if decision == 'approve' else 'REJECTED'
            approval_id, expiry = str(uuid.uuid4()), later(86400)
            c.execute("INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?,?)", (tenant, approval_id, pid, status, now(), patch, base, reviewer, expiry))
            c.execute("UPDATE proposals SET approval_status=?, version=version+1 WHERE tenant_id=? AND id=? AND version=?", (status, tenant, pid, expected_version))
            return c.execute("SELECT * FROM approvals WHERE tenant_id=? AND id=?", (tenant, approval_id)).fetchone(), None

    def approval(self, tenant, aid):
        with self.conn() as c:
            return c.execute("SELECT * FROM approvals WHERE tenant_id=? AND id=?", (tenant, aid)).fetchone()

    def create_pull_request(self, tenant, pid, approval_id, target_branch):
        rid = str(uuid.uuid4())
        effect = f'pull-request:{tenant}:{pid}:{approval_id}:{target_branch}'
        with self.lock, self.conn() as c:
            c.execute("INSERT INTO pull_requests VALUES(?,?,?,?,?,?,?,?)", (tenant, rid, pid, 'BLOCKED_GITHUB_WRITE_DISABLED', now(), '', 1, effect))
        return self.pull_request(tenant, rid)

    def pull_request(self, tenant, rid):
        with self.conn() as c:
            return c.execute("SELECT * FROM pull_requests WHERE tenant_id=? AND id=?", (tenant, rid)).fetchone()

