"""Verified GitHub App webhook intake with a separate least-privilege store."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import psycopg

MAX_WEBHOOK_BYTES = 1024 * 1024
MAX_WEBHOOK_DEPTH = 64
MAX_WEBHOOK_NODES = 50000
SIGNATURE = re.compile(r"^sha256=([0-9a-f]{64})$")
SUPPORTED_EVENTS = {"installation", "ping"}


class WebhookRejected(ValueError):
    def __init__(self, code: str, detail: str, status: int = 400):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status = status


@dataclass(frozen=True)
class VerifiedWebhook:
    delivery_id: str
    event: str
    payload: dict
    payload_sha256: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def verify_webhook(secret: str, signature: str | None, delivery: str | None, event: str | None, body: bytes) -> VerifiedWebhook:
    if len(secret.encode()) < 32:
        raise WebhookRejected("WEBHOOK_NOT_CONFIGURED", "A webhook secret of at least 32 bytes is required", 503)
    if len(body) > MAX_WEBHOOK_BYTES:
        raise WebhookRejected("WEBHOOK_TOO_LARGE", "Webhook payload exceeds 1 MiB", 413)
    match = SIGNATURE.fullmatch(signature or "")
    if not match:
        raise WebhookRejected("INVALID_WEBHOOK_SIGNATURE", "A sha256 webhook signature is required", 401)
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, match.group(1)):
        raise WebhookRejected("INVALID_WEBHOOK_SIGNATURE", "Webhook signature verification failed", 401)
    try:
        delivery_id = str(UUID(delivery or ""))
    except ValueError as error:
        raise WebhookRejected("INVALID_WEBHOOK_DELIVERY", "X-GitHub-Delivery must be a UUID") from error
    if event not in SUPPORTED_EVENTS:
        raise WebhookRejected("UNSUPPORTED_WEBHOOK_EVENT", "Webhook event is not accepted", 422)
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise WebhookRejected("INVALID_WEBHOOK_JSON", "Duplicate webhook JSON keys are forbidden", 422)
            result[key] = value
        return result

    def finite_numbers(_value):
        raise WebhookRejected("INVALID_WEBHOOK_JSON", "Non-finite webhook JSON numbers are forbidden", 422)

    try:
        payload = json.loads(body, object_pairs_hook=unique_keys, parse_constant=finite_numbers)
    except WebhookRejected:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise WebhookRejected("INVALID_WEBHOOK_JSON", "Webhook body must be valid bounded JSON", 422) from error
    if not isinstance(payload, dict):
        raise WebhookRejected("INVALID_WEBHOOK_JSON", "Webhook body must be a JSON object")
    # A syntactically valid JSON document can still have excessive depth or
    # complexity. Python's parser limit is runtime-dependent, so enforce the
    # same bounded budget across CI and production before changing any state.
    pending = [(payload, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_WEBHOOK_DEPTH or nodes > MAX_WEBHOOK_NODES:
            raise WebhookRejected("INVALID_WEBHOOK_JSON", "Webhook structure budget exceeded", 422)
        if isinstance(item, dict):
            pending.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            pending.extend((value, depth + 1) for value in item)
    return VerifiedWebhook(delivery_id, event, payload, hashlib.sha256(body).hexdigest())


def _installation_projection(event: VerifiedWebhook) -> tuple[int, str] | None:
    if event.event == "ping":
        return None
    installation = event.payload.get("installation")
    action = event.payload.get("action")
    if not isinstance(installation, dict) or type(installation.get("id")) is not int or not (0 < installation["id"] <= 2**63 - 1):
        raise WebhookRejected("INVALID_INSTALLATION_EVENT", "Installation event requires a positive integer installation.id", 422)
    states = {"created": "ACTIVE", "new_permissions_accepted": "ACTIVE", "suspend": "SUSPENDED", "unsuspend": "ACTIVE", "deleted": "DELETED"}
    if not isinstance(action, str) or action not in states:
        raise WebhookRejected("UNSUPPORTED_INSTALLATION_ACTION", "Installation action is not accepted", 422)
    return installation["id"], states[action]


class SQLiteWebhookInbox:
    """Development/test adapter. Production uses the separate PostgreSQL role."""

    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with sqlite3.connect(path) as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS github_webhook_deliveries(delivery_id TEXT PRIMARY KEY,event TEXT NOT NULL,payload_sha256 TEXT NOT NULL,received_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS github_installation_states(installation_id INTEGER PRIMARY KEY,state TEXT NOT NULL,updated_at TEXT NOT NULL);
            """)

    def apply(self, webhook: VerifiedWebhook) -> tuple[bool, str | None]:
        projection = _installation_projection(webhook)
        with sqlite3.connect(self.path) as db:
            inserted = db.execute("INSERT OR IGNORE INTO github_webhook_deliveries VALUES(?,?,?,?)", (webhook.delivery_id, webhook.event, webhook.payload_sha256, _now())).rowcount == 1
            if not inserted:
                existing = db.execute("SELECT event,payload_sha256 FROM github_webhook_deliveries WHERE delivery_id=?", (webhook.delivery_id,)).fetchone()
                if existing != (webhook.event, webhook.payload_sha256):
                    raise WebhookRejected("WEBHOOK_REPLAY_CONFLICT", "Delivery UUID was reused with different content", 409)
                state = db.execute("SELECT state FROM github_installation_states WHERE installation_id=?", (projection[0],)).fetchone() if projection else None
                return False, state[0] if state else None
            if projection:
                installation_id, state = projection
                db.execute("INSERT INTO github_installation_states VALUES(?,?,?) ON CONFLICT(installation_id) DO UPDATE SET state=excluded.state,updated_at=excluded.updated_at", (installation_id, state, _now()))
            return True, projection[1] if projection else None


class PostgresWebhookInbox:
    """Webhook adapter using only the dedicated NOLOGIN group role."""

    ROLE = "fw_apishield_webhook"

    def __init__(self, dsn: str):
        self.dsn = dsn
        with psycopg.connect(dsn) as db:
            attrs = db.execute("SELECT rolsuper,rolbypassrls,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=current_user").fetchone()
            if any(attrs):
                raise ValueError("Webhook login must be least privilege")
            if not db.execute("SELECT pg_has_role(current_user,%s,'MEMBER')", (self.ROLE,)).fetchone()[0]:
                raise ValueError("Webhook login must be a member of fw_apishield_webhook")
            group = db.execute("SELECT rolsuper,rolbypassrls,rolcanlogin,rolcreaterole,rolcreatedb FROM pg_roles WHERE rolname=%s", (self.ROLE,)).fetchone()
            if not group or any(group):
                raise ValueError("Webhook group role must be NOLOGIN and least privilege")
            if db.execute("SELECT 1 FROM pg_tables WHERE schemaname=current_schema() AND tableowner IN (current_user,%s) AND tablename IN ('github_webhook_deliveries','github_installation_states','repositories')", (self.ROLE,)).fetchone():
                raise ValueError("Webhook role must not own product tables")

    def apply(self, webhook: VerifiedWebhook) -> tuple[bool, str | None]:
        projection = _installation_projection(webhook)
        with psycopg.connect(self.dsn) as db:
            db.execute("SET LOCAL ROLE fw_apishield_webhook")
            row = db.execute("INSERT INTO github_webhook_deliveries(delivery_id,event,payload_sha256) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING RETURNING delivery_id", (webhook.delivery_id, webhook.event, webhook.payload_sha256)).fetchone()
            if not row:
                existing = db.execute("SELECT event,payload_sha256 FROM github_webhook_deliveries WHERE delivery_id=%s", (webhook.delivery_id,)).fetchone()
                if existing != (webhook.event, webhook.payload_sha256):
                    raise WebhookRejected("WEBHOOK_REPLAY_CONFLICT", "Delivery UUID was reused with different content", 409)
                state = db.execute("SELECT state FROM github_installation_states WHERE installation_id=%s", (projection[0],)).fetchone() if projection else None
                return False, state[0] if state else None
            if projection:
                installation_id, state = projection
                db.execute("INSERT INTO github_installation_states(installation_id,state) VALUES(%s,%s) ON CONFLICT(installation_id) DO UPDATE SET state=excluded.state,updated_at=now()", (installation_id, state))
                if state in {"SUSPENDED", "DELETED"}:
                    db.execute("UPDATE repositories SET permission_state='REVOKED' WHERE installation_id=%s", (installation_id,))
            return True, projection[1] if projection else None
