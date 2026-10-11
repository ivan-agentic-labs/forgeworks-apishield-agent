"""Signed deliveries are unique, but stale ones must not resurrect access."""
from uuid import uuid4
import hashlib
import json

from apishield_agent.infrastructure.github_webhooks import (
    SQLiteWebhookInbox, VerifiedWebhook,
)


def test_unique_delayed_deliveries_preserve_revocation(tmp_path):
    store = SQLiteWebhookInbox(str(tmp_path / "inbox.sqlite"))
    sequence = [
        ("suspend", "SUSPENDED"),
        ("created", "SUSPENDED"),
        ("new_permissions_accepted", "SUSPENDED"),
        ("unsuspend", "ACTIVE"),
        ("deleted", "DELETED"),
        ("created", "DELETED"),
        ("unsuspend", "DELETED"),
    ]
    for action, expected in sequence:
        payload = {"action": action, "installation": {"id": 71}}
        body = json.dumps(payload, sort_keys=True).encode()
        incoming = VerifiedWebhook(str(uuid4()), "installation", payload, hashlib.sha256(body).hexdigest())
        assert store.apply(incoming) == (True, expected)
        assert store.apply(incoming) == (False, expected)
