"""Synthetic transition rules for out-of-order installation events."""
import pytest

from apishield_agent.infrastructure.github_webhooks import _effective_installation_state


@pytest.mark.parametrize("previous, requested, action, result", [
    (None, "ACTIVE", "created", "ACTIVE"),
    (None, "SUSPENDED", "suspend", "SUSPENDED"),
    ("SUSPENDED", "ACTIVE", "created", "SUSPENDED"),
    ("SUSPENDED", "ACTIVE", "new_permissions_accepted", "SUSPENDED"),
    ("SUSPENDED", "ACTIVE", "unsuspend", "ACTIVE"),
    ("DELETED", "ACTIVE", "created", "DELETED"),
    ("DELETED", "ACTIVE", "unsuspend", "DELETED"),
    ("DELETED", "SUSPENDED", "suspend", "DELETED"),
])
def test_installation_transition(previous, requested, action, result):
    assert _effective_installation_state(previous, requested, action) == result
