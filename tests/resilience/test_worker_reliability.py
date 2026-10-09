from concurrent.futures import ThreadPoolExecutor

from apishield_agent.domain.analysis import Finding
from apishield_agent.infrastructure.store import REPOSITORY, TENANT, USER, Store

BASE = "a" * 40
HEAD = "b" * 40
FINDING = Finding("REQUIRED_RESPONSE_FIELD_ADDED", "BREAKING", "after:/paths/get:required/id", "e" * 64)


def seeded_store(tmp_path):
    store = Store(str(tmp_path / "reliability.sqlite"))
    store.seed_demo("before.yaml", "after.yaml")
    return store


def submit(store, key, head=HEAD):
    return store.create_analysis(TENANT, USER, REPOSITORY, BASE, head, "profile", key, f"request:{head}")


def test_submit_is_idempotent_under_concurrent_retries(tmp_path):
    store = seeded_store(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(lambda _: submit(store, "reliable-submit-key-0001"), range(8)))
    assert {row["id"] for row in rows} == {rows[0]["id"]}
    with store.conn() as db:
        assert db.execute("SELECT COUNT(*) FROM analyses").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM idempotency").fetchone()[0] == 1


def test_lease_claim_is_atomic_and_only_one_worker_owns_each_job(tmp_path):
    store = seeded_store(tmp_path)
    submit(store, "atomic-lease-key-00001")
    submit(store, "atomic-lease-key-00002", "c" * 40)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claimed = [row for row in pool.map(lambda _: store.claim_pending(), range(2)) if row]
    assert len(claimed) == 2
    assert len({row["id"] for row in claimed}) == 2
    assert all(row["status"] == "RUNNING" and row["lease_token"] for row in claimed)


def test_stale_lease_fences_late_completion(tmp_path):
    store = seeded_store(tmp_path)
    row = submit(store, "stale-fence-key-0001")
    claimed = store.claim_pending(lease_seconds=30)
    assert claimed["id"] == row["id"]
    with store.lock, store.conn() as db:
        db.execute("UPDATE analyses SET lease_until='2000-01-01T00:00:00Z' WHERE tenant_id=? AND id=?", (TENANT, row["id"]))
    assert store.claim_pending() is None
    assert store.get_analysis(TENANT, row["id"])["status"] == "FAILED_TERMINAL"
    assert store.finish(TENANT, row["id"], [FINDING], claimed["lease_token"]) is False
    with store.conn() as db:
        assert db.execute("SELECT COUNT(*) FROM events WHERE aggregate_id=?", (row["id"],)).fetchone()[0] == 0


def test_worker_failure_retries_then_becomes_terminal(tmp_path):
    store = seeded_store(tmp_path)
    row = submit(store, "retry-terminal-key-0001")
    for attempt in range(1, 4):
        claimed = store.claim_pending()
        assert claimed["attempt_count"] == attempt
        assert store.fail(TENANT, row["id"], "SYNTHETIC_PROVIDER_FAILURE", claimed["lease_token"], max_attempts=3)
        status = store.get_analysis(TENANT, row["id"])
        if attempt < 3:
            assert status["status"] == "PENDING"
        else:
            assert status["status"] == "FAILED_TERMINAL"
            assert status["last_error_code"] == "SYNTHETIC_PROVIDER_FAILURE"
    assert store.claim_pending() is None


def test_completion_and_event_are_duplicate_safe(tmp_path):
    store = seeded_store(tmp_path)
    row = submit(store, "duplicate-completion-key-0001")
    claimed = store.claim_pending()
    assert store.finish(TENANT, row["id"], [FINDING], claimed["lease_token"])
    assert store.finish(TENANT, row["id"], [FINDING], claimed["lease_token"]) is False
    assert store.finding_count(TENANT, row["id"]) == 1
    with store.conn() as db:
        assert db.execute("SELECT COUNT(*) FROM events WHERE aggregate_id=? AND event_type='analysis.completed'", (row["id"],)).fetchone()[0] == 1


def test_artifact_digest_and_size_errors_are_terminal_rejections(tmp_path):
    store = seeded_store(tmp_path)
    artifact = store.create_artifact(TENANT, "contract", "contract.yaml", "application/yaml", "a" * 64, 12)
    rejected, error = store.commit_artifact(TENANT, artifact["id"], "b" * 64, 12, "generation-1")
    assert error == "DIGEST_MISMATCH"
    assert rejected["status"] == "REJECTED"
    assert rejected["rejected_reason"] == "DIGEST_OR_SIZE_MISMATCH"
    again, second_error = store.commit_artifact(TENANT, artifact["id"], "a" * 64, 12, "generation-1")
    assert second_error == "INVALID_ARTIFACT_STATE"
    assert again["status"] == "REJECTED"
