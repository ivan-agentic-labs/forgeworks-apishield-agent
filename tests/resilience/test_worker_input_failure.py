from apishield_agent.application.analysis_worker import AnalysisWorker
from apishield_agent.infrastructure.store import Store, TENANT, USER, REPOSITORY
from apishield_agent.domain.analysis import deterministic_openapi_diff
import pytest


def test_missing_contract_fails_durable_job_instead_of_empty_success(tmp_path):
    store = Store(str(tmp_path / 'runtime.sqlite'))
    store.seed_demo(str(tmp_path / 'missing-before.yaml'), str(tmp_path / 'missing-after.yaml'))
    row = store.create_analysis(TENANT, USER, REPOSITORY, 'a'*40, 'b'*40, 'fixture', 'missing-input-001', 'digest')
    worker = AnalysisWorker(store)
    assert worker.run_once()
    result = store.get_analysis(TENANT, row['id'])
    assert result['status'] != 'SUCCEEDED'
    assert result['last_error_code'] == 'VALUEERROR'


def test_diff_rejects_non_mapping_contract(tmp_path):
    before, after = tmp_path / 'before.yaml', tmp_path / 'after.yaml'
    before.write_text('- scalar\n')
    after.write_text('paths: {}\n')
    with pytest.raises(ValueError, match='CONTRACT_INPUT_INVALID'):
        deterministic_openapi_diff(str(before), str(after))


def test_evidence_digest_changes_with_source_bytes(tmp_path):
    before, after = tmp_path / 'before.yaml', tmp_path / 'after.yaml'
    before.write_text('paths: {}\n')
    after.write_text('paths:\n  /x:\n    get:\n      responses:\n        "200":\n          content:\n            application/json:\n              schema:\n                required: [id]\n')
    first = deterministic_openapi_diff(str(before), str(after))[0].evidence_digest
    after.write_text(after.read_text() + '# changed source revision\n')
    second = deterministic_openapi_diff(str(before), str(after))[0].evidence_digest
    assert first != second
