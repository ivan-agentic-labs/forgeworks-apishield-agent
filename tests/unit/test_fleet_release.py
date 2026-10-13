import copy
import importlib.util
from pathlib import Path
import pytest

path = Path(__file__).resolve().parents[2] / 'scripts/verify_fleet_release.py'
spec = importlib.util.spec_from_file_location('fleet_release', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

@pytest.fixture
def plan():
    return {'schema': 'forgeworks-fleet-staging-candidate-v1', 'environment': 'staging',
            'products': [{'product': p, 'revision_sha': 'a'*40,
                          'runtime_manifest': {'profile': 'forgeworks-runtime-manifest-v1', 'file_count': 1, 'sha256': 'b'*64}}
                         for p in module.PRODUCTS]}


def transport(plan):
    records = module.validate_plan(plan)
    def request(product, path):
        if path in {'/healthz', '/readyz'}:
            return 200, {'status': 'ok' if path == '/healthz' else 'ready'}
        if path == '/versionz':
            return 200, {**records[product], 'environment': 'staging'}
        return 401, None
    return request


def test_exact_five_product_fleet_passes_with_scoped_limits(plan):
    result = module.verify_fleet(plan, transport(plan))
    assert result['result'] == 'PASS'
    assert len(result['products']) == 5
    assert result['production_acceptance'] == 'NOT_ACCEPTED'


@pytest.mark.parametrize('product', module.PRODUCTS)
def test_one_healthy_but_old_release_fails_entire_fleet(plan, product):
    correct = transport(plan)
    def drift(name, path):
        status, body = correct(name, path)
        if name == product and path == '/versionz':
            body = {**body, 'revision_sha': 'c'*40}
        return status, body
    report = module.verify_fleet(plan, drift)
    assert report['result'] == 'FAIL'
    assert sum(p['result'] == 'FAIL' for p in report['products']) == 1
    assert next(p for p in report['products'] if p['product'] == product)['code'] == 'FLEET_IDENTITY_MISMATCH'


@pytest.mark.parametrize('field,value', [('environment','production'), ('revision_sha','main'), ('runtime_manifest',{})])
def test_unreviewable_plan_is_rejected_before_network(plan, field, value):
    if field == 'environment': plan[field] = value
    else: plan['products'][0][field] = value
    with pytest.raises(ValueError): module.verify_fleet(plan, lambda *args: pytest.fail('Network must not be called'))


@pytest.mark.parametrize('profile', ['missing', 'duplicate', 'unknown'])
def test_incomplete_or_duplicate_products_are_rejected(plan, profile):
    if profile == 'missing': plan['products'].pop()
    elif profile == 'duplicate': plan['products'][0] = copy.deepcopy(plan['products'][1])
    else: plan['products'][0]['product'] = 'sealangel-work'
    with pytest.raises(ValueError): module.validate_plan(plan)


@pytest.mark.parametrize('path', ['/metricsz', module.BUSINESS_PATHS['apishield-agent']])
def test_open_or_missing_protected_endpoint_is_not_a_pass(plan, path):
    correct = transport(plan)
    for status in [200, 404]:
        def broken(product, target):
            return (status, {}) if product == 'apishield-agent' and target == path else correct(product, target)
        assert module.verify_fleet(plan, broken)['result'] == 'FAIL'


def test_network_error_is_reported_without_sensitive_text(plan):
    def failure(*args): raise OSError('password=never-print-me')
    result = module.verify_fleet(plan, failure)
    assert result['result'] == 'FAIL'
    assert 'never-print-me' not in str(result)


def test_unknown_target_is_rejected_without_network():
    with pytest.raises(ValueError): module.fetch('sealangel-work', '/healthz')
    with pytest.raises(ValueError): module.fetch('apishield-agent', '//external.invalid')


@pytest.mark.parametrize('counter', [True, 1.0])
def test_observed_manifest_types_must_match_exactly(plan, counter):
    correct = transport(plan)
    def mistyped(product, path):
        status, body = correct(product, path)
        if product == 'apishield-agent' and path == '/versionz':
            body = copy.deepcopy(body)
            body['runtime_manifest']['file_count'] = counter
        return status, body
    assert module.verify_fleet(plan, mistyped)['result'] == 'FAIL'


def test_untrusted_error_code_prefix_cannot_expose_sensitive_data(plan):
    def failure(*args): raise ValueError('FLEET_password=never-print-me')
    assert 'never-print-me' not in str(module.verify_fleet(plan, failure))
