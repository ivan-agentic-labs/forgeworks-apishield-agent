"""Read-only release acceptance of five fixed ForgeWorks staging origins.

A healthy old deployment must never satisfy a new fleet release candidate.
This proves public identity/boundaries only, never authenticated business acceptance.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

PRODUCTS = ('apishield-agent', 'accessfix-ai', 'specforge-ai', 'agenttest-lab', 'datareconcile-ai')
FAKE_ID = '00000000-0000-0000-0000-000000000001'
BUSINESS_PATHS = {
    'apishield-agent': f'/v1/analyses/{FAKE_ID}',
    'accessfix-ai': f'/v1/scans/{FAKE_ID}/findings',
    'specforge-ai': f'/v1/spec-revisions/{FAKE_ID}/openapi',
    'agenttest-lab': f'/v1/evaluation-runs/{FAKE_ID}/cases',
    'datareconcile-ai': f'/v1/reports/{FAKE_ID}/signature',
}
MAX_PLAN_BYTES = 65536
MAX_RESPONSE_BYTES = 4096


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('DUPLICATE_JSON_KEY')
        value[key] = item
    return value


def validate_plan(plan):
    if (not isinstance(plan, dict) or set(plan) != {'schema', 'environment', 'products'}
            or plan['schema'] != 'forgeworks-fleet-staging-candidate-v1'
            or plan['environment'] != 'staging' or not isinstance(plan['products'], list)
            or len(plan['products']) != len(PRODUCTS)):
        raise ValueError('FLEET_PLAN_INVALID')
    records = {}
    for item in plan['products']:
        if not isinstance(item, dict) or set(item) != {'product', 'revision_sha', 'runtime_manifest'}:
            raise ValueError('FLEET_PRODUCT_INVALID')
        name = item['product']
        if not isinstance(name, str) or name not in PRODUCTS or name in records:
            raise ValueError('FLEET_PRODUCT_INVALID')
        if not isinstance(item['revision_sha'], str) or not re.fullmatch('[0-9a-f]{40}', item['revision_sha']):
            raise ValueError('FLEET_REVISION_INVALID')
        manifest = item['runtime_manifest']
        if (not isinstance(manifest, dict) or set(manifest) != {'profile', 'file_count', 'sha256'}
                or manifest['profile'] != 'forgeworks-runtime-manifest-v1'
                or type(manifest['file_count']) is not int or not 1 <= manifest['file_count'] <= 256
                or not isinstance(manifest['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', manifest['sha256'])):
            raise ValueError('FLEET_MANIFEST_INVALID')
        records[name] = item
    if set(records) != set(PRODUCTS):
        raise ValueError('FLEET_INCOMPLETE')
    return records


def fetch(product, path):
    if product not in PRODUCTS or path not in {'/healthz', '/readyz', '/versionz', '/metricsz', BUSINESS_PATHS[product]}:
        raise ValueError('FLEET_TARGET_FORBIDDEN')
    origin = f'https://{product}-staging.up.railway.app'
    request = Request(origin + path, headers={'Accept': 'application/json',
                      'User-Agent': 'ForgeWorks-Fleet-Release-Proof/1.0'}, method='GET')
    try:
        response = build_opener(NoRedirect()).open(request, timeout=15)
    except HTTPError as error:
        response = error
    with response:
        status, raw = response.code, response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError('FLEET_RESPONSE_BUDGET')
    if status != 200:
        return status, None
    return status, json.loads(raw, object_pairs_hook=unique_object)


def verify_product(record, request=fetch):
    product = record['product']
    for path, state in [('/healthz', 'ok'), ('/readyz', 'ready')]:
        status, body = request(product, path)
        if status != 200 or not isinstance(body, dict) or body.get('status') != state:
            raise ValueError('FLEET_HEALTH_FAILED')
    status, identity = request(product, '/versionz')
    expected = {'product': product, 'environment': 'staging',
                'revision_sha': record['revision_sha'], 'runtime_manifest': record['runtime_manifest']}
    if (status != 200 or not isinstance(identity, dict)
            or json.dumps(identity, sort_keys=True, separators=(',', ':')) !=
               json.dumps(expected, sort_keys=True, separators=(',', ':'))):
        raise ValueError('FLEET_IDENTITY_MISMATCH')
    for path in ['/metricsz', BUSINESS_PATHS[product]]:
        if request(product, path)[0] != 401:
            raise ValueError('FLEET_ANONYMOUS_BOUNDARY_FAILED')
    return {'product': product, 'result': 'PASS', 'revision_sha': record['revision_sha'],
            'runtime_manifest': record['runtime_manifest']}


def verify_fleet(plan, request=fetch):
    records = validate_plan(plan)
    def check(product):
        try:
            return verify_product(records[product], request)
        except Exception as error:
            # Exception strings may contain URLs or other network content.
            public_codes = {'FLEET_HEALTH_FAILED', 'FLEET_IDENTITY_MISMATCH',
                            'FLEET_ANONYMOUS_BOUNDARY_FAILED', 'FLEET_RESPONSE_BUDGET'}
            code = str(error) if type(error) is ValueError and str(error) in public_codes else type(error).__name__
            return {'product': product, 'result': 'FAIL', 'code': code}
    with ThreadPoolExecutor(max_workers=5) as executor:
        checks = list(executor.map(check, PRODUCTS))
    return {'schema': 'forgeworks-fleet-public-release-proof-v1',
            'verified_at': datetime.now(timezone.utc).isoformat(), 'environment': 'staging',
            'result': 'PASS' if all(item['result'] == 'PASS' for item in checks) else 'FAIL',
            'products': checks, 'production_acceptance': 'NOT_ACCEPTED',
            'limits': 'Exact public release identity and anonymous boundaries only; authenticated business, SLO and DR acceptance remain open.'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan', type=Path, default=Path(__file__).resolve().parents[1] / 'ops/releases/fleet-staging-candidate.json')
    args = parser.parse_args()
    if args.plan.is_symlink():
        raise ValueError('FLEET_PLAN_UNSAFE')
    with args.plan.open('rb') as handle:
        raw = handle.read(MAX_PLAN_BYTES + 1)
    if len(raw) > MAX_PLAN_BYTES:
        raise ValueError('FLEET_PLAN_BUDGET')
    report = verify_fleet(json.loads(raw, object_pairs_hook=unique_object))
    print(json.dumps(report, sort_keys=True))
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
