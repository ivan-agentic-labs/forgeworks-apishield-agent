"""Real AST subprocess and applicable diff proof; fixed synthetic source only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(os.getenv('APISHIELD_CALLER_CLI_PROOF') != 'yes', reason='Caller package requires its dedicated mandatory CI step')


def manifest(source):
    op = {'operationId':'listItems','responses':{'200':{'description':'List items'}}}
    return {'schema_version':'typescript-fetch-path-v1','base_sha':'a'*40,'head_sha':'b'*40,
        'before':{'openapi':'3.1.0','info':{'title':'API','version':'1'},'paths':{'/old':{'get':op}}},
        'after':{'openapi':'3.1.0','info':{'title':'API','version':'2'},'paths':{'/new':{'get':op}}},
        'sources':[{'path':'src/client.ts','content':source,'sha256':hashlib.sha256(source.encode()).hexdigest()}]}


def invoke(raw):
    return subprocess.run([sys.executable,str(ROOT/'scripts/analyze_typescript_callers.py')],input=raw,capture_output=True,timeout=15)


@pytest.mark.parametrize('ending',['','\n','\r\n'],ids=['missing-final-newline','lf','crlf'])
def test_cli_proposal_diff_is_actually_applicable(tmp_path,ending):
    source = 'fetch("/old");'+ending
    result = invoke(json.dumps(manifest(source)).encode())
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout); proposal = output['proposals'][0]
    assert proposal['patch_sha256'] == hashlib.sha256(proposal['patch_text'].encode()).hexdigest()
    (tmp_path/'src').mkdir(); (tmp_path/'src/client.ts').write_bytes(source.encode())
    patch = tmp_path/'migration.patch'; patch.write_bytes(proposal['patch_text'].encode())
    checked = subprocess.run(['git','apply','--check',str(patch)],cwd=tmp_path,capture_output=True)
    assert checked.returncode == 0, checked.stderr
    applied = subprocess.run(['git','apply',str(patch)],cwd=tmp_path,capture_output=True)
    assert applied.returncode == 0, applied.stderr
    assert hashlib.sha256((tmp_path/'src/client.ts').read_bytes()).hexdigest() == proposal['after_sha256']
    assert (tmp_path/'src/client.ts').read_bytes() == ('fetch("/new");'+ending).encode()
    assert output['sandbox_status'] == 'NOT_RUN' and output['approval_status'] == 'PENDING'


def test_cli_never_executes_source_or_reflects_invalid_manifest():
    source = 'throw new Error("must never execute"); fetch("/old");'
    value = manifest(source)
    result = invoke(json.dumps(value).encode())
    assert result.returncode == 0 and json.loads(result.stdout)['proposals']
    value['sources'][0]['sha256'] = '0'*64
    rejected = invoke(json.dumps(value).encode())
    assert rejected.returncode == 1 and rejected.stdout == b''
    assert source.encode() not in rejected.stderr


def test_cli_rejects_duplicate_json_keys():
    result = invoke(b'{"schema_version":"first","schema_version":"second"}')
    assert result.returncode == 1 and result.stdout == b''
