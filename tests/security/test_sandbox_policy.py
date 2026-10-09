import importlib.util
from pathlib import Path

import pytest

path=Path(__file__).resolve().parents[2]/'scripts/prove_disposable_sandbox.py'
spec=importlib.util.spec_from_file_location('sandbox_proof',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def test_synthetic_canary_command_has_no_host_mount_or_secrets():
    command=module.sandbox_command('sha256:'+'a'*64,'fw-synthetic-sandbox-test')
    assert '--network' in command and command[command.index('--network')+1]=='none'
    assert '--read-only' in command and '--cap-drop' in command
    assert '--pids-limit' in command and '--memory' in command and '--cpus' in command
    assert '-v' not in command and '--volume' not in command and '--mount' not in command
    assert '-e' not in command and '--env' not in command and '--privileged' not in command
    assert command[-1]==module.CANARY


def test_mutable_image_reference_is_rejected():
    with pytest.raises(ValueError,match='immutable'):
        module.sandbox_command('python:latest','fw-synthetic-sandbox-test')


def test_proof_requires_explicit_disposable_ci_opt_in(monkeypatch):
    monkeypatch.delenv('G1_DISPOSABLE_SANDBOX',raising=False)
    with pytest.raises(SystemExit,match='Refusing'):
        module.main()
