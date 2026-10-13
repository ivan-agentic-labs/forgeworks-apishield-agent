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


def test_required_sandbox_image_pull_retries_transient_registry_error(monkeypatch):
    calls, delays = [], []
    def fake_run(command, timeout):
        calls.append((command, timeout))
        if len(calls) < 3:
            raise RuntimeError("synthetic registry outage")
        return "synthetic image pulled"
    monkeypatch.setattr(module, "run", fake_run)
    monkeypatch.setattr(module.time, "sleep", delays.append)
    result = module.pull_image_with_bounded_retry("public.ecr.aws/docker/library/python:3.12-alpine")
    assert result == "synthetic image pulled"
    assert len(calls) == 3
    assert delays == [2, 4]
    assert all(command == ["docker", "pull", "public.ecr.aws/docker/library/python:3.12-alpine"] and timeout == 90
               for command, timeout in calls)


def test_persistent_registry_outage_is_not_counted_as_sandbox_pass(monkeypatch):
    calls, delays = [], []
    def failed(command, timeout):
        calls.append((command, timeout))
        raise RuntimeError("synthetic registry outage")
    monkeypatch.setattr(module, "run", failed)
    monkeypatch.setattr(module.time, "sleep", delays.append)
    with pytest.raises(RuntimeError, match="proof BLOCKED"):
        module.pull_image_with_bounded_retry("public.ecr.aws/docker/library/python:3.12-alpine")
    assert len(calls) == 3
    assert delays == [2, 4]
