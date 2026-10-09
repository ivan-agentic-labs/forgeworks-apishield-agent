#!/usr/bin/env python3
"""Fixed synthetic Docker canary only. Never executes user/customer code."""
import json
import os
import shutil
import subprocess
import sys
import uuid

CANARY = r'''
import json, os, socket
checks = {}
checks['non_root'] = os.getuid() == 65534 and os.getgid() == 65534
status = {}
with open('/proc/self/status') as file:
    for line in file:
        if ':' in line:
            key, value = line.split(':', 1); status[key] = value.strip()
checks['capabilities_dropped'] = int(status['CapEff'], 16) == 0
checks['no_new_privileges'] = status.get('NoNewPrivs') == '1'
checks['seccomp_filter'] = status.get('Seccomp') == '2'
mounts = {}
with open('/proc/mounts') as file:
    for line in file:
        fields = line.split()
        if len(fields) >= 4: mounts[fields[1]] = set(fields[3].split(','))
checks['root_mount_is_read_only'] = 'ro' in mounts.get('/', set())
checks['scratch_mount_hardened'] = {'noexec','nosuid','nodev'} <= mounts.get('/tmp', set())
checks['only_loopback_interface'] = sorted(os.listdir('/sys/class/net')) == ['lo']
with open('/sys/fs/cgroup/memory.max') as file:
    checks['memory_limit_enforced'] = int(file.read()) <= 128 * 1024 * 1024
with open('/sys/fs/cgroup/pids.max') as file:
    checks['process_limit_enforced'] = int(file.read()) <= 32
with open('/sys/fs/cgroup/cpu.max') as file:
    quota, period = map(int, file.read().split())
    checks['cpu_limit_enforced'] = quota / period <= 0.5
for name, path in [('root_filesystem_read_only', '/sandbox-canary'), ('kernel_setting_not_writable', '/proc/sys/kernel/core_pattern')]:
    try:
        with open(path, 'w') as file: file.write('synthetic canary')
        checks[name] = False
    except OSError:
        checks[name] = True
with open('/tmp/synthetic-canary', 'w') as file: file.write('scratch')
checks['bounded_scratch_available'] = True
connection = socket.socket()
connection.settimeout(2)
try:
    connection.connect(('1.1.1.1', 443)); checks['external_network_denied'] = False
except OSError:
    checks['external_network_denied'] = True
finally:
    connection.close()
print(json.dumps(checks, sort_keys=True))
raise SystemExit(0 if all(checks.values()) else 1)
'''


def run(command, timeout):
    result = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError('Disposable sandbox command failed; inspect the CI step, not customer content')
    if len(result.stdout) > 65536:
        raise RuntimeError('Disposable proof output exceeded its fixed limit')
    return result.stdout


def sandbox_command(image_id, name):
    if not image_id.startswith('sha256:') or len(image_id) != 71 or any(c not in '0123456789abcdef' for c in image_id[7:]):
        raise ValueError('An immutable local image ID is required')
    return ['docker','run','--rm','--name',name,'--network','none','--read-only',
            '--cap-drop','ALL','--security-opt','no-new-privileges:true',
            '--pids-limit','32','--memory','128m','--memory-swap','128m','--cpus','0.5',
            '--ulimit','nofile=64:64','--user','65534:65534',
            '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=8m',
            image_id,'python','-I','-c',CANARY]


def main():
    if os.getenv('G1_DISPOSABLE_SANDBOX') != 'yes' or os.getenv('GITHUB_ACTIONS') != 'true':
        raise SystemExit('Refusing execution outside explicitly opted-in disposable GitHub Actions')
    if not shutil.which('docker'):
        raise SystemExit('Docker unavailable: BLOCKED, not PASS')
    # Pull a named upstream version, then execute only its resolved immutable ID.
    # This records provenance but is NOT an independently approved image digest.
    run(['docker','pull','public.ecr.aws/docker/library/python:3.12-alpine'],120)
    image = json.loads(run(['docker','image','inspect','public.ecr.aws/docker/library/python:3.12-alpine'],10))[0]
    image_id=image['Id'];name='fw-synthetic-sandbox-'+uuid.uuid4().hex
    try:
        checks=json.loads(run(sandbox_command(image_id,name),20))
        if not checks or not all(checks.values()):
            raise RuntimeError('Sandbox canary did not satisfy every check')
        print(json.dumps({'result':'PASS','image_id':image_id,'repo_digests':image.get('RepoDigests',[]),'checks':checks,
                          'limits':'Fixed synthetic canaries only. Not an escape audit, approved production image, provider workload, live sandbox service or complete egress proof.'},sort_keys=True))
    finally:
        # Exact UUID-named task container only, including timeout cleanup.
        subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=10,check=False)


if __name__ == '__main__':
    main()
