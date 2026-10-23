"""Trusted container supervisor for the fixed OpenSSL source-build recipe."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys

sys.path.insert(0, '/runner')
from library_native import build_index


def sha(raw): return hashlib.sha256(raw).hexdigest()


def isolation():
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    active = sorted(p.name for p in Path('/sys/class/net').iterdir()
                    if (p / 'flags').is_file() and int((p / 'flags').read_text().strip(), 16) & 1)
    result = {'uid': os.getuid(), 'active_interfaces': active, 'root_read_only': bool(os.statvfs('/').f_flag & os.ST_RDONLY),
              'capabilities_zero': int(status['CapEff'].strip(), 16) == 0,
              'no_new_privileges': status['NoNewPrivs'].strip() == '1', 'seccomp_filter': status['Seccomp'].strip() == '2'}
    if result != {'uid': 65534, 'active_interfaces': ['lo'], 'root_read_only': True,
                  'capabilities_zero': True, 'no_new_privileges': True, 'seccomp_filter': True}:
        raise ValueError('Container isolation check failed: ' + repr(result))
    return result


def verify_source(snapshot):
    expected = {f['path']: f for f in snapshot['files']}
    actual = set()
    for root, dirs, files in os.walk('/source', followlinks=False):
        for name in dirs + files:
            if (Path(root) / name).is_symlink(): raise ValueError('Unexpected source symlink')
        for name in files:
            path = Path(root) / name
            rel = path.relative_to('/source').as_posix()
            if rel not in expected: raise ValueError('Unexpected captured source file')
            raw = path.read_bytes()
            if len(raw) != expected[rel]['bytes'] or sha(raw) != expected[rel]['sha256']:
                raise ValueError('Captured source no longer matches its manifest: ' + rel)
            actual.add(rel)
    if actual != set(expected): raise ValueError('Captured source file is missing')


def build():
    checks = isolation()
    snapshot = json.loads(Path('/runner/snapshot.json').read_text())
    verify_source(snapshot)
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024,) * 2)
    build_dir = Path('/work/build'); build_dir.mkdir()
    # Current OpenSSL emits the apps configuration header even with no-apps.
    (build_dir / 'apps/include').mkdir(parents=True)
    Path('/work/commands').mkdir()
    target = {'aarch64': 'linux-aarch64', 'x86_64': 'linux-x86_64'}[platform.machine()]
    configure = ['perl', '/source/Configure', target, 'shared', 'no-asm', 'no-module',
                 'no-tests', 'no-apps', 'no-docs', 'no-quic', '-O1']
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
           'HOME': '/work', 'CC': '/runner/library_compiler.py'}
    commands = [configure, ['make', '-j2', 'build_generated'], ['make', '-j2', 'libcrypto.so']]
    log = Path('/work/build.log')
    with log.open('wb') as out:
        for command in commands:
            process = subprocess.run(command, cwd=build_dir, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=540)
            if process.returncode:
                raise RuntimeError('Build command failed: ' + repr(command) + '\n' + log.read_text(errors='replace')[-3000:])
    # Only an actual regular ELF library within our build workspace is exported.
    artifact = (build_dir / 'libcrypto.so').resolve()
    if artifact.parent != build_dir or not artifact.is_file(): raise ValueError('Unexpected library output path')
    raw = artifact.read_bytes()
    if not raw.startswith(b'\x7fELF') or not 1024 <= len(raw) <= 32 * 1024 * 1024:
        raise ValueError('Invalid or oversized library artifact')
    records = [json.loads(p.read_text()) for p in Path('/work/commands').glob('*.json')]
    records.sort(key=lambda r: json.dumps(r, sort_keys=True))
    if not 1 <= len(records) <= 5000: raise ValueError('Invalid compilation record count')
    native = build_index(snapshot)
    verify_source(snapshot)
    return {'status': 'built', 'source_snapshot_id': snapshot['id'], 'isolation_checks': checks,
            'artifact_sha256': sha(raw), 'artifact_base64': base64.b64encode(raw).decode(),
            'artifact_name': artifact.name, 'configure': configure, 'commands': commands,
            'compiler_version': subprocess.check_output(['/usr/bin/clang-14', '--version'], text=True).strip(),
            'toolchain_packages_sha256': sha(Path('/opt/pqscan/toolchain-packages.txt').read_bytes()),
            'build_log_sha256': sha(log.read_bytes()), 'compilation_commands': records,
            'generated_files': {name: sha((build_dir / name).read_bytes()) for name in
                                ('Makefile', 'configdata.pm', 'include/openssl/configuration.h')},
            'native_source': native, 'machine': platform.machine(), 'python': platform.python_version()}


if __name__ == '__main__':
    try:
        result = build()
    except Exception as exc:
        result = {'status': 'build_error', 'error': (type(exc).__name__ + ': ' + str(exc))[:4000]}
    print(json.dumps(result, sort_keys=True))
