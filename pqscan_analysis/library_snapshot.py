"""Bounded source capture with no Git commands, hooks, builds or imports.

Every non-VCS regular file is captured, including untracked and ignored files.
Symlinks/special files and exhausted limits fail closed instead of yielding a
partial source/build binding. Directory FDs prevent traversal through symlinks.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

MAX_FILES = 20000
MAX_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 40000
MAX_DEPTH = 64
VCS = {'.git', '.hg', '.svn'}
MUTATIONS = {
    'kem-zero-secret': ('crypto/ml_kem/ml_kem.c',
                        'secret[i] = constant_time_select_8(mask, Kr[i], failure_key[i]);', 'secret[i] = 0;'),
    'dsa-accept-invalid': ('crypto/ml_dsa/ml_dsa_sign.c',
                           'ret = ml_dsa_verify_internal(pub, mu_ptr, mu_len, sig, sig_len);', 'ret = 1; /* PQScan designated source mutant */'),
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(files):
    return digest(json.dumps(files, sort_keys=True, separators=(',', ':')).encode())


def safe_path(path):
    return (isinstance(path, str) and bool(path) and not any(ord(c) < 32 for c in path)
            and '\\' not in path and not PurePosixPath(path).is_absolute()
            and all(p not in ('', '.', '..') for p in path.split('/')))


def capture(root, destination, mutation='none', max_files=MAX_FILES, max_bytes=MAX_BYTES):
    root, destination = Path(root).resolve(), Path(destination).resolve()
    if root == destination or root in destination.parents:
        raise ValueError('Snapshot staging must be outside the target repository')
    if mutation not in ('none', *MUTATIONS, 'kem-repaired', 'dsa-repaired'):
        raise ValueError('Unknown designated source mutation')
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError('Snapshot staging must be empty')
    entries, excluded = [], []
    total, visited = 0, 0
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    rootfd = os.open(root, flags | os.O_DIRECTORY)
    revision = None
    try:
        # Informational only; never follow a worktree .git file or execute Git.
        try:
            gitfd = os.open('.git', flags | os.O_DIRECTORY, dir_fd=rootfd)
            try:
                def git_read(name):
                    fd = os.dup(gitfd)
                    try:
                        parts = name.split('/')
                        for part in parts[:-1]:
                            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=fd)
                            os.close(fd); fd = child
                        f = os.open(parts[-1], flags, dir_fd=fd)
                        try:
                            if not stat.S_ISREG(os.fstat(f).st_mode): return ''
                            return os.read(f, 4096).decode('ascii').strip()
                        finally: os.close(f)
                    finally: os.close(fd)
                head = git_read('HEAD')
                if head.startswith('ref: ') and safe_path(head[5:]): head = git_read(head[5:])
                if re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', head): revision = head
            finally: os.close(gitfd)
        except (OSError, UnicodeError):
            pass

        def visit(fd, relative='', depth=0):
            nonlocal total, visited
            if depth > MAX_DEPTH: raise ValueError('Source snapshot directory depth limit exceeded')
            names = []
            with os.scandir(fd) as children:
                for child in children:
                    visited += 1
                    if visited > MAX_ENTRIES: raise ValueError('Source snapshot entry limit exceeded')
                    names.append(child.name)
            for name in sorted(names):
                rel = relative + name
                if not safe_path(rel): raise ValueError('Unsupported source path')
                if name in VCS:
                    excluded.append(rel)
                    continue
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    child = os.open(name, flags | os.O_DIRECTORY, dir_fd=fd)
                    (destination / rel).mkdir()
                    try: visit(child, rel + '/', depth + 1)
                    finally: os.close(child)
                elif stat.S_ISREG(st.st_mode):
                    if len(entries) >= max_files or st.st_size > MAX_FILE_BYTES:
                        raise ValueError('Source snapshot file/count limit exceeded')
                    f = os.open(name, flags, dir_fd=fd)
                    try:
                        before = os.fstat(f)
                        if not stat.S_ISREG(before.st_mode): raise ValueError('Source type changed during capture')
                        chunks, length = [], 0
                        while True:
                            block = os.read(f, min(65536, MAX_FILE_BYTES + 1 - length))
                            if not block: break
                            chunks.append(block); length += len(block)
                            if length > MAX_FILE_BYTES: raise ValueError('Source file exceeds snapshot limit')
                        after = os.fstat(f)
                        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                            raise ValueError('Source file changed during capture')
                        raw = b''.join(chunks)
                    finally: os.close(f)
                    total += len(raw)
                    if total > max_bytes: raise ValueError('Source snapshot byte limit exceeded')
                    dest = destination / rel
                    dest.write_bytes(raw)
                    executable = bool(before.st_mode & 0o111)
                    dest.chmod(0o555 if executable else 0o444)
                    entries.append({'path': rel, 'sha256': digest(raw), 'bytes': len(raw), 'executable': executable})
                else:
                    raise ValueError('Symlinks and special files are unsupported build inputs: ' + rel)
        visit(rootfd)
    finally:
        os.close(rootfd)
    if not entries: raise ValueError('Empty source repository')
    entries.sort(key=lambda e: e['path'])
    original_id = identity(entries)
    mutation_record = None
    if mutation != 'none':
        chosen = {'kem-repaired': 'kem-zero-secret', 'dsa-repaired': 'dsa-accept-invalid'}.get(mutation, mutation)
        path, old, new = MUTATIONS[chosen]
        entry = next((e for e in entries if e['path'] == path), None)
        if entry is None: raise ValueError('Mutation target is absent')
        dest = destination / path
        raw = dest.read_bytes()
        if raw.count(old.encode()) != 1: raise ValueError('Mutation anchor is not unique in this source revision')
        changed = raw.replace(old.encode(), new.encode(), 1)
        mutated_sha = digest(changed)
        if mutation.endswith('repaired'): changed = changed.replace(new.encode(), old.encode(), 1)
        dest.chmod(0o644); dest.write_bytes(changed); dest.chmod(0o555 if entry['executable'] else 0o444)
        mutation_record = {'name': mutation, 'path': path, 'before_sha256': entry['sha256'],
                           'before_bytes': entry['bytes'],
                           'mutated_sha256': mutated_sha, 'after_sha256': digest(changed),
                           'repaired': mutation.endswith('repaired')}
        entry.update(sha256=digest(changed), bytes=len(changed))
    return {'id': identity(entries), 'original_id': original_id, 'files': entries,
            'total_bytes': sum(e['bytes'] for e in entries), 'revision_hint': revision,
            'atomic': False, 'git_status': 'not_inferred; all non-VCS files captured',
            'excluded_vcs_paths': excluded, 'mutation': mutation_record}


def validate_snapshot(snapshot):
    files = snapshot['files']
    if (not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES
            or [e['path'] for e in files] != sorted({e['path'] for e in files})):
        raise ValueError('Invalid snapshot manifest')
    for e in files:
        if (set(e) != {'path', 'sha256', 'bytes', 'executable'} or not safe_path(e['path'])
                or any(p in VCS for p in e['path'].split('/'))
                or not re.fullmatch(r'[0-9a-f]{64}', e['sha256'])
                or type(e['bytes']) is not int or not 0 <= e['bytes'] <= MAX_FILE_BYTES
                or type(e['executable']) is not bool):
            raise ValueError('Invalid snapshot entry')
    if snapshot['id'] != identity(files) or snapshot['total_bytes'] != sum(e['bytes'] for e in files) or snapshot['total_bytes'] > MAX_BYTES:
        raise ValueError('Snapshot identity/size mismatch')
    if snapshot['atomic'] is not False: raise ValueError('Snapshot is not an atomic checkout attestation')
    mutation = snapshot['mutation']
    if mutation is None:
        if snapshot['original_id'] != snapshot['id']: raise ValueError('Unmodified snapshot identity mismatch')
    else:
        chosen = {'kem-repaired': 'kem-zero-secret', 'dsa-repaired': 'dsa-accept-invalid'}.get(mutation['name'], mutation['name'])
        if chosen not in MUTATIONS or mutation['path'] != MUTATIONS[chosen][0]: raise ValueError('Unknown mutation source')
        original = [dict(e) for e in files]
        entry = next((e for e in original if e['path'] == mutation['path']), None)
        if entry is None or entry['sha256'] != mutation['after_sha256']: raise ValueError('Mutation artifact mismatch')
        expected_after = mutation['before_sha256'] if mutation['repaired'] else mutation['mutated_sha256']
        if mutation['after_sha256'] != expected_after or mutation['repaired'] != mutation['name'].endswith('repaired'):
            raise ValueError('Invalid repaired mutation identity')
        entry.update(sha256=mutation['before_sha256'], bytes=mutation['before_bytes'])
        if identity(original) != snapshot['original_id']: raise ValueError('Original source identity mismatch')
    return snapshot
