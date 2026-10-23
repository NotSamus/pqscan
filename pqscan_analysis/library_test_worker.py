"""Fresh container: tests only the exact staged build artifact."""
import sys
# Use CPython's built-in hash implementations. Importing _hashlib would load a
# second, system libcrypto before the artifact identity check.
sys.modules['_hashlib'] = None
import hashlib
import json
import os
from pathlib import Path
sys.path.insert(0, '/runner')
from library_worker import isolation
from library_adapter import Adapter
from library_cases import library_cases
from validation_cases import observe


def main():
    checks = isolation()
    os.environ['OPENSSL_CONF'] = '/dev/null'
    os.environ['OPENSSL_MODULES'] = '/nonexistent'
    os.environ['OPENSSL_ENGINES'] = '/nonexistent'
    artifact = Path('/runner/libcrypto.so')
    before = hashlib.sha256(artifact.read_bytes()).hexdigest()
    vectors = json.loads(Path('/runner/vectors.json').read_text())
    adapter = Adapter(artifact)
    try:
        observations = [{'id': case['id'], 'observation': observe(adapter, case)} for case in library_cases(vectors)]
        runtime = adapter.metadata()
        if hashlib.sha256(artifact.read_bytes()).hexdigest() != before:
            raise RuntimeError('Artifact changed during testing')
        return {'status': 'completed', 'artifact_sha256': before, 'runtime': runtime,
                'isolation_checks': checks, 'observations': observations}
    finally: adapter.close()


if __name__ == '__main__':
    try: result = main()
    except Exception as exc: result = {'status': 'setup_error', 'error': (type(exc).__name__ + ': ' + str(exc))[:2000]}
    print(json.dumps(result, sort_keys=True))
