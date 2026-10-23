"""Container entrypoint. Only fixed staged files are imported; no target code."""
import hashlib
import json
from pathlib import Path
import sys

# -I deliberately removes script directory from sys.path. Add only the isolated,
# read-only staging mount containing this scanner's reviewed helper modules.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from validation_adapter import initialize
from validation_cases import FIXTURES, cases_from_vectors, observe


def main():
    try:
        fixture = sys.argv[1]
        if fixture not in FIXTURES:
            raise ValueError('Unknown designated fixture')
        base = Path(__file__).resolve().parent
        raw = (base / 'vectors.json').read_bytes()
        adapter, runtime = initialize()
        cases = cases_from_vectors(json.loads(raw))
        result = {'status': 'completed', 'fixture': fixture, 'vectors_sha256': hashlib.sha256(raw).hexdigest(),
                  'runtime': runtime, 'observations': [{'id': c['id'], 'observation': observe(adapter, c, fixture)} for c in cases]}
    except Exception as exc:
        result = {'status': 'setup_error', 'error': type(exc).__name__ + ': ' + str(exc)[:1000]}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
