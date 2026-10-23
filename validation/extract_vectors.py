"""Offline reproduction of the selected corpus from checksum-pinned NIST files.

python validation/extract_vectors.py MLKEM_JSON MLDSA_JSON NEW_OUTPUT_JSON
Downloads and source-file paths are explicit; nothing is executed or fetched.
"""
import argparse
import hashlib
import json
from pathlib import Path


def extract(mlkem_path, mldsa_path):
    manifest = json.loads((Path(__file__).parent / 'vectors/manifest.json').read_text())
    result = {'schema_version': '1.0', 'profile': manifest['profile'],
              'sources': manifest['sources'], 'cases': []}
    for source, path, group_id in zip(manifest['sources'], (mlkem_path, mldsa_path), (5, 3)):
        with Path(path).open('rb') as stream:
            raw = stream.read(32 * 1024 * 1024 + 1)
        if len(raw) > 32 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != source['sha256']:
            raise ValueError('Upstream vector file does not match its pinned checksum: ' + source['id'])
        data = json.loads(raw)
        for group in data['testGroups']:
            if group['tgId'] != group_id:
                continue
            for test in group['tests']:
                kem = source['id'] == 'mlkem'
                fields = ('dk', 'c', 'k') if kem else ('pk', 'message', 'context', 'signature', 'testPassed')
                result['cases'].append({'id': f"{source['id']}-tg{group_id}-tc{test['tcId']}",
                                        'source_id': source['id'], 'tgId': group_id, 'tcId': test['tcId'],
                                        'parameter_set': group['parameterSet'], 'reason': test['reason'],
                                        'operation': 'decapsulate' if kem else 'verify_context',
                                        'inputs': {key: test[key] for key in fields}})
    raw = (json.dumps(result, indent=2) + '\n').encode()
    if hashlib.sha256(raw).hexdigest() != manifest['sha256']:
        raise ValueError('Reconstructed selection does not match its pinned checksum')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mlkem', type=Path)
    parser.add_argument('mldsa', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    raw = extract(args.mlkem, args.mldsa)
    with args.output.open('xb') as stream:
        stream.write(raw)
    print('Reproduced pinned corpus:', hashlib.sha256(raw).hexdigest())


if __name__ == '__main__':
    main()
