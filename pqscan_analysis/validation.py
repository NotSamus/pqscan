"""Explicit, bounded container validation. Never imports or mounts a target repo.

Usage: python -m pqscan_analysis.validation run --image IMAGE --output REPORT
Image preparation is a separate, explicit Docker build; this runner never pulls.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time
import uuid

from .requirements import load_catalog, _validate_contract
from .validation_cases import PROFILE, FIXTURES, cases_from_vectors, evaluate

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / 'validation'
MAX_OUTPUT = 1024 * 1024
BOUNDARY = ('Only these cases on the recorded isolated provider build were exercised. '
            'No repository or application was executed; no deployment equivalence, full requirement '
            'conformance, exploitability, CAVP validation or CMVP certification is established. '
            'Imported JSON is unauthenticated evidence, even when its hashes are consistent.')
ISOLATION = {'backend': 'docker', 'network': 'none', 'root_filesystem': 'read_only',
             'user': '65534:65534', 'capabilities': 'none', 'no_new_privileges': True,
             'memory_bytes': 268435456, 'cpus': 1, 'pids': 64, 'target_mounted': False,
             'automatic_downloads': False}


class SetupError(ValueError):
    pass


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def parse_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('Duplicate JSON key: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError('Invalid JSON constant: ' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def read_bounded(path, maximum=2 * 1024 * 1024):
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('Validation artifact exceeds its size limit')
    return raw


def load_vectors():
    manifest_raw = read_bounded(DATA / 'vectors/manifest.json')
    manifest = parse_json(manifest_raw)
    raw = read_bounded(DATA / 'vectors/acvp-selected.json')
    vectors = parse_json(raw)
    if (manifest['profile'] != PROFILE or manifest['file'] != 'acvp-selected.json'
            or manifest['sha256'] != sha(raw) or manifest['cases'] != len(vectors['cases'])
            or vectors['profile'] != PROFILE or vectors['sources'] != manifest['sources']):
        raise ValueError('Pinned vector manifest mismatch')
    # Pin the release corpus shape, not just a claimed count or self-declared hash.
    expected = ['mlkem-tg5-tc' + str(i) for i in range(86, 96)] + ['mldsa-tg3-tc' + str(i) for i in range(31, 46)]
    if [v['id'] for v in vectors['cases']] != expected:
        raise ValueError('Unexpected vector selection')
    for v in vectors['cases']:
        x = v['inputs']
        lengths = {'dk': 2400, 'c': 1088, 'k': 32} if v['operation'] == 'decapsulate' else {'pk': 1952, 'signature': 3309}
        for key, length in lengths.items():
            if len(bytes.fromhex(x[key])) != length:
                raise ValueError('Invalid pinned vector field length')
        if v['operation'] == 'verify_context':
            if type(x['testPassed']) is not bool or len(bytes.fromhex(x['context'])) > 255:
                raise ValueError('Invalid signature vector')
            bytes.fromhex(x['message'])
    return vectors, raw, manifest_raw


def artifacts(raw, manifest_raw):
    files = {'worker': ROOT / 'pqscan_analysis/validation_worker.py',
             'adapter': ROOT / 'pqscan_analysis/validation_adapter.py',
             'cases': ROOT / 'pqscan_analysis/validation_cases.py',
             'runner': Path(__file__), 'requirements_lock': DATA / 'container/requirements.lock',
             'dockerfile': DATA / 'container/Dockerfile'}
    return dict({name: sha(read_bounded(path)) for name, path in files.items()},
                vectors=sha(raw), vector_manifest=sha(manifest_raw))


def bounded_process(command, timeout, max_output=MAX_OUTPUT):
    """No shell; deadline and output limits apply to stdout and stderr together."""
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as process:
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
                selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
                deadline = time.monotonic() + timeout
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SetupError('Validation command timed out')
                    for key, _ in selector.select(min(remaining, 0.1)):
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        buffers[key.data].extend(block)
                        if sum(len(b) for b in buffers.values()) > max_output:
                            raise SetupError('Validation command exceeded its output limit')
                try:
                    process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired as exc:
                    raise SetupError('Validation command timed out') from exc
            return process.returncode, bytes(buffers['stdout']), bytes(buffers['stderr'])
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def inspect_image(image):
    if not isinstance(image, str) or not image or len(image) > 256 or image.startswith('-'):
        raise SetupError('Supply a local validation image name or full image ID')
    code, raw, error = bounded_process(['docker', 'image', 'inspect', image], 15)
    if code:
        raise SetupError('Local validation image unavailable; explicitly build validation/container first. ' + error.decode(errors='replace')[:500])
    values = parse_json(raw)
    if not isinstance(values, list) or len(values) != 1:
        raise SetupError('Unexpected Docker image metadata')
    info = values[0]
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', info.get('Id', '')) or info.get('Os') != 'linux':
        raise SetupError('Validation requires an immutable Linux image ID')
    if info.get('Config', {}).get('Volumes'):
        raise SetupError('Validation images with declared volumes are not supported')
    if info.get('Architecture') not in ('arm64', 'amd64'):
        raise SetupError('Only Linux arm64 and amd64 provider wheels are pinned')
    return {'requested': image, 'id': info['Id'], 'platform': info['Os'] + '/' + info['Architecture']}


def container_command(image_id, staging, name, fixture):
    # One read-only mount of freshly copied harness data. No repository, home,
    # Docker socket, arbitrary environment, image entrypoint or network access.
    return ['docker', 'run', '--name', name, '--rm', '--pull=never', '--network=none',
            '--read-only', '--user=65534:65534', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--pids-limit=64', '--memory=256m',
            '--memory-swap=256m', '--cpus=1', '--ulimit=nofile=64:64',
            '--log-driver=none', '--no-healthcheck', '--workdir=/runner',
            '--mount', f'type=bind,src={staging},dst=/runner,readonly',
            '--entrypoint=/usr/local/bin/python3', image_id, '-I', '-B',
            '/runner/validation_worker.py', fixture]


def validate_worker(value, cases, fixture, vector_sha):
    if not isinstance(value, dict):
        raise SetupError('Worker returned an invalid response')
    if value.get('status') == 'setup_error':
        raise SetupError('Worker setup failed: ' + str(value.get('error', 'unknown error'))[:1000])
    if (set(value) != {'status', 'fixture', 'vectors_sha256', 'runtime', 'observations'}
            or value['status'] != 'completed' or value['fixture'] != fixture or value['vectors_sha256'] != vector_sha):
        raise SetupError('Worker identity or vector hash mismatch')
    runtime = value['runtime']
    _validate_contract(runtime, 'validation-runtime.schema.json')
    if runtime['python'] != '3.11.14' or [a['module'] for a in runtime['artifacts']] != [
            'pqcrypto.kem.ml_kem_768', 'pqcrypto.sign.ml_dsa_65',
            'pqcrypto._kem.ml_kem_768', 'pqcrypto._sign.ml_dsa_65']:
        raise SetupError('Unexpected Python runtime or provider artifact identities')
    if runtime['versions'] != {'pqcrypto': '0.3.4', 'cffi': '1.17.1', 'pycparser': '2.22'}:
        raise SetupError('Worker provider versions do not match the profile')
    observations = value['observations']
    if (not isinstance(observations, list) or len(observations) != len(cases)
            or not all(isinstance(o, dict) for o in observations)
            or [o.get('id') for o in observations] != [c['id'] for c in cases]):
        raise SetupError('Worker omitted, reordered or fabricated test IDs')
    results = []
    for case, record in zip(cases, observations):
        if set(record) != {'id', 'observation'}:
            raise SetupError('Invalid worker observation fields')
        observation = record['observation']
        _validate_contract(observation, 'validation-observation.schema.json')
        results.append(dict({k: v for k, v in case.items() if k != 'inputs'},
                            observation=observation, status=evaluate(case, observation)))
    return runtime, results


def summary(results):
    counts = Counter(c['status'] for c in results)
    return {s: counts[s] for s in ('passed', 'failed', 'error')}


def outcome(results):
    counts = summary(results)
    return 'inconclusive' if counts['error'] else ('failed' if counts['failed'] else 'passed')


def new_report(image, fixture, timeout, vectors, raw, manifest_raw):
    catalog, catalog_sha = load_catalog()
    return {'schema_version': '1.0', 'tool': 'pqscan-validation', 'profile': PROFILE,
            'status': 'pending', 'origin': 'local_execution', 'fixture': fixture,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'image': {'requested': image, 'id': None, 'platform': None},
            'isolation': dict(ISOLATION, timeout_seconds=timeout), 'command': [],
            'artifacts': artifacts(raw, manifest_raw), 'vector_sources': vectors['sources'],
            'catalog': {'id': catalog['catalog_id'], 'version': catalog['version'], 'sha256': catalog_sha},
            'runtime': None, 'case_results': [], 'summary': summary([]), 'error': None,
            'coverage': {'partial': True, 'planned_cases': len(cases_from_vectors(vectors)),
                         'repository_binding': 'none', 'requirements_assessed_in_full': 0},
            'correctness_verified': False, 'compliance_certified': False,
            'exploitability': 'not_assessed', 'boundary': BOUNDARY}


def run_validation(image, fixture='provider', timeout=45, checkpoint=None):
    if not isinstance(image, str) or not image or len(image) > 256 or image.startswith('-'):
        raise ValueError('Supply a local validation image name or full image ID')
    if fixture not in FIXTURES or type(timeout) is not int or not 1 <= timeout <= 120:
        raise ValueError('Invalid fixture or timeout (must be 1-120 seconds)')
    vectors, raw, manifest_raw = load_vectors()
    cases = cases_from_vectors(vectors)
    report = new_report(image, fixture, timeout, vectors, raw, manifest_raw)
    if checkpoint:
        checkpoint(report, False)
    name = 'pqscan-validation-' + uuid.uuid4().hex
    started = False
    try:
        report['image'] = inspect_image(image)
        with tempfile.TemporaryDirectory(prefix='pqscan-validation-') as temporary:
            staging = Path(temporary)
            staging.chmod(0o755)
            for filename in ('validation_worker.py', 'validation_adapter.py', 'validation_cases.py'):
                dest = staging / filename
                content = read_bounded(ROOT / 'pqscan_analysis' / filename)
                key = filename.removeprefix('validation_').removesuffix('.py')
                if sha(content) != report['artifacts'][key]:
                    raise SetupError('Harness changed while preparing validation; retry from a stable scanner checkout')
                dest.write_bytes(content)
                dest.chmod(0o444)
            (staging / 'vectors.json').write_bytes(raw)
            (staging / 'vectors.json').chmod(0o444)
            report['command'] = container_command(report['image']['id'], str(staging), name, fixture)
            started = True
            try:
                code, output, error = bounded_process(report['command'], timeout)
                if code:
                    raise SetupError('Container execution failed (exit ' + str(code) + '): ' + error.decode(errors='replace')[:1000])
                runtime, results = validate_worker(parse_json(output), cases, fixture, sha(raw))
                report.update(runtime=runtime, case_results=results, summary=summary(results), status=outcome(results))
            finally:
                # A killed Docker client may leave a live container. Remove only our
                # UUID-named container before deleting its temporary harness mount.
                if started:
                    cleanup_code, _, cleanup_error = bounded_process(['docker', 'rm', '--force', name], 10)
                    if cleanup_code and b'No such container' not in cleanup_error:
                        raise SetupError('Could not confirm container cleanup for ' + name + ': ' + cleanup_error.decode(errors='replace')[:500])
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        report['status'] = 'setup_error'
        report['error'] = (type(exc).__name__ + ': ' + str(exc))[:2000]
    except BaseException:
        report['status'] = 'setup_error'
        report['error'] = 'Validation interrupted; no complete execution claim.'
        if checkpoint:
            checkpoint(report, True)
        raise
    if checkpoint:
        checkpoint(report, True)
    return report


def validate_report(report):
    """Current immutable profile only. Structural checks never authenticate JSON."""
    _validate_contract(report, 'validation-report.schema.json')
    vectors, raw, manifest_raw = load_vectors()
    expected_cases = cases_from_vectors(vectors)
    if report['artifacts'] != artifacts(raw, manifest_raw) or report['vector_sources'] != vectors['sources']:
        raise ValueError('Validation artifacts differ from this runner profile; retain the matching scanner revision')
    if {k: v for k, v in report['isolation'].items() if k != 'timeout_seconds'} != ISOLATION:
        raise ValueError('Unexpected isolation policy')
    if report['coverage'] != {'partial': True, 'planned_cases': len(expected_cases), 'repository_binding': 'none', 'requirements_assessed_in_full': 0}:
        raise ValueError('Invalid validation coverage')
    if report['summary'] != summary(report['case_results']):
        raise ValueError('Validation result counts disagree')
    if report['boundary'] != BOUNDARY:
        raise ValueError('Validation boundary text was changed')
    catalog, catalog_sha = load_catalog()
    if report['catalog'] != {'id': catalog['catalog_id'], 'version': catalog['version'], 'sha256': catalog_sha}:
        raise ValueError('Requirement catalog differs from this validation profile')
    if report['command']:
        command = report['command']
        try:
            name = command[command.index('--name') + 1]
            mount = command[command.index('--mount') + 1]
            staging = mount.removeprefix('type=bind,src=').removesuffix(',dst=/runner,readonly')
        except (ValueError, IndexError) as exc:
            raise ValueError('Invalid recorded container command') from exc
        if (not re.fullmatch(r'pqscan-validation-[a-f0-9]{32}', name) or not staging.startswith('/')
                or command != container_command(report['image']['id'], staging, name, report['fixture'])):
            raise ValueError('Recorded container command contradicts the isolation policy')
    if report['status'] in ('passed', 'failed', 'inconclusive') or report['case_results']:
        worker = {'status': 'completed', 'fixture': report['fixture'], 'vectors_sha256': sha(raw),
                  'runtime': report['runtime'], 'observations': [{'id': r['id'], 'observation': r['observation']} for r in report['case_results']]}
        _, results = validate_worker(worker, expected_cases, report['fixture'], sha(raw))
        if results != report['case_results']:
            raise ValueError('Saved validation outcomes do not match the fixed test oracles')
        if report['status'] != 'setup_error' and (outcome(results) != report['status'] or report['error'] is not None):
            raise ValueError('Saved validation status does not match its case results')
        if not report['image']['id'] or not report['command']:
            raise ValueError('Completed validation lacks execution provenance')
        machine = {'linux/arm64': 'aarch64', 'linux/amd64': 'x86_64'}[report['image']['platform']]
        if report['runtime']['machine'] != machine:
            raise ValueError('Worker architecture does not match the recorded image')
    if report['status'] == 'pending' and (report['case_results'] or report['runtime'] or report['error']):
        raise ValueError('Pending validation cannot claim results')
    elif report['status'] == 'setup_error' and not report['error']:
        raise ValueError('Setup failure lacks an error')
    return report


def load_validation_report(path):
    try:
        report = validate_report(parse_json(read_bounded(Path(path))))
    except (KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise ValueError('Malformed validation report') from exc
    report['origin'] = 'imported_unverified'
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='Run fixed PQC provider checks in a local Docker container; no target repository is executed.')
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run', help='explicitly execute the pinned provider profile; never build or pull images')
    run.add_argument('--image', required=True, help='previously built local image, resolved to an immutable ID')
    run.add_argument('--fixture', choices=FIXTURES, default='provider', help='designated fault injection for harness regression testing only')
    run.add_argument('--timeout', type=int, default=45, help='container deadline, 1-120 seconds')
    run.add_argument('-o', '--output', type=Path, required=True, help='new JSON report; never overwrite an existing report')
    read = commands.add_parser('read', help='validate and show saved results as unauthenticated imported evidence; never execute')
    read.add_argument('report', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'read':
            report = load_validation_report(args.report)
        else:
            from pqscan import save_json
            path = args.output.expanduser().absolute()
            if path.exists() or path.is_symlink():
                raise ValueError('Output already exists; choose a new report path')
            path.parent.mkdir(parents=True, exist_ok=True)
            report = run_validation(args.image, args.fixture, args.timeout,
                                    checkpoint=lambda value, replace: save_json(value, path, replace=replace))
        print(f"{report['profile']}: {report['status']} ({report['origin']}; fixture={report['fixture']})")
        print(canonical(report['summary']))
        for case in report['case_results']:
            if case['status'] != 'passed':
                print(f"{case['id']}: {case['status']} ({', '.join(case['requirement_ids']) or case['locator']})")
        print(BOUNDARY)
        if report['error']:
            print(''.join(c if c.isprintable() else ' ' for c in report['error']))
        return 0 if report['status'] == 'passed' else (1 if report['status'] == 'failed' else 2)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Validation error: ' + ''.join(c if c.isprintable() else ' ' for c in str(exc)))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
