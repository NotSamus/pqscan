"""Library repository inspection and explicit isolated OpenSSL source validation."""
import argparse
import base64
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
import uuid

from .library_snapshot import capture, validate_snapshot, identity, digest, MUTATIONS, safe_path
from .library_cases import library_cases
from .validation import (ROOT, bounded_process, inspect_image, parse_json, read_bounded, load_vectors,
                         canonical, summary, outcome, SetupError)
from .validation_cases import evaluate
from .requirements import load_catalog, _validate_contract

PROFILE = 'pqscan-library-openssl-v1'
RECIPE = 'openssl-evp-portable-v1'
HARNESS = ('library_worker.py', 'library_compiler.py', 'library_native.py', 'library_adapter.py',
           'library_cases.py', 'library_test_worker.py', 'validation_cases.py')
CHECKS = {'uid': 65534, 'active_interfaces': ['lo'], 'root_read_only': True, 'capabilities_zero': True,
          'no_new_privileges': True, 'seccomp_filter': True}
BOUNDARY = ('Results apply only to the captured source, recorded build recipe, portable no-asm backend '
            'and tested artifact/cases. Build provenance is recorded locally, not independently attested. '
            'No full requirement conformance, constant-time behavior, deployed application security, '
            'exploitability or NIST certification is established. Imported reports are unauthenticated.')


def harness_bytes():
    return {name: read_bounded(ROOT / 'pqscan_analysis' / name) for name in HARNESS}


def detect_subject(snapshot):
    paths = {f['path'] for f in snapshot['files']}
    markers = {'Configure', 'VERSION.dat', 'crypto/ml_kem/ml_kem.c', 'crypto/ml_dsa/ml_dsa_sign.c', 'include/openssl/evp.h.in'}
    return {'kind': 'library_repository', 'adapter': RECIPE if markers <= paths else None,
            'adapter_status': 'candidate_supported' if markers <= paths else 'unsupported',
            'languages': dict(sorted(Counter(Path(p).suffix or '(no extension)' for p in paths).items()))}


def container_command(image_id, staging, source, name, phase):
    if phase not in ('build', 'test'):
        raise ValueError('Unknown library execution phase')
    for path in (staging, source):
        if path is not None and (not str(path).startswith('/') or ',' in str(path) or any(ord(c) < 32 for c in str(path))):
            raise ValueError('Unsafe container mount path')
    command = ['docker', 'run', '--name', name, '--rm', '--pull=never', '--network=none',
               '--read-only', '--user=65534:65534', '--cap-drop=ALL', '--security-opt=no-new-privileges',
               '--pids-limit=128', '--memory=2g', '--memory-swap=2g', '--cpus=2',
               '--ulimit=nofile=256:256', '--log-driver=none', '--no-healthcheck', '--workdir=/work',
               '--tmpfs=/work:rw,nosuid,nodev,exec,size=1536m,mode=1777',
               '--mount', f'type=bind,src={staging},dst=/runner,readonly']
    if phase == 'build': command += ['--mount', f'type=bind,src={source},dst=/source,readonly']
    command += ['--entrypoint=/usr/local/bin/python3', image_id, '-I', '-B',
                '/runner/library_worker.py' if phase == 'build' else '/runner/library_test_worker.py']
    return command


def execute_container(command, timeout, limit):
    name = command[command.index('--name') + 1]
    try:
        code, raw, error = bounded_process(command, timeout, max_output=limit)
        if code: raise SetupError('Container failed (exit ' + str(code) + '): ' + error.decode(errors='replace')[:2000])
        return parse_json(raw)
    finally:
        code, _, error = bounded_process(['docker', 'rm', '--force', name], 10)
        if code and b'No such container' not in error:
            raise SetupError('Could not confirm cleanup of ' + name)


def validate_native(index, snapshot, source_dir=None):
    _validate_contract(index, 'library-native.schema.json')
    files = {f['path']: f for f in snapshot['files']}
    if index['parser'] != 'libclang-14' or index['coverage']['partial'] is not True:
        raise ValueError('Invalid native source index')
    if len(index['translation_units']) > 24 or len(index['symbols']) > 1200 or len(index['calls']) > 4000:
        raise ValueError('Native source index exceeds its budget')
    symbols = {}
    for symbol in index['symbols']:
        if symbol['id'] in symbols or symbol['path'] not in files:
            raise ValueError('Duplicate or unknown native symbol')
        if symbol['file_sha256'] != files[symbol['path']]['sha256'] or not 1 <= symbol['start_line'] <= symbol['end_line']:
            raise ValueError('Invalid native symbol source reference')
        symbols[symbol['id']] = symbol
    for unit in index['translation_units']:
        if unit['path'] not in files or unit['file_sha256'] != files[unit['path']]['sha256']:
            raise ValueError('Invalid translation unit reference')
    for call in index['calls']:
        if call['caller_id'] not in symbols or (call['target_id'] is not None and call['target_id'] not in symbols):
            raise ValueError('Invalid native call reference')
        caller = symbols[call['caller_id']]
        if call['path'] != caller['path'] or not caller['start_line'] <= call['line'] <= caller['end_line']:
            raise ValueError('Native call is outside its caller')
    ids = set()
    for excerpt in index['source_slices']:
        symbol = symbols.get(excerpt['symbol_id'])
        if excerpt['id'] in ids or symbol is None: raise ValueError('Invalid source excerpt ID')
        ids.add(excerpt['id'])
        if (excerpt['path'] != symbol['path'] or excerpt['file_sha256'] != symbol['file_sha256']
                or not symbol['start_line'] <= excerpt['start_line'] <= excerpt['end_line'] <= symbol['end_line']
                or digest(excerpt['text'].encode()) != excerpt['sha256'] or len(excerpt['text']) > 4000):
            raise ValueError('Invalid native excerpt reference/hash')
        if source_dir is not None:
            lines = (Path(source_dir) / excerpt['path']).read_bytes().decode('utf-8').splitlines(keepends=True)
            if excerpt['text'] != ''.join(lines[excerpt['start_line'] - 1:excerpt['end_line']]):
                raise ValueError('Native excerpt does not match captured source')
    if index['source_chars'] != sum(len(s['text']) for s in index['source_slices']) or index['source_chars'] > 24000:
        raise ValueError('Native source excerpt budget mismatch')
    return index


def check_build(result, snapshot, source_dir):
    if not isinstance(result, dict) or result.get('status') != 'built':
        raise SetupError('Source build failed: ' + str(result.get('error', 'invalid worker response') if isinstance(result, dict) else 'invalid worker response')[:4000])
    if result['source_snapshot_id'] != snapshot['id'] or result['isolation_checks'] != CHECKS:
        raise SetupError('Build source identity or isolation mismatch')
    raw = base64.b64decode(result.pop('artifact_base64'), validate=True)
    _validate_contract(result, 'library-build.schema.json')
    if not raw.startswith(b'\x7fELF') or not 1024 <= len(raw) <= 32 * 1024 * 1024 or digest(raw) != result['artifact_sha256']:
        raise SetupError('Build artifact identity mismatch')
    if not safe_path(result['artifact_name']) or '/' in result['artifact_name']:
        raise SetupError('Invalid library artifact name')
    validate_build_recipe(result)
    validate_native(result['native_source'], snapshot, source_dir)
    return raw


def validate_build_recipe(build):
    target = {'aarch64': 'linux-aarch64', 'x86_64': 'linux-x86_64'}.get(build['machine'])
    configure = ['perl', '/source/Configure', target, 'shared', 'no-asm', 'no-module',
                 'no-tests', 'no-apps', 'no-docs', 'no-quic', '-O1']
    if target is None or build['configure'] != configure or build['commands'] != [configure, ['make', '-j2', 'build_generated'], ['make', '-j2', 'libcrypto.so']]:
        raise ValueError('Unsupported build recipe/backend configuration')
    if not 1 <= len(build['compilation_commands']) <= 5000 or any(
            record['directory'] != '/work/build' for record in build['compilation_commands']):
        raise ValueError('Missing or unexpected compilation provenance')


def check_tests(result, artifact_sha, vectors):
    if not isinstance(result, dict) or result.get('status') != 'completed':
        raise SetupError('Artifact tests failed to run: ' + str(result.get('error', 'invalid response') if isinstance(result, dict) else 'invalid response')[:2000])
    _validate_contract(result, 'library-tests.schema.json')
    if (result['artifact_sha256'] != artifact_sha or result['runtime']['loaded_sha256'] != artifact_sha
            or result['runtime']['loaded_path'] != '/runner/libcrypto.so'
            or result['runtime']['provider'] != 'default' or result['isolation_checks'] != CHECKS):
        raise SetupError('Loaded artifact/provider identity or isolation mismatch')
    cases = library_cases(vectors)
    observed = result['observations']
    if not isinstance(observed, list) or len(observed) != len(cases) or [o['id'] for o in observed] != [c['id'] for c in cases]:
        raise SetupError('Artifact tests omitted or fabricated cases')
    rows = []
    for case, record in zip(cases, observed):
        if set(record) != {'id', 'observation'}: raise SetupError('Invalid test observation')
        _validate_contract(record['observation'], 'validation-observation.schema.json')
        rows.append(dict({k: v for k, v in case.items() if k != 'inputs'},
                         observation=record['observation'], status=evaluate(case, record['observation'])))
    return rows


def requirement_links(index, results):
    patterns = {'F203-IMPLICIT-REJECTION': ('decap', 'ossl_ml_kem_decap'),
                'F203-DECAPS-INPUT': ('ossl_ml_kem_decap', 'ossl_ml_kem_parse_private_key'),
                'F204-VERIFY': ('ossl_ml_dsa_verify', 'ml_dsa_verify_internal'),
                'F204-CONTEXT': ('ossl_ml_dsa_verify', 'ossl_ml_dsa_mu_init')}
    return [{'requirement_id': rid, 'status': 'not_assessed_in_full',
             'source_symbol_ids': [s['id'] for s in index['symbols'] if s['name'] in names],
             'case_ids': [c['id'] for c in results if rid in c['requirement_ids']],
             'link_basis': 'adapter-reviewed function names; candidates, not proof of requirement applicability or runtime reachability'}
            for rid, names in patterns.items()]


def run_library(repository, image=None, mutation='none', timeout=600, checkpoint=None, artifacts_dir=None):
    if type(timeout) is not int or not 1 <= timeout <= 1200: raise ValueError('Build timeout must be 1-1200 seconds')
    if image is not None and (not isinstance(image, str) or not image or len(image) > 256 or image.startswith('-')):
        raise ValueError('Invalid library toolchain image name')
    if artifacts_dir is not None:
        root, output = Path(repository).resolve(), Path(artifacts_dir).resolve()
        if root == output or root in output.parents or output.exists():
            raise ValueError('Artifact output must be a new directory outside the repository')
    vectors, vector_raw, vector_manifest = load_vectors()
    catalog, catalog_sha = load_catalog()
    harness = harness_bytes()
    with tempfile.TemporaryDirectory(prefix='pqscan-library-') as tmp:
        base = Path(tmp); base.chmod(0o755)
        source = base / 'source'
        snapshot = capture(repository, source, mutation=mutation)
        subject = detect_subject(snapshot)
        report = {'schema_version': '1.0', 'tool': 'pqscan-library', 'profile': PROFILE,
                  'status': 'pending' if image else 'inspected', 'origin': 'local_pipeline',
                  'generated_at': datetime.now(timezone.utc).isoformat(), 'subject': subject,
                  'snapshot': snapshot, 'recipe': RECIPE, 'image': None, 'timeout_seconds': timeout,
                  'harness_sha256': {name: digest(raw) for name, raw in harness.items()},
                  'runner_sha256': digest(read_bounded(Path(__file__))),
                  'snapshot_code_sha256': digest(read_bounded(ROOT / 'pqscan_analysis/library_snapshot.py')),
                  'dockerfile_sha256': digest(read_bounded(ROOT / 'validation/library-container/Dockerfile')),
                  'vectors_sha256': digest(vector_raw), 'vector_sources': vectors['sources'],
                  'catalog': {'id': catalog['catalog_id'], 'version': catalog['version'], 'sha256': catalog_sha},
                  'build': None, 'tests': None, 'case_results': [], 'summary': summary([]),
                  'source_build_binding': {'status': 'not_built'}, 'requirement_links': [],
                  'execution_commands': [], 'error': None, 'correctness_verified': False,
                  'compliance_certified': False, 'exploitability': 'not_assessed', 'boundary': BOUNDARY}
        if checkpoint: checkpoint(report, False)
        if not image: return report
        try:
            if subject['adapter'] != RECIPE: raise SetupError('No reviewed build adapter for this library; inspection remains available')
            if any((source / p).exists() for p in ('configdata.pm', 'Makefile')):
                raise SetupError('OpenSSL recipe requires an unconfigured source tree; existing generated build files are not reused')
            report['image'] = inspect_image(image)
            staging = base / 'runner'; staging.mkdir()
            for name, raw in harness.items():
                path = staging / name; path.write_bytes(raw); path.chmod(0o555 if name == 'library_compiler.py' else 0o444)
            (staging / 'snapshot.json').write_text(json.dumps(snapshot)); (staging / 'snapshot.json').chmod(0o444)
            (staging / 'vectors.json').write_bytes(vector_raw); (staging / 'vectors.json').chmod(0o444)
            name = 'pqscan-library-' + uuid.uuid4().hex
            command = container_command(report['image']['id'], staging, source, name, 'build')
            report['execution_commands'].append(command)
            build = execute_container(command, timeout, 64 * 1024 * 1024)
            artifact = check_build(build, snapshot, source)
            report['build'] = build
            (staging / 'libcrypto.so').write_bytes(artifact); (staging / 'libcrypto.so').chmod(0o444)
            if artifacts_dir:
                output = Path(artifacts_dir)
                output.mkdir(parents=True, exist_ok=False)
                (output / 'libcrypto.so').write_bytes(artifact)
                (output / 'snapshot.json').write_text(json.dumps(snapshot, indent=2) + '\n')
                (output / 'compile_commands.json').write_text(json.dumps(build['compilation_commands'], indent=2) + '\n')
            name = 'pqscan-library-' + uuid.uuid4().hex
            command = container_command(report['image']['id'], staging, None, name, 'test')
            report['execution_commands'].append(command)
            tested = execute_container(command, min(timeout, 60), 2 * 1024 * 1024)
            rows = check_tests(tested, build['artifact_sha256'], vectors)
            report.update(tests=tested, case_results=rows, summary=summary(rows), status=outcome(rows))
            report['source_build_binding'] = {'status': 'recorded_local_pipeline', 'snapshot_id': snapshot['id'],
                'artifact_sha256': build['artifact_sha256'],
                'compilation_commands_sha256': digest(canonical(build['compilation_commands']).encode()),
                'backend': 'portable-no-asm', 'provider': 'default'}
            report['requirement_links'] = requirement_links(build['native_source'], rows)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
            report['status'] = 'setup_error'; report['error'] = (type(exc).__name__ + ': ' + str(exc))[:5000]
        except BaseException:
            report['status'] = 'setup_error'; report['error'] = 'Library pipeline interrupted'
            if checkpoint: checkpoint(report, True)
            raise
        if checkpoint: checkpoint(report, True)
        return report


def validate_report(report):
    _validate_contract(report, 'library-report.schema.json')
    validate_snapshot(report['snapshot'])
    if report['subject'] != detect_subject(report['snapshot']): raise ValueError('Library subject does not match source manifest')
    if report['harness_sha256'] != {n: digest(b) for n, b in harness_bytes().items()}:
        raise ValueError('Preserve the matching scanner revision for this library report')
    if report['runner_sha256'] != digest(read_bounded(Path(__file__))) or report['snapshot_code_sha256'] != digest(read_bounded(ROOT / 'pqscan_analysis/library_snapshot.py')):
        raise ValueError('Library runner revision mismatch')
    if report['dockerfile_sha256'] != digest(read_bounded(ROOT / 'validation/library-container/Dockerfile')):
        raise ValueError('Build recipe revision mismatch')
    vectors, raw, _ = load_vectors()
    catalog, catalog_sha = load_catalog()
    if report['vectors_sha256'] != digest(raw) or report['vector_sources'] != vectors['sources']:
        raise ValueError('Library test oracle revision mismatch')
    if report['catalog'] != {'id': catalog['catalog_id'], 'version': catalog['version'], 'sha256': catalog_sha}:
        raise ValueError('Requirement catalog mismatch')
    if report['boundary'] != BOUNDARY or report['summary'] != summary(report['case_results']): raise ValueError('Invalid report boundary/counts')
    if report['build'] is not None:
        build = report['build']
        if build['source_snapshot_id'] != report['snapshot']['id'] or build['isolation_checks'] != CHECKS:
            raise ValueError('Build source binding mismatch')
        validate_build_recipe(build)
        platform = {'aarch64': 'linux/arm64', 'x86_64': 'linux/amd64'}[build['machine']]
        if report['image'] is None or report['image']['platform'] != platform:
            raise ValueError('Build machine does not match recorded toolchain image')
        validate_native(build['native_source'], report['snapshot'])
    for number, command in enumerate(report['execution_commands']):
        phase = 'build' if number == 0 else 'test'
        try:
            name = command[command.index('--name') + 1]
            mounts = [command[i + 1] for i, arg in enumerate(command) if arg == '--mount']
            if len(mounts) != (2 if phase == 'build' else 1): raise ValueError('Wrong mount count')
            staging = mounts[0].removeprefix('type=bind,src=').removesuffix(',dst=/runner,readonly')
            source = mounts[1].removeprefix('type=bind,src=').removesuffix(',dst=/source,readonly') if phase == 'build' else None
            if not re.fullmatch(r'pqscan-library-[a-f0-9]{32}', name): raise ValueError('Invalid container name')
            if command != container_command(report['image']['id'], staging, source, name, phase):
                raise ValueError('Recorded execution contradicts isolation policy')
        except (IndexError, KeyError, TypeError) as exc:
            raise ValueError('Invalid library execution command') from exc
    if report['status'] in ('passed', 'failed', 'inconclusive'):
        if len(report['execution_commands']) != 2 or report['image'] is None:
            raise ValueError('Completed library pipeline lacks execution provenance')
        build = report['build']
        if build is None: raise ValueError('Completed pipeline lacks a built artifact')
        rows = check_tests(report['tests'], build['artifact_sha256'], vectors)
        binding = {'status': 'recorded_local_pipeline', 'snapshot_id': report['snapshot']['id'],
                   'artifact_sha256': build['artifact_sha256'],
                   'compilation_commands_sha256': digest(canonical(build['compilation_commands']).encode()),
                   'backend': 'portable-no-asm', 'provider': 'default'}
        if (report['case_results'] != rows or report['status'] != outcome(rows)
                or report['source_build_binding'] != binding or report['error'] is not None
                or report['requirement_links'] != requirement_links(build['native_source'], rows)):
            raise ValueError('Library test/binding claims do not match evidence')
    elif report['source_build_binding'] != {'status': 'not_built'} or report['case_results'] or report['tests']:
        raise ValueError('Incomplete pipeline cannot claim source-bound tests')
    if report['status'] == 'setup_error' and not report['error']: raise ValueError('Setup failure lacks an error')
    return report


def load_report(path):
    try: report = validate_report(parse_json(read_bounded(Path(path), 16 * 1024 * 1024)))
    except (TypeError, KeyError, AttributeError, RecursionError) as exc: raise ValueError('Malformed library report') from exc
    report['origin'] = 'imported_unverified'
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='Inspect library sources or explicitly build/test a captured OpenSSL implementation in isolation.')
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('inspect', 'run'):
        p = sub.add_parser(name)
        p.add_argument('repository', type=Path)
        p.add_argument('-o', '--output', type=Path, required=True)
        if name == 'run':
            p.add_argument('--image', required=True, help='prepared local library toolchain image; never pulled automatically')
            p.add_argument('--timeout', type=int, default=600)
            p.add_argument('--mutation', choices=['none', *MUTATIONS, 'kem-repaired', 'dsa-repaired'], default='none')
    p = sub.add_parser('read'); p.add_argument('report', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'read': report = load_report(args.report)
        else:
            from pqscan import save_json
            output = args.output.expanduser().absolute()
            repo = args.repository.expanduser().resolve()
            if repo == output.resolve() or repo in output.resolve().parents:
                raise ValueError('Library reports/artifacts must be outside the captured repository')
            if output.exists() or output.is_symlink(): raise ValueError('Output already exists; choose a new filename')
            artifact_dir = output.with_name(output.stem + '.artifacts')
            if artifact_dir.exists() or artifact_dir.is_symlink(): raise ValueError('Artifact output directory already exists')
            output.parent.mkdir(parents=True, exist_ok=True)
            report = run_library(repo, getattr(args, 'image', None), getattr(args, 'mutation', 'none'),
                                 getattr(args, 'timeout', 600),
                                 checkpoint=lambda value, replace: save_json(value, output, replace=replace),
                                 artifacts_dir=artifact_dir if args.command == 'run' else None)
        print(f"Library analysis: {report['status']} ({report['origin']})")
        print('Snapshot: ' + report['snapshot']['id'])
        print(canonical(report['summary']))
        if report['error']: print(''.join(c if c.isprintable() else ' ' for c in report['error']))
        print(BOUNDARY)
        return 0 if report['status'] in ('passed', 'inspected') else (1 if report['status'] == 'failed' else 2)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Library analysis error: ' + ''.join(c if c.isprintable() else ' ' for c in str(exc)))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
