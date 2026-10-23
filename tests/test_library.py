"""Library snapshot, native-index and source/build/test binding regressions."""
import base64
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from pqscan_analysis import library as lib
from pqscan_analysis.library_snapshot import capture, validate_snapshot, digest, identity, MUTATIONS
from pqscan_analysis.library_native import parse_flags
from pqscan_analysis.library_cases import library_cases
from pqscan_analysis.validation import load_vectors, canonical


class LibraryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'; self.repo.mkdir()
        self.write('Configure', '# untrusted build script; never run by inspection\n')
        self.write('VERSION.dat', 'MAJOR=4\nMINOR=2\n')
        self.write('include/openssl/evp.h.in', '/* generated header template */\n')
        for path, old, _ in MUTATIONS.values(): self.write(path, 'int function(void) {\n    ' + old + '\n}\n')
        self.image = {'requested': 'test-image', 'id': 'sha256:' + 'a' * 64, 'platform': 'linux/arm64'}
        self.vectors = load_vectors()[0]
        self.artifact = b'\x7fELF' + b'x' * 2048

    def write(self, name, value):
        p = self.repo / name; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(value.encode() if isinstance(value, str) else value)
        return p

    def snapshot(self, mutation='none'):
        return capture(self.repo, self.root / ('snapshot-' + mutation), mutation=mutation)

    def native(self, snapshot):
        entry = next(e for e in snapshot['files'] if e['path'] == 'crypto/ml_kem/ml_kem.c')
        return {'parser': 'libclang-14', 'translation_units': [{'path': entry['path'], 'file_sha256': entry['sha256'], 'arguments': ['-I/source/include'], 'macros_defined': 0, 'macro_expansions': 0}],
                'symbols': [], 'calls': [], 'source_slices': [], 'source_chars': 0,
                'coverage': {'partial': True, 'gaps': [], 'selected_prefixes': ['crypto/ml_kem/'], 'candidate_translation_units': 1, 'call_budget_reached': False},
                'limitations': ['Only selected portable C translation units.']}

    def build_result(self, snapshot):
        config = ['perl', '/source/Configure', 'linux-aarch64', 'shared', 'no-asm', 'no-module', 'no-tests', 'no-apps', 'no-docs', 'no-quic', '-O1']
        return {'status': 'built', 'source_snapshot_id': snapshot['id'], 'isolation_checks': copy.deepcopy(lib.CHECKS),
                'artifact_base64': base64.b64encode(self.artifact).decode(), 'artifact_sha256': digest(self.artifact),
                'artifact_name': 'libcrypto.so.4', 'configure': config, 'commands': [config, ['make', '-j2', 'build_generated'], ['make', '-j2', 'libcrypto.so']],
                'compiler_version': 'Debian clang version 14', 'toolchain_packages_sha256': 'b' * 64, 'build_log_sha256': 'c' * 64,
                'compilation_commands': [{'directory': '/work/build', 'arguments': ['-c', '/source/crypto/ml_kem/ml_kem.c', '-O1']}],
                'generated_files': {p: 'a' * 64 for p in ('Makefile', 'configdata.pm', 'include/openssl/configuration.h')},
                'native_source': self.native(snapshot), 'machine': 'aarch64', 'python': '3.11.14'}

    def test_result(self):
        return {'status': 'completed', 'artifact_sha256': digest(self.artifact),
                'runtime': {'version': 'OpenSSL 4.2.0-dev', 'provider': 'default', 'loaded_path': '/runner/libcrypto.so', 'loaded_sha256': digest(self.artifact)},
                'isolation_checks': copy.deepcopy(lib.CHECKS),
                'observations': [{'id': c['id'], 'observation': copy.deepcopy(c['expected'])} for c in library_cases(self.vectors)]}

    def completed(self, callback=None):
        def execute(command, timeout, limit):
            mounts = [command[i + 1] for i, value in enumerate(command) if value == '--mount']
            staging = Path(mounts[0].split('src=')[1].split(',dst=')[0])
            if command[-1].endswith('library_worker.py'):
                snapshot = json.loads((staging / 'snapshot.json').read_text())
                return self.build_result(snapshot)
            return callback(self.test_result()) if callback else self.test_result()
        with mock.patch.object(lib, 'inspect_image', return_value=self.image), mock.patch.object(lib, 'execute_container', side_effect=execute):
            return lib.run_library(self.repo, 'test-image')

    def test_inspection_never_invokes_docker_git_builds_or_imports(self):
        self.write('.git/config', '[core]\nfsmonitor = malicious-command\n')
        with mock.patch.object(lib, 'inspect_image', side_effect=AssertionError('no execution')), mock.patch.object(lib, 'bounded_process', side_effect=AssertionError('no execution')):
            report = lib.run_library(self.repo)
        lib.validate_report(report)
        self.assertEqual(report['status'], 'inspected')
        self.assertEqual(report['source_build_binding'], {'status': 'not_built'})
        self.assertEqual(report['subject']['kind'], 'library_repository')
        self.assertNotIn('.git/config', [f['path'] for f in report['snapshot']['files']])

    def test_unknown_library_gets_inspection_not_fabricated_build_support(self):
        (self.repo / 'Configure').unlink()
        report = lib.run_library(self.repo)
        self.assertEqual(report['subject']['adapter_status'], 'unsupported')
        with mock.patch.object(lib, 'execute_container') as execute:
            report = lib.run_library(self.repo, 'test-image')
        execute.assert_not_called()
        self.assertEqual(report['status'], 'setup_error')
        lib.validate_report(report)

    def test_snapshot_captures_ignored_untracked_and_executable_inputs(self):
        self.write('.gitignore', 'untracked.bin\n')
        self.write('untracked.bin', b'\x00\xff')
        executable = self.write('build-helper', '#!/bin/sh\nexit 1\n'); executable.chmod(0o755)
        snapshot = self.snapshot()
        validate_snapshot(snapshot)
        entries = {f['path']: f for f in snapshot['files']}
        self.assertEqual(entries['untracked.bin']['sha256'], digest(b'\x00\xff'))
        self.assertTrue(entries['build-helper']['executable'])
        self.assertFalse(snapshot['atomic'])

    def test_dirty_source_changes_identity_and_original_is_untouched(self):
        before = self.snapshot()
        original = (self.repo / 'crypto/ml_kem/ml_kem.c').read_bytes()
        mutated = self.snapshot('kem-zero-secret')
        repaired = self.snapshot('kem-repaired')
        self.assertNotEqual(before['id'], mutated['id'])
        self.assertEqual(before['id'], repaired['id'])
        self.assertEqual(before['id'], mutated['original_id'])
        self.assertEqual((self.repo / 'crypto/ml_kem/ml_kem.c').read_bytes(), original)
        validate_snapshot(mutated); validate_snapshot(repaired)
        self.write('new.c', 'int added;\n')
        after = capture(self.repo, self.root / 'after')
        self.assertNotEqual(before['id'], after['id'])

    def test_mutation_anchor_mismatch_is_explicit(self):
        path, old, _ = MUTATIONS['kem-zero-secret']
        self.write(path, old + '\n' + old)
        with self.assertRaisesRegex(ValueError, 'not unique'): self.snapshot('kem-zero-secret')

    def test_signature_mutation_and_repair_preserve_original(self):
        baseline = self.snapshot()
        mutant = self.snapshot('dsa-accept-invalid')
        repaired = self.snapshot('dsa-repaired')
        self.assertNotEqual(baseline['id'], mutant['id'])
        self.assertEqual(baseline['id'], repaired['id'])
        validate_snapshot(mutant); validate_snapshot(repaired)
        path, old, _ = MUTATIONS['dsa-accept-invalid']
        self.assertIn(old, (self.repo / path).read_text())

    def test_symlinks_special_files_and_incomplete_snapshots_are_rejected(self):
        link = self.repo / 'escape'; link.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'Symlinks'): self.snapshot()
        link.unlink()
        os.mkfifo(self.repo / 'pipe')
        with self.assertRaisesRegex(ValueError, 'special files'): capture(self.repo, self.root / 'fifo')
        (self.repo / 'pipe').unlink()
        with self.assertRaisesRegex(ValueError, 'limit'): capture(self.repo, self.root / 'small', max_bytes=1)
        with self.assertRaisesRegex(ValueError, 'limit'): capture(self.repo, self.root / 'few', max_files=1)

    def test_snapshot_never_follows_git_worktree_or_submodule_pointer(self):
        self.write('.git', 'gitdir: /outside/private/path\n')
        snapshot = self.snapshot()
        self.assertIsNone(snapshot['revision_hint'])
        self.assertIn('.git', snapshot['excluded_vcs_paths'])

    def test_empty_directory_trees_are_bounded(self):
        from pqscan_analysis import library_snapshot
        (self.repo / 'empty/a/b/c').mkdir(parents=True)
        with mock.patch.object(library_snapshot, 'MAX_ENTRIES', 2):
            with self.assertRaisesRegex(ValueError, 'entry limit'): self.snapshot()
        with mock.patch.object(library_snapshot, 'MAX_DEPTH', 2):
            with self.assertRaisesRegex(ValueError, 'depth limit'): capture(self.repo, self.root / 'deep')

    def test_snapshot_identity_and_mutation_claim_tampering(self):
        snapshot = self.snapshot('kem-zero-secret')
        for kind in ('hash', 'path', 'mutation', 'original'):
            bad = copy.deepcopy(snapshot)
            if kind == 'hash': bad['files'][0]['sha256'] = '0' * 64
            if kind == 'path': bad['files'][0]['path'] = '../outside'
            if kind == 'mutation': bad['mutation']['repaired'] = True
            if kind == 'original': bad['original_id'] = '0' * 64
            with self.subTest(kind=kind), self.assertRaises(ValueError): validate_snapshot(bad)

    def test_compiler_metadata_is_allowlisted_not_executed(self):
        flags = parse_flags(['-I/source/include', '-Iinclude', '-DFEATURE=1', '-UOLD', '-O1', '-pthread', '-MMD', '-MF', 'a.d.tmp', '-c', '/source/a.c', '-o', 'a.o'])
        self.assertIn('-I/work/build/include', flags)
        self.assertIn('-DFEATURE=1', flags)
        for args in [['@commands'], ['-Xclang', '-load', 'plugin.so'], ['-fplugin=bad.so'], ['-I/etc'], ['-I../../etc'], ['-include', '/etc/passwd'], ['$(touch hacked)'], ['-MF']]:
            with self.subTest(args=args), self.assertRaises(ValueError): parse_flags(args)

    def test_build_and_test_commands_have_distinct_readonly_mounts(self):
        build = lib.container_command(self.image['id'], '/tmp/harness', '/tmp/source', 'pqscan-library-' + 'a' * 32, 'build')
        test = lib.container_command(self.image['id'], '/tmp/harness', None, 'pqscan-library-' + 'a' * 32, 'test')
        self.assertEqual(build.count('--mount'), 2)
        self.assertEqual(test.count('--mount'), 1)
        for command in (build, test):
            for flag in ('--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pull=never', '--user=65534:65534'):
                self.assertIn(flag, command)
        self.assertFalse(any('dst=/source' in arg for arg in test))
        with self.assertRaises(ValueError): lib.container_command(self.image['id'], '/tmp/a,b', None, 'name', 'test')

    def test_complete_pipeline_binds_actual_artifact_and_preserves_partial_scope(self):
        report = self.completed(); lib.validate_report(report)
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['summary']['passed'], 33)
        self.assertEqual(report['source_build_binding']['snapshot_id'], report['snapshot']['id'])
        self.assertEqual(report['source_build_binding']['artifact_sha256'], digest(self.artifact))
        self.assertFalse(report['correctness_verified']); self.assertFalse(report['compliance_certified'])
        self.assertTrue(all(r['status'] == 'not_assessed_in_full' for r in report['requirement_links']))

    def test_artifact_substitution_does_not_receive_source_binding(self):
        def wrong(response): response['runtime']['loaded_sha256'] = 'b' * 64; return response
        report = self.completed(wrong)
        self.assertEqual(report['status'], 'setup_error')
        self.assertEqual(report['source_build_binding'], {'status': 'not_built'})
        self.assertEqual(report['case_results'], [])
        lib.validate_report(report)

    def test_failed_and_error_observations_remain_distinct(self):
        def mismatch(response): response['observations'][0]['observation'] = {'kind': 'bytes', 'value': '00' * 32}; return response
        failed = self.completed(mismatch)
        self.assertEqual(failed['status'], 'failed'); self.assertEqual(failed['summary']['failed'], 1)
        def error(response): response['observations'][0]['observation'] = {'kind': 'exception', 'value': 'RuntimeError'}; return response
        errored = self.completed(error)
        self.assertEqual(errored['status'], 'inconclusive'); self.assertEqual(errored['summary']['error'], 1)

    def test_evp_operational_error_is_not_signature_rejection(self):
        from pqscan_analysis.library_adapter import Adapter
        adapter = Adapter.__new__(Adapter)
        adapter.lib = mock.Mock()
        adapter.ctx, adapter.properties = 1, b'provider=default'
        adapter.import_key = mock.Mock(return_value=2)
        adapter.lib.EVP_MD_CTX_new.return_value = 3
        adapter.lib.EVP_DigestVerifyInit_ex.return_value = 1
        for result in (0, 1, -1):
            adapter.lib.EVP_DigestVerify.return_value = result
            if result == -1:
                with self.assertRaises(RuntimeError): adapter.verify_context(b'pk', b'message', b'context', b'sig')
            else:
                self.assertEqual(adapter.verify_context(b'pk', b'message', b'context', b'sig'), bool(result))

    def test_native_source_citations_checked_against_snapshot(self):
        snapshot = self.snapshot()
        native = self.native(snapshot)
        path = 'crypto/ml_kem/ml_kem.c'; source = (self.repo / path).read_text()
        filehash = digest(source.encode())
        native['symbols'] = [{'id': 's', 'usr': 'c:@F@decap', 'name': 'decap', 'path': path, 'start_line': 1, 'end_line': 3, 'file_sha256': filehash}]
        native['source_slices'] = [{'id': 's:slice', 'symbol_id': 's', 'path': path, 'start_line': 1, 'end_line': 3, 'text': source, 'sha256': filehash, 'file_sha256': filehash}]
        native['source_chars'] = len(source)
        lib.validate_native(native, snapshot, self.repo)
        native['source_slices'][0]['text'] = source.replace('function', 'madeupxx')
        native['source_slices'][0]['sha256'] = digest(native['source_slices'][0]['text'].encode())
        with self.assertRaises(ValueError): lib.validate_native(native, snapshot, self.repo)

    def test_saved_reports_never_execute_and_cannot_self_certify(self):
        report = self.completed(); path = self.root / 'report.json'; path.write_text(json.dumps(report))
        with mock.patch.object(lib, 'execute_container', side_effect=AssertionError('no execution')):
            loaded = lib.load_report(path)
        self.assertEqual(loaded['origin'], 'imported_unverified')
        for kind in ('binding', 'case', 'oracle', 'source', 'network', 'certification', 'recipe', 'architecture'):
            bad = copy.deepcopy(report)
            if kind == 'binding': bad['source_build_binding']['artifact_sha256'] = 'b' * 64
            if kind == 'case': bad['case_results'].pop()
            if kind == 'oracle': bad['case_results'][0]['expected']['value'] = '00' * 32
            if kind == 'source': bad['build']['source_snapshot_id'] = '0' * 64
            if kind == 'network': bad['execution_commands'][0][bad['execution_commands'][0].index('--network=none')] = '--network=host'
            if kind == 'certification': bad['compliance_certified'] = True
            if kind == 'recipe': bad['build']['configure'].remove('no-asm')
            if kind == 'architecture': bad['image']['platform'] = 'linux/amd64'
            with self.subTest(kind=kind), self.assertRaises(ValueError): lib.validate_report(bad)

    def test_timeout_attempts_container_cleanup(self):
        command = lib.container_command(self.image['id'], '/tmp/harness', None, 'pqscan-library-' + 'a' * 32, 'test')
        with mock.patch.object(lib, 'bounded_process', side_effect=[lib.SetupError('timed out'), (0, b'', b'')]) as call:
            with self.assertRaises(lib.SetupError): lib.execute_container(command, 1, 1024)
        self.assertEqual(call.call_args_list[-1].args[0][:3], ['docker', 'rm', '--force'])

    def test_existing_and_inside_repository_outputs_refused(self):
        path = self.root / 'report.json'; path.write_text('preserve')
        with mock.patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(lib.main(['inspect', str(self.repo), '-o', str(path)]), 2)
            self.assertEqual(lib.main(['inspect', str(self.repo), '-o', str(self.repo / 'bad.json')]), 2)
        self.assertEqual(path.read_text(), 'preserve')
        self.assertFalse((self.repo / 'bad.json').exists())

    def test_inspection_cli_roundtrip(self):
        output = self.root / 'inspection.json'
        with mock.patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(lib.main(['inspect', str(self.repo), '-o', str(output)]), 0)
            self.assertEqual(lib.main(['read', str(output)]), 0)
        self.assertEqual(lib.load_report(output)['status'], 'inspected')

    def test_independent_schema(self):
        try: import jsonschema
        except ImportError: self.skipTest('Optional JSON Schema validator unavailable')
        schema = json.loads((lib.ROOT / 'standards/library-report.schema.json').read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(self.completed(), schema)


@unittest.skipUnless(os.environ.get('PQSCAN_LIBRARY_IMAGE') and os.environ.get('PQSCAN_LIBRARY_REPO'), 'Explicit source-build integration opt-in required')
class LibraryIntegrationTests(unittest.TestCase):
    def test_source_baseline_mutant_and_repaired_builds(self):
        image, repo = os.environ['PQSCAN_LIBRARY_IMAGE'], os.environ['PQSCAN_LIBRARY_REPO']
        snapshots = {}
        # OpenSSL's import-time pairwise test blocks the all-zero KEM mutation;
        # those are execution errors, not output mismatches. The DSA mutation
        # reaches verification and must produce explicit false-accept failures.
        for mutation, failures, errors in [('none', 0, 0), ('kem-zero-secret', 0, 10),
                                          ('kem-repaired', 0, 0), ('dsa-accept-invalid', 15, 0),
                                          ('dsa-repaired', 0, 0)]:
            report = lib.run_library(repo, image, mutation)
            lib.validate_report(report)
            expected = 'failed' if failures else ('inconclusive' if errors else 'passed')
            self.assertEqual(report['status'], expected, report['error'])
            self.assertEqual(report['summary'], {'passed': 33 - failures - errors, 'failed': failures, 'error': errors})
            self.assertGreater(len(report['build']['native_source']['symbols']), 0)
            snapshots[mutation] = report['snapshot']['id']
        self.assertEqual(snapshots['none'], snapshots['kem-repaired'])
        self.assertEqual(snapshots['none'], snapshots['dsa-repaired'])
        self.assertNotEqual(snapshots['none'], snapshots['kem-zero-secret'])


if __name__ == '__main__': unittest.main()
