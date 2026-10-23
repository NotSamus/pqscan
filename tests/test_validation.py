"""Isolated validator oracles, provenance, failure modes and designated mutants."""
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from pqscan_analysis import validation as v
from pqscan_analysis.validation_cases import cases_from_vectors, evaluate, observe


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vectors, self.raw, self.manifest_raw = v.load_vectors()
        self.cases = cases_from_vectors(self.vectors)
        self.runtime = {'versions': {'pqcrypto': '0.3.4', 'cffi': '1.17.1', 'pycparser': '2.22'},
                        'python': '3.11.14', 'platform': 'Linux test', 'machine': 'aarch64',
                        'isolation_checks': {'uid': 65534, 'active_interfaces': ['lo'], 'root_read_only': True,
                                             'no_new_privileges': True, 'capabilities_zero': True, 'seccomp_filter': True},
                        'artifacts': [{'module': name, 'file': 'module.so', 'sha256': 'a' * 64} for name in
                                      ['pqcrypto.kem.ml_kem_768', 'pqcrypto.sign.ml_dsa_65',
                                       'pqcrypto._kem.ml_kem_768', 'pqcrypto._sign.ml_dsa_65']],
                        'build_flags': 'Not exposed by wheel'}
        self.image = {'requested': 'test-image', 'id': 'sha256:' + 'a' * 64, 'platform': 'linux/arm64'}
        self.response = {'status': 'completed', 'fixture': 'provider', 'vectors_sha256': v.sha(self.raw),
                         'runtime': self.runtime, 'observations': [{'id': c['id'], 'observation': copy.deepcopy(c['expected'])} for c in self.cases]}

    def fake_process(self, command, timeout, **kwargs):
        if command[:3] == ['docker', 'rm', '--force']:
            return 1, b'', b'No such container'
        return 0, json.dumps(self.response).encode(), b''

    def completed(self):
        with mock.patch.object(v, 'inspect_image', return_value=self.image), mock.patch.object(v, 'bounded_process', side_effect=self.fake_process):
            return v.run_validation('test-image')

    def test_pinned_vectors_have_positive_negative_and_implicit_rejection_oracles(self):
        self.assertEqual(len(self.cases), 33)
        self.assertEqual(len({c['id'] for c in self.cases}), 33)
        kem = [c for c in self.cases if c['kind'] == 'nist_known_answer' and c['operation'] == 'decapsulate']
        self.assertEqual(len(kem), 10)
        self.assertEqual(sum(c['requirement_ids'] == ['F203-IMPLICIT-REJECTION'] for c in kem), 5)
        dsa = [c for c in self.cases if c['kind'] == 'nist_known_answer' and c['operation'] == 'verify_context']
        self.assertEqual(sum(c['expected']['value'] is True for c in dsa), 3)
        self.assertEqual(sum(c['expected']['value'] is False for c in dsa), 12)
        self.assertEqual({s['commit'] for s in self.vectors['sources']}, {'975de31eb83d87039ec88934fdc47d8c312b892d'})

    def test_derived_lengths_are_actual_invalid_lengths(self):
        for case in self.cases:
            if case['kind'] == 'derived_negative' and case['operation'] == 'decapsulate':
                field, size = case['id'].split('-')[1], int(case['id'].split('-')[-1])
                self.assertEqual(len(bytes.fromhex(case['inputs'][field])), size)
                self.assertEqual(case['expected'], {'kind': 'exception', 'value': 'ValueError'})

    def test_vector_tampering_fails_before_execution(self):
        changed = bytearray(self.raw); changed[-10] ^= 1
        original = v.read_bounded
        def read(path, *args):
            return bytes(changed) if path.name == 'acvp-selected.json' else original(path, *args)
        with mock.patch.object(v, 'read_bounded', side_effect=read), mock.patch.object(v, 'bounded_process') as process:
            with self.assertRaises(ValueError):
                v.run_validation('test-image')
        process.assert_not_called()

    def test_isolation_command_is_fixed_no_shell_and_has_only_staged_mount(self):
        command = v.container_command(self.image['id'], '/tmp/staged', 'pqscan-validation-' + 'a' * 32, 'provider')
        for flag in ('--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                     '--user=65534:65534', '--pids-limit=64', '--memory=256m', '--memory-swap=256m', '--cpus=1', '--pull=never'):
            self.assertIn(flag, command)
        self.assertEqual(command.count('--mount'), 1)
        self.assertIn('type=bind,src=/tmp/staged,dst=/runner,readonly', command)
        self.assertNotIn('-e', command)
        self.assertIn('-I', command)
        self.assertEqual(command[-1], 'provider')

    def test_staging_contains_only_harness_and_corpus_and_is_cleaned(self):
        paths = []
        def run(command, timeout, **kwargs):
            if command[1] == 'run':
                mount = command[command.index('--mount') + 1]
                path = Path(mount.split('src=')[1].split(',dst=')[0]); paths.append(path)
                self.assertEqual({p.name for p in path.iterdir()}, {'validation_worker.py', 'validation_adapter.py', 'validation_cases.py', 'vectors.json'})
                self.assertEqual((path / 'vectors.json').read_bytes(), self.raw)
                self.assertEqual((path / 'vectors.json').stat().st_mode & 0o777, 0o444)
            return self.fake_process(command, timeout, **kwargs)
        with mock.patch.object(v, 'inspect_image', return_value=self.image), mock.patch.object(v, 'bounded_process', side_effect=run):
            report = v.run_validation('test-image')
        self.assertEqual(report['status'], 'passed')
        self.assertTrue(paths)
        self.assertFalse(paths[0].exists())

    def test_completed_report_has_no_global_verification_or_repository_binding(self):
        result = self.completed()
        v.validate_report(result)
        self.assertEqual(result['summary'], {'passed': 33, 'failed': 0, 'error': 0})
        self.assertFalse(result['correctness_verified'])
        self.assertFalse(result['compliance_certified'])
        self.assertEqual(result['coverage']['repository_binding'], 'none')
        self.assertEqual(result['coverage']['requirements_assessed_in_full'], 0)
        self.assertEqual(result['exploitability'], 'not_assessed')

    def test_mismatched_output_is_failure_but_unexpected_exception_is_error(self):
        case = self.cases[0]
        self.assertEqual(evaluate(case, {'kind': 'bytes', 'value': '00' * 32}), 'failed')
        self.assertEqual(evaluate(case, {'kind': 'exception', 'value': 'RuntimeError'}), 'error')
        self.assertEqual(evaluate(case, {'kind': 'unexpected', 'value': 'wrong type'}), 'error')

    def test_designated_mutants_use_same_oracles(self):
        case = self.cases[0]
        adapter = mock.Mock()
        adapter.decapsulate.return_value = bytes.fromhex(case['expected']['value'])
        self.assertEqual(evaluate(case, observe(adapter, case)), 'passed')
        self.assertEqual(evaluate(case, observe(adapter, case, 'zero-secret')), 'failed')
        case = next(c for c in self.cases if c['operation'] == 'verify_context' and c['expected']['value'] is False)
        adapter.verify_context.return_value = False
        self.assertEqual(evaluate(case, observe(adapter, case)), 'passed')
        self.assertEqual(evaluate(case, observe(adapter, case, 'accept-all-signatures')), 'failed')

    def test_partial_or_fabricated_worker_results_are_setup_errors(self):
        for change in ('missing', 'duplicate', 'hash', 'version', 'extra', 'malformed', 'oracle', 'trailing_record'):
            response = copy.deepcopy(self.response)
            if change == 'missing': response['observations'].pop()
            if change == 'duplicate': response['observations'][1] = response['observations'][0]
            if change == 'hash': response['vectors_sha256'] = '0' * 64
            if change == 'version': response['runtime']['versions']['pqcrypto'] = '9.9'
            if change == 'extra': response['certified'] = True
            if change == 'malformed': response['observations'][0]['observation'] = {'kind': 'boolean', 'value': 'True'}
            if change == 'oracle': response['observations'][0]['expected'] = 'fake'
            if change == 'trailing_record': response['observations'].append(None)
            with self.subTest(change=change), self.assertRaises(ValueError):
                v.validate_worker(response, self.cases, 'provider', v.sha(self.raw))

    def test_image_inspection_rejects_automatic_volumes_and_unsupported_platforms(self):
        info = {'Id': self.image['id'], 'Os': 'linux', 'Architecture': 'arm64', 'Config': {}}
        with mock.patch.object(v, 'bounded_process', return_value=(0, json.dumps([info]).encode(), b'')):
            self.assertEqual(v.inspect_image('test-image'), self.image)
        for key, value in [('Config', {'Volumes': {'/data': {}}}), ('Architecture', 's390x'), ('Id', 'floating-tag'), ('Os', 'windows')]:
            changed = dict(info, **{key: value})
            with mock.patch.object(v, 'bounded_process', return_value=(0, json.dumps([changed]).encode(), b'')), self.assertRaises(v.SetupError):
                v.inspect_image('test-image')

    def test_process_bounds_deadline_and_output(self):
        code, out, err = v.bounded_process([sys.executable, '-I', '-c', 'print("ok")'], 5)
        self.assertEqual((code, out.strip(), err), (0, b'ok', b''))
        with self.assertRaisesRegex(v.SetupError, 'timed out'):
            v.bounded_process([sys.executable, '-I', '-c', 'import time; time.sleep(5)'], 0.1)
        with self.assertRaisesRegex(v.SetupError, 'output limit'):
            v.bounded_process([sys.executable, '-I', '-c', 'print("x"*200000)'], 5, max_output=1000)

    def test_timeout_cleanup_and_checkpoint_preserve_setup_error(self):
        checkpoints = []
        commands = []
        def process(command, timeout, **kwargs):
            commands.append(command)
            if command[1] == 'run': raise v.SetupError('timed out')
            return 0, b'', b''
        with mock.patch.object(v, 'inspect_image', return_value=self.image), mock.patch.object(v, 'bounded_process', side_effect=process):
            result = v.run_validation('test-image', checkpoint=lambda r, replace: checkpoints.append((copy.deepcopy(r), replace)))
        self.assertEqual(result['status'], 'setup_error')
        self.assertEqual(result['case_results'], [])
        self.assertEqual([c[0]['status'] for c in checkpoints], ['pending', 'setup_error'])
        self.assertEqual([c[1] for c in checkpoints], [False, True])
        self.assertEqual(commands[-1][:3], ['docker', 'rm', '--force'])
        v.validate_report(result)

    def test_cleanup_failure_cannot_silently_claim_success(self):
        def process(command, timeout, **kwargs):
            if command[1] == 'rm': return 1, b'', b'daemon unavailable'
            return self.fake_process(command, timeout)
        with mock.patch.object(v, 'inspect_image', return_value=self.image), mock.patch.object(v, 'bounded_process', side_effect=process):
            result = v.run_validation('test-image')
        self.assertEqual(result['status'], 'setup_error')
        self.assertIn('cleanup', result['error'])

    def test_missing_docker_missing_image_and_worker_startup_error_are_not_defects(self):
        for failure in (FileNotFoundError('docker missing'), v.SetupError('image missing')):
            with mock.patch.object(v, 'inspect_image', side_effect=failure):
                result = v.run_validation('test-image')
            self.assertEqual(result['status'], 'setup_error')
            self.assertEqual(result['summary']['failed'], 0)
        self.response = {'status': 'setup_error', 'error': 'ImportError: provider missing'}
        self.assertEqual(self.completed()['status'], 'setup_error')

    def test_import_never_executes_and_marks_results_unauthenticated(self):
        path = self.root / 'saved.json'
        path.write_text(json.dumps(self.completed()))
        with mock.patch.object(v, 'bounded_process', side_effect=AssertionError('must not execute')):
            imported = v.load_validation_report(path)
        self.assertEqual(imported['origin'], 'imported_unverified')
        self.assertEqual(imported['status'], 'passed')

    def test_import_rejects_promoted_claims_or_changed_oracles(self):
        good = self.completed()
        for change in ('status', 'count', 'case', 'expected', 'artifact', 'scope', 'claim', 'network'):
            r = copy.deepcopy(good)
            if change == 'status': r['status'] = 'failed'
            if change == 'count': r['summary']['passed'] = 99
            if change == 'case': r['case_results'].pop()
            if change == 'expected': r['case_results'][0]['expected']['value'] = '00' * 32
            if change == 'artifact': r['artifacts']['adapter'] = '0' * 64
            if change == 'scope': r['coverage']['repository_binding'] = 'verified'
            if change == 'claim': r['compliance_certified'] = True
            if change == 'network': r['command'][r['command'].index('--network=none')] = '--network=host'
            with self.subTest(change=change), self.assertRaises(ValueError): v.validate_report(r)

    def test_cli_refuses_existing_outputs_and_returns_failure_codes(self):
        path = self.root / 'report.json'; path.write_text('keep me')
        with mock.patch('sys.stdout', new_callable=io.StringIO), mock.patch.object(v, 'run_validation') as run:
            self.assertEqual(v.main(['run', '--image', 'test-image', '-o', str(path)]), 2)
        run.assert_not_called()
        self.assertEqual(path.read_text(), 'keep me')
        self.response['observations'][0]['observation']['value'] = '00' * 32
        with mock.patch('sys.stdout', new_callable=io.StringIO), mock.patch.object(v, 'inspect_image', return_value=self.image), mock.patch.object(v, 'bounded_process', side_effect=self.fake_process):
            self.assertEqual(v.main(['run', '--image', 'test-image', '-o', str(self.root / 'failed.json')]), 1)
        r = v.load_validation_report(self.root / 'failed.json')
        self.assertEqual(r['summary']['failed'], 1)

    def test_independent_schema_validation(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest('Optional JSON Schema validator unavailable')
        schema = json.loads((v.ROOT / 'standards/validation-report.schema.json').read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(self.completed(), schema)


@unittest.skipUnless(os.environ.get('PQSCAN_VALIDATION_IMAGE'), 'Explicit Docker integration opt-in required')
class ContainerValidationTests(unittest.TestCase):
    def test_real_provider_and_both_faulty_fixtures(self):
        image = os.environ['PQSCAN_VALIDATION_IMAGE']
        for fixture, expected_failures in [('provider', 0), ('zero-secret', 10), ('accept-all-signatures', 16)]:
            with self.subTest(fixture=fixture):
                report = v.run_validation(image, fixture)
                v.validate_report(report)
                self.assertEqual(report['status'], 'passed' if fixture == 'provider' else 'failed', report.get('error'))
                self.assertEqual(report['summary']['failed'], expected_failures)
                self.assertEqual(report['summary']['error'], 0)


if __name__ == '__main__':
    unittest.main()
