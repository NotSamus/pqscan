"""Python source capture, conservative graph resolution and report boundaries."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import pqscan
from pqscan_analysis import source_index as index


class SourceIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()

    def write(self, path, source):
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(source.encode() if isinstance(source, str) else source)
        return file

    def scan(self, **kwargs):
        return pqscan.scan_repository(self.repo, review_source=True, **kwargs)

    def calls(self, report, expression):
        return [c for c in report['source_review']['calls'] if c['expression'] == expression]

    def test_default_scan_and_model_payload_contain_no_source(self):
        self.write('app.py', "from pqcrypto.kem import ml_kem_768\nsecret = 'PRIVATE_LITERAL'\nml_kem_768.decrypt(key, ciphertext)\n")
        plain = pqscan.scan_repository(self.repo)
        self.assertNotIn('source_review', plain)
        self.assertNotIn('PRIVATE_LITERAL', json.dumps(plain))
        rich = self.scan()
        self.assertIn('PRIVATE_LITERAL', json.dumps(rich))
        self.assertEqual(pqscan.build_review_evidence(plain), pqscan.build_review_evidence(rich))
        self.assertNotIn('PRIVATE_LITERAL', json.dumps(pqscan.build_review_evidence(rich)))
        self.assertEqual(plain['assessment'], rich['assessment'])
        self.assertEqual(plain['specification_review'], rich['specification_review'])

    def test_aliases_wrappers_reexports_and_relative_imports(self):
        self.write('pkg/__init__.py', 'from .wrapper import unwrap as open_message\n')
        self.write('pkg/wrapper.py', 'from .primitive import dec as inner\ndef unwrap(sk, ct):\n    return inner(sk, ct)\n')
        self.write('pkg/primitive.py', 'from pqcrypto.kem.ml_kem_768 import decrypt as decrypt_impl\ndef dec(sk, ct):\n    operation = decrypt_impl\n    return operation(sk, ct)\n')
        self.write('main.py', 'from pkg import open_message as unlock\ndef receive(sk, ct):\n    return unlock(sk, ct)\n')
        report = self.scan()
        for expression in ('unlock', 'inner'):
            call = self.calls(report, expression)[0]
            self.assertEqual(call['resolution'], 'local_candidate')
            self.assertIsNotNone(call['target_id'])
        provider = self.calls(report, 'operation')[0]
        self.assertEqual(provider['resolved_name'], 'pqcrypto.kem.ml_kem_768.decrypt')
        self.assertEqual(provider['provider']['contract_status'], 'not_verified')
        excerpts = report['source_review']['source_slices']
        self.assertTrue(any(e['path'] == 'main.py' and 'caller_or_callee' in e['selection_reasons'] for e in excerpts))
        self.assertTrue(any('return operation(sk, ct)' in e['text'] for e in excerpts))

    def test_src_layout_and_duplicate_module_ambiguity(self):
        self.write('src/core.py', 'def wrap():\n    return 1\n')
        self.write('main.py', 'import core as helper\nhelper.wrap()\n')
        self.assertEqual(self.calls(self.scan(), 'helper.wrap')[0]['resolution'], 'local_candidate')
        self.write('core.py', 'def wrap():\n    return 2\n')
        call = self.calls(self.scan(), 'helper.wrap')[0]
        self.assertEqual(call['resolution'], 'unresolved')
        self.assertIn('ambiguous', call['reason'])

    def test_scope_shadowing_and_rebinding_are_not_provider_calls(self):
        self.write('app.py', 'from pqcrypto.kem.ml_kem_768 import decrypt as action\n'
                   'def first(action):\n    return action()\n'
                   'def second():\n    action = factory()\n    return action()\n'
                   'def third():\n    action = action\n    return action()\n'
                   'def fourth():\n    from other import action\n    action = factory()\n    return action()\n')
        calls = self.calls(self.scan(), 'action')
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(c['resolution'] == 'unresolved' and c['provider'] is None for c in calls))

    def test_function_imports_do_not_leak_between_scopes(self):
        self.write('app.py', 'def first():\n    from pqcrypto.kem.ml_kem_768 import decrypt as x\n    x()\n'
                   'def second():\n    x()\n')
        first, second = self.calls(self.scan(), 'x')
        self.assertEqual(first['resolution'], 'external_boundary')
        self.assertEqual(second['resolution'], 'unresolved')

    def test_dynamic_dispatch_star_imports_and_decorators_are_explicit(self):
        self.write('app.py', 'from pqcrypto.kem import ml_kem_768 as kem\n'
                   'def wrap(obj):\n    obj.decrypt()\n    getattr(kem, "decrypt")()\n'
                   '@decorate\ndef handler():\n    return kem.decrypt(sk, ct)\n')
        report = self.scan()
        self.assertEqual(self.calls(report, 'obj.decrypt')[0]['resolution'], 'unresolved')
        self.assertTrue(self.calls(report, '<dynamic>'))
        self.assertTrue(any(g['reason'] == 'decorator' for g in report['source_review']['coverage']['gaps']))
        self.write('star.py', 'from pqcrypto.kem.ml_kem_768 import *\ndecrypt(sk, ct)\n')
        report = self.scan()
        self.assertEqual(self.calls(report, 'decrypt')[0]['resolution'], 'unresolved')
        self.assertTrue(any(g['reason'] == 'wildcard_import' for g in report['source_review']['coverage']['gaps']))

    def test_conditional_and_attribute_mutations_are_unknown(self):
        self.write('app.py', 'if enabled:\n    from pqcrypto.kem.ml_kem_768 import decrypt\ndecrypt(sk, ct)\n'
                   'from pqcrypto.kem import ml_kem_768 as kem\nkem.decrypt = replacement\nkem.decrypt(sk, ct)\n')
        report = self.scan()
        for expression in ('decrypt', 'kem.decrypt'):
            self.assertEqual(self.calls(report, expression)[0]['resolution'], 'unresolved')

    def test_nested_functions_async_and_class_boundaries(self):
        self.write('app.py', 'def outer():\n    def inner():\n        return 1\n    return inner()\n'
                   'async def entry():\n    return outer()\n'
                   'class Client:\n    def read(self):\n        return self.decrypt()\n'
                   'Client.read()\n')
        report = self.scan()
        self.assertEqual(self.calls(report, 'inner')[0]['resolution'], 'local_candidate')
        self.assertEqual(self.calls(report, 'self.decrypt')[0]['resolution'], 'unresolved')
        self.assertEqual(self.calls(report, 'Client.read')[0]['resolution'], 'unresolved')
        self.assertTrue(any(s['kind'] == 'async_function' for s in report['source_review']['symbols']))

    def test_independent_index_and_entrypoints_without_inventory_hits(self):
        self.write('app.py', 'def helper(v):\n    return v\ndef receive(v):\n    return helper(v)\n')
        report = self.scan()
        self.assertEqual(report['findings'], [])
        self.assertEqual(self.calls(report, 'helper')[0]['resolution'], 'local_candidate')
        self.assertTrue(report['source_review']['potential_entrypoints'])
        self.assertTrue(any('def receive' in s['text'] for s in report['source_review']['source_slices']))

    def test_native_or_external_boundary_not_a_fake_local_implementation(self):
        self.write('app.py', 'import oqs\ninstance = oqs.KeyEncapsulation("ML-KEM-768")\ninstance.decap_secret(ct)\n')
        report = self.scan()
        constructor = self.calls(report, 'oqs.KeyEncapsulation')[0]
        self.assertEqual(constructor['provider']['implementation'], 'external_or_native_uninspected')
        self.assertEqual(self.calls(report, 'instance.decap_secret')[0]['resolution'], 'unresolved')
        # If source with the same module name is present, it takes precedence.
        self.write('oqs.py', 'def KeyEncapsulation(name):\n    return name\n')
        call = self.calls(self.scan(), 'oqs.KeyEncapsulation')[0]
        self.assertEqual(call['resolution'], 'local_candidate')
        self.assertIsNone(call['provider'])

    def test_file_and_slice_hashes_locations_unicode_and_crlf(self):
        raw = 'note = "é\u2028x"; invoke()\r\ndef helper():\r\n    return 3\r\n'.encode()
        self.write('app.py', raw)
        report = self.scan()
        review = report['source_review']
        self.assertEqual(review['snapshot']['files'][0]['sha256'], hashlib.sha256(raw).hexdigest())
        call = self.calls(report, 'invoke')[0]
        self.assertEqual(call['line'], 1)
        self.assertEqual(call['column'], len('note = "é\u2028x"; ') + 1)
        lines = index.source_lines(raw.decode())
        for s in review['source_slices']:
            self.assertEqual(s['text'], ''.join(lines[s['start_line']-1:s['end_line']]))
            self.assertEqual(s['sha256'], hashlib.sha256(s['text'].encode()).hexdigest())

    def test_snapshot_uses_same_read_as_inventory_and_detects_changes(self):
        path = self.write('app.py', 'def helper():\n    return 1\n')
        real = pqscan.read_regular_file
        def mutate_after_read(p, limit):
            data, reason = real(p, limit)
            if p.resolve() == path.resolve():
                p.write_text('def helper():\n    return 2\n')
            return data, reason
        with mock.patch.object(pqscan, 'read_regular_file', side_effect=mutate_after_read):
            first = self.scan()['source_review']
        second = self.scan()['source_review']
        self.assertNotEqual(first['snapshot']['id'], second['snapshot']['id'])
        self.assertTrue(any('return 1' in s['text'] for s in first['source_slices']))
        self.assertTrue(any('return 2' in s['text'] for s in second['source_slices']))

    def test_exclusions_symlinks_and_other_languages_are_disclosed(self):
        self.write('.pqscanignore', 'private.py\n')
        self.write('private.py', "secret='do not collect'\n")
        self.write('app.js', 'const x = "ML-KEM-768";')
        (self.repo / 'linked.py').symlink_to(self.repo / 'private.py')
        self.write('bad.py', 'def (:')
        review = self.scan()['source_review']
        paths = {f['path'] for f in review['snapshot']['files']}
        self.assertNotIn('private.py', paths)
        self.assertNotIn('linked.py', paths)
        self.assertTrue(any(g['reason'] == 'inventory_only' for g in review['coverage']['gaps']))
        self.assertTrue(any(g['reason'] == 'parse_error' for g in review['coverage']['gaps']))
        self.assertTrue(any(s['reason'] == 'symlink' for s in review['coverage']['scanner_skipped']))
        self.assertNotIn('do not collect', json.dumps(review))

    def test_budgets_disclose_omissions_without_partial_lines(self):
        self.write('app.py', 'def helper():\n' + '    value = 1\n' * 20)
        review = self.scan(source_max_chars=30)['source_review']
        self.assertLessEqual(review['coverage']['source_chars'], 30)
        self.assertTrue(review['coverage']['slices_omitted_or_truncated'])
        collector = index.Collector(max_files=1, max_ast_nodes=1)
        for path in ['a.py', 'b.py']:
            collector.observe(path, b'f()\n', 'f()\n', 'production')
        report = pqscan.scan_repository(self.repo)
        bounded = collector.build(report)
        reasons = {g['reason'] for g in bounded['coverage']['gaps']}
        self.assertEqual(reasons, {'snapshot_budget', 'ast_budget'})
        index.validate_source_review(bounded, report['findings'])
        with self.assertRaises(ValueError):
            self.scan(source_max_chars=24001)

    def test_requirements_constraints_are_not_installed_versions(self):
        self.write('requirements.txt', 'pqcrypto==0.3.4\nliboqs-python>=0.12\n# oqs==fake\n')
        deps = self.scan()['source_review']['dependencies']
        self.assertEqual([(d['distribution'], d['constraint'], d['status']) for d in deps],
                         [('pqcrypto', '==0.3.4', 'declared_only'), ('liboqs-python', '>=0.12', 'declared_only')])

    def test_cyclic_reexports_and_nested_calls_terminate_with_unique_ids(self):
        self.write('a.py', 'from b import wrap\nwrap()\nfactory()()\n')
        self.write('b.py', 'from a import wrap\n')
        review = self.scan()['source_review']
        self.assertTrue(any('cycle' in c['reason'] for c in review['calls']))
        self.assertEqual(len(review['calls']), len({c['id'] for c in review['calls']}))

    def test_saved_source_is_unverified_and_never_reread(self):
        self.write('app.py', 'def helper():\n    return 1\n')
        report = self.scan()
        path = self.root / 'report.json'
        pqscan.save_json(report, path)
        before = path.read_bytes()
        shutil.rmtree(self.repo)
        with mock.patch.object(pqscan, 'read_regular_file', side_effect=AssertionError('must not reread')):
            loaded = pqscan.load_report(path)
        self.assertEqual(loaded['source_review']['origin'], 'imported_unverified')
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(loaded['source_review']['snapshot'], report['source_review']['snapshot'])
        self.assertFalse(loaded['specification_review']['correctness_verified'])
        bundle = index.build_source_evidence(loaded)
        bundle['source_slices'][0]['text'] = 'changed'
        self.assertNotEqual(bundle['source_slices'], loaded['source_review']['source_slices'])

    def test_corrupted_saved_hashes_references_claims_and_paths_are_rejected(self):
        self.write('app.py', 'def helper():\n    return 1\nhelper()\n')
        original = self.scan()
        changes = [
            lambda s: s.update(compliance_certified=True),
            lambda s: s['snapshot'].update(id='0'*64),
            lambda s: s['source_slices'][0].update(text='tampered\n'),
            lambda s: s['calls'][0].update(target_id='missing'),
            lambda s: s['source_slices'][0].update(finding_ids=['F9999']),
            lambda s: s['snapshot']['files'][0].update(path='../escape.py'),
            lambda s: s['source_slices'][0].update(end_line=999),
            lambda s: s['coverage'].update(source_chars=0),
        ]
        for i, mutate in enumerate(changes):
            report = copy.deepcopy(original)
            mutate(report['source_review'])
            path = self.root / f'bad-{i}.json'
            pqscan.save_json(report, path)
            with self.subTest(case=i), self.assertRaises(ValueError):
                pqscan.load_report(path)

    def test_cli_rejects_source_collection_from_saved_report_and_missing_package(self):
        with mock.patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit):
            pqscan.main(['--from-json', str(self.root/'old.json'), '--review-source'])
        script = self.root/'pqscan.py'
        shutil.copy2(pqscan.__file__, script)
        run = subprocess.run([sys.executable, '-I', str(script), str(self.repo), '--review-source'],
                             text=True, capture_output=True, timeout=20)
        self.assertEqual(run.returncode, 2)
        self.assertIn('requires pqscan_analysis/', run.stderr)

    def test_target_code_is_never_imported_or_executed(self):
        marker = self.root/'executed'
        self.write('app.py', f'from pathlib import Path\nPath({str(marker)!r}).touch()\nraise RuntimeError()\n')
        self.scan()
        self.assertFalse(marker.exists())

    def test_deterministic_index_and_stable_snapshot(self):
        self.write('b.py', 'from a import helper\nhelper()\n')
        self.write('a.py', 'def helper():\n    return 1\n')
        self.assertEqual(self.scan()['source_review'], self.scan()['source_review'])

    @unittest.skipUnless(importlib.util.find_spec('jsonschema'), 'optional independent validator not installed')
    def test_source_report_matches_published_json_schema(self):
        import jsonschema
        from pqscan_analysis.requirements import STANDARDS_DIR
        self.write('app.py', 'import oqs\noqs.KeyEncapsulation("ML-KEM-768")\n')
        schema = json.loads((STANDARDS_DIR/'source-review.schema.json').read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(self.scan()['source_review'])


if __name__ == '__main__':
    unittest.main()
