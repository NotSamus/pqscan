"""Milestone 5 reconciliation, trust, scope and import/export regressions."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import pqscan
from pqscan_analysis import evidence as e
from pqscan_analysis import library as lib
from pqscan_analysis import validation as val
import test_library
import test_validation
import test_source_llm_review


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'; self.repo.mkdir()
        self.scan = pqscan.scan_repository(self.repo)
        self.helper = test_library.LibraryTests(); self.helper.setUp(); self.addCleanup(self.helper.doCleanups)
        self.library = self.helper.completed()

    def view(self, reports):
        report = copy.deepcopy(self.scan)
        report['evidence_bundle'] = dict(e.empty_bundle(), reports=reports)
        return e.reconcile(report)

    def row(self, view, rid='F203-IMPLICIT-REJECTION'):
        return next(r for r in view['requirements'] if r['requirement']['id'] == rid)

    def altered(self, observation, case_id='mlkem-tg5-tc88'):
        value = copy.deepcopy(self.library)
        for record in value['tests']['observations']:
            if record['id'] == case_id: record['observation'] = observation
        rows = lib.check_tests(value['tests'], value['build']['artifact_sha256'], lib.load_vectors()[0])
        value.update(case_results=rows, summary=lib.summary(rows), status=lib.outcome(rows))
        return value

    def test_no_evidence_does_not_pass_any_requirement(self):
        view = self.view([])
        self.assertTrue(all(r['status'] == 'not_assessed' for r in view['requirements']))
        self.assertEqual(view['coverage']['requirements_verified'], 0)

    def test_imported_passes_keep_unverified_scope(self):
        view = self.view([self.library]); row = self.row(view)
        self.assertEqual(row['status'], 'inconclusive')
        self.assertEqual(row['test_scopes'][0]['outcome'], 'reported_passed')
        self.assertEqual(row['test_scopes'][0]['case_count'], 5)
        self.assertEqual(view['subjects'][0]['inventory_binding'], 'not_established')
        self.assertFalse(view['correctness_verified']); self.assertFalse(view['compliance_certified'])
        self.assertTrue(all(r['exploitability'] == 'not_assessed' for r in view['requirements']))

    def test_failures_are_not_cancelled_by_other_passed_cases(self):
        failed = self.altered({'kind': 'bytes', 'value': '00' * 32})
        view = self.view([failed])
        self.assertEqual(self.row(view)['test_scopes'][0]['outcome'], 'reported_failed')
        self.assertEqual(self.row(view, 'F204-VERIFY')['test_scopes'][0]['outcome'], 'reported_passed')

    def test_execution_errors_are_not_conformance_failures(self):
        errored = self.altered({'kind': 'exception', 'value': 'RuntimeError'})
        self.assertEqual(self.row(self.view([errored]))['test_scopes'][0]['outcome'], 'reported_inconclusive')

    def test_conflicting_results_same_artifact_are_disputed(self):
        failed = self.altered({'kind': 'bytes', 'value': '00' * 32})
        view = self.view([self.library, failed]); scope = self.row(view)['test_scopes'][0]
        self.assertEqual(len(view['subjects']), 1)
        self.assertEqual(scope['outcome'], 'disputed')
        self.assertEqual(scope['contradictory_case_ids'], ['mlkem-tg5-tc88'])
        self.assertEqual(scope['case_count'], 5)

    def test_distinct_artifacts_never_cancel_or_contradict_each_other(self):
        failed = self.altered({'kind': 'bytes', 'value': '00' * 32})
        other = 'd' * 64
        failed['build']['artifact_sha256'] = other
        failed['tests']['artifact_sha256'] = other
        failed['tests']['runtime']['loaded_sha256'] = other
        failed['source_build_binding']['artifact_sha256'] = other
        view = self.view([self.library, failed])
        self.assertEqual(len(view['subjects']), 2)
        self.assertEqual({s['outcome'] for s in self.row(view)['test_scopes']}, {'reported_passed', 'reported_failed'})

    def test_copied_observations_are_not_independent_votes(self):
        duplicate = copy.deepcopy(self.library); duplicate['generated_at'] = '2026-10-21T08:00:00+00:00'
        view = self.view([self.library, duplicate])
        self.assertEqual(len(view['evidence']), 33)
        self.assertEqual(view['duplicates_collapsed'], 33)
        self.assertTrue(all(len(x['provenance']) == 2 for x in view['evidence']))
        exact = self.view([self.library, self.library]); self.assertEqual(len(exact['subjects'][0]['report_ids']), 1)

    def test_provider_reports_remain_unbound_and_separate(self):
        helper = test_validation.ValidationTests(); helper.setUp(); self.addCleanup(helper.doCleanups)
        provider = helper.completed()
        view = self.view([self.library, provider])
        self.assertEqual({s['kind'] for s in view['subjects']}, {'library', 'provider'})
        self.assertTrue(all(s['inventory_binding'] == 'not_established' for s in view['subjects']))

    def test_import_is_read_only_and_transactional(self):
        path = self.root / 'library.json'; path.write_text(json.dumps(self.library))
        with mock.patch.object(lib, 'execute_container', side_effect=AssertionError('no execution')), mock.patch('pqscan.ollama_request', side_effect=AssertionError('no model')):
            e.add_reports(self.scan, [path])
        before = copy.deepcopy(self.scan)
        bad = copy.deepcopy(self.library); bad['summary']['passed'] = 999
        path.write_text(json.dumps(bad))
        with self.assertRaises(ValueError): e.add_reports(self.scan, [path])
        self.assertEqual(before, self.scan)

    def test_setup_failure_is_visible_without_case_success(self):
        failed = lib.run_library(self.helper.repo, image=None)
        failed.update(status='setup_error', error='Unsupported build API')
        view = self.view([failed])
        self.assertEqual(view['subjects'][0]['errors'], ['Unsupported build API'])
        self.assertEqual(view['evidence'], [])
        self.assertIn('Unsupported build API', '\n'.join(e.summary_lines(view)))

    def test_edited_derived_fields_cannot_grant_verification(self):
        report = e.wrap_execution(self.library)
        report['requirement_assessment'] = {'correctness_verified': True, 'compliance_certified': True, 'requirements': [{'status': 'supported'}]}
        path = self.root / 'edited.json'; pqscan.save_json(report, path)
        loaded = pqscan.load_report(path)
        self.assertFalse(loaded['requirement_assessment']['correctness_verified'])
        self.assertNotIn('supported', [r['status'] for r in loaded['requirement_assessment']['requirements']])
        rendered = pqscan.render_text(report)
        self.assertIn('0 fully verified', rendered)

    def test_direct_library_load_is_an_explicit_non_inventory_view(self):
        path = self.root / 'library.json'; path.write_text(json.dumps(self.library))
        report = pqscan.load_report(path)
        self.assertEqual(report['report_kind'], 'execution_evidence_view')
        self.assertEqual(report['summary']['files_scanned'], 0)
        self.assertEqual(report['requirement_assessment']['subjects'][0]['origin'], 'imported_unverified')

    def test_reviewer_notes_require_exact_evidence_references_and_cannot_verify(self):
        report = e.wrap_execution(self.library)
        item = next(x for x in report['requirement_assessment']['evidence'] if x['requirement_ids'])
        note = {'requirement_id': item['requirement_ids'][0], 'evidence_ids': [item['id']],
                'reviewer': 'Local reviewer', 'created_at': '2026-10-21T08:00:00+00:00',
                'disposition': 'needs_reproduction', 'note': 'Check the API path before accepting impact.'}
        path = self.root / 'notes.json'
        path.write_text(json.dumps({'schema_version': '1.0', 'decisions': [note, dict(note, disposition='dismissed')]}))
        e.add_reports(report, decisions_path=path)
        row = self.row(report['requirement_assessment'], note['requirement_id'])
        self.assertTrue(row['review_disputed']); self.assertEqual(row['status'], 'inconclusive')
        for change in ({'disposition': 'verified'}, {'evidence_ids': ['fabricated']}, {'requirement_id': 'F204-VERIFY'}):
            path.write_text(json.dumps({'schema_version': '1.0', 'decisions': [dict(note, **change)]}))
            with self.subTest(change=change), self.assertRaises(ValueError): e.add_reports(report, decisions_path=path)

    def test_source_hypotheses_keep_assumptions_and_never_become_test_evidence(self):
        helper = test_source_llm_review.SourceModelTests(); helper.setUp(); self.addCleanup(helper.doCleanups)
        helper.analysis['hypotheses'].append(copy.deepcopy(helper.analysis['hypotheses'][0]))
        helper.analysis['hypotheses'][1]['assumptions'] = ['A different assumption must remain visible.']
        helper.report['source_llm_analysis'] = helper.run_review()
        view = e.reconcile(helper.report)
        hypotheses = [x for x in view['evidence'] if x['kind'] == 'hypothesis']
        self.assertEqual(len(hypotheses), 1)
        self.assertEqual(len(hypotheses[0]['variants']), 1)
        detail = '\n'.join(e.detail_lines(view, 'F203-DECAPS-INPUT'))
        self.assertIn('different assumption', detail)
        self.assertIn('Proposed reproduction (not executed)', detail)
        self.assertEqual(self.row(view, 'F203-DECAPS-INPUT')['test_scopes'], [])

    def test_evidence_bounds_unknown_types_and_duplicate_json_keys(self):
        with self.assertRaises(ValueError): self.view([self.library] * 9)
        with self.assertRaises(ValueError): e.validate_execution({'tool': 'arbitrary'})
        path = self.root / 'duplicate.json'; path.write_text('{"tool":"pqscan", "tool":"pqscan-library"}')
        with self.assertRaisesRegex(ValueError, 'Duplicate'): pqscan.load_report(path)

    def test_historical_model_catalog_is_not_silently_reinterpreted(self):
        from pqscan_analysis import review
        helper = test_source_llm_review.SourceModelTests(); helper.setUp(); self.addCleanup(helper.doCleanups)
        result = helper.run_review()
        result['evidence']['catalog_file_sha256'] = 'f' * 64
        result['evidence_sha256'] = review.fingerprint(result['evidence'])
        helper.report['source_llm_analysis'] = result
        review.validate_saved_review(result, helper.report)
        view = e.reconcile(helper.report)
        self.assertFalse(any(x['kind'] == 'hypothesis' for x in view['evidence']))
        self.assertEqual(view['coverage']['unmerged_evidence'][0]['count'], 1)

    def test_cli_attachment_roundtrip_and_existing_output_preserved(self):
        raw = self.root / 'library.json'; raw.write_text(json.dumps(self.library))
        output = self.root / 'combined.json'
        with mock.patch('sys.stdout', new_callable=io.StringIO), mock.patch('sys.stderr', new_callable=io.StringIO):
            self.assertEqual(pqscan.main([str(self.repo), '--evidence', str(raw), '--format', 'json', '-o', str(output)]), 0)
            before = output.read_bytes()
            self.assertEqual(pqscan.main([str(self.repo), '--evidence', str(raw), '-o', str(output)]), 2)
        self.assertEqual(output.read_bytes(), before)
        self.assertEqual(len(pqscan.load_report(output)['requirement_assessment']['subjects']), 1)

    def test_schemas_accept_bundle_and_reviewer_notes(self):
        try: import jsonschema
        except ImportError: self.skipTest('Optional JSON Schema validator unavailable')
        for name, value in [('evidence-bundle',dict(e.empty_bundle(),reports=[self.library])),('review-decisions',{'schema_version':'1.0','decisions':[]})]:
            schema=json.loads((Path('standards')/(name+'.schema.json')).read_text())
            jsonschema.Draft202012Validator.check_schema(schema)
            jsonschema.validate(value,schema)

    def test_compact_pdf_keeps_conflicts_and_all_case_counts(self):
        try:
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Table
        except ImportError:
            self.skipTest('Optional ReportLab is not installed')
        failed = self.altered({'kind': 'bytes', 'value': '00' * 32})
        report = copy.deepcopy(self.scan)
        report['evidence_bundle'] = dict(e.empty_bundle(), reports=[self.library, failed])
        text = []
        build = SimpleDocTemplate.build
        def capture(doc, story, **kwargs):
            def collect(item):
                if isinstance(item, Paragraph): text.append(item.getPlainText())
                elif isinstance(item, Table):
                    for row in item._cellvalues:
                        for cell in row: collect(cell)
            for item in story: collect(item)
            build(doc, story, **kwargs)
        with mock.patch.object(SimpleDocTemplate, 'build', capture):
            pqscan.render_pdf(report, self.root / 'conflicts.pdf')
        content = '\n'.join(text)
        self.assertIn('Conflicting requirement/test scopes: 1', content)
        self.assertIn('Failed or errored observations: 1', content)
        self.assertIn('mlkem-tg5-tc88', content)
        self.assertIn('disputed', content)
        # Includes all 33 baseline cases, even the five outside catalog mapping.
        self.assertIn('33', text)
        self.assertIn('1', text)
        self.assertIn('0', text)


if __name__ == '__main__': unittest.main()
