"""Reconcile scoped evidence without treating imported JSON as execution proof.

This module never executes targets, stored commands, Docker or model requests.
The derived view is rebuilt from validated inputs at every display/load boundary.
"""
from collections import Counter
from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path

from .requirements import load_catalog, build_specification_review, _validate_contract

PROFILE = 'pqscan-requirement-evidence-v1'
BOUNDARY = ('Selected test outcomes are reported evidence, not authenticated execution. '
            'Requirement status remains inconclusive where evidence exists and not_assessed otherwise. '
            'No whole-requirement conformance, application binding, exploitability or certification is established. '
            'Reviewer notes and model hypotheses cannot grant verification.')
MAX_REPORTS = 8
MAX_BYTES = 64 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def read_json(path, limit=MAX_BYTES):
    from .validation import read_bounded, parse_json
    return parse_json(read_bounded(Path(path), limit))


def validate_execution(value):
    if not isinstance(value, dict): raise ValueError('Execution evidence must be a JSON object')
    value = deepcopy(value)
    if value.get('tool') == 'pqscan-library':
        from .library import validate_report
    elif value.get('tool') == 'pqscan-validation':
        from .validation import validate_report
    else:
        raise ValueError('Evidence must be a library or provider validation report')
    try:
        validate_report(value)
    except (KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise ValueError('Malformed execution evidence') from exc
    value['origin'] = 'imported_unverified'
    return value


def empty_bundle():
    return {'schema_version': '1.0', 'reports': [], 'decisions': []}


def normalize_bundle(bundle):
    _validate_contract(bundle, 'evidence-bundle.schema.json')
    if len(canonical(bundle)) > MAX_BYTES:
        raise ValueError('Evidence bundle exceeds 64 MiB')
    reports, seen = [], set()
    for value in bundle['reports']:
        normalized = validate_execution(value)
        key = fingerprint(normalized)
        if key not in seen:
            reports.append(normalized); seen.add(key)
    return {'schema_version': '1.0', 'reports': reports, 'decisions': deepcopy(bundle['decisions'])}


def add_reports(report, paths=(), decisions_path=None):
    """Transactional import: invalid attachments never partially update a report."""
    bundle = deepcopy(report.get('evidence_bundle', empty_bundle()))
    if len(bundle['reports']) + len(paths) > MAX_REPORTS:
        raise ValueError('At most eight execution reports can be attached')
    for path in paths:
        bundle['reports'].append(read_json(path, 16 * 1024 * 1024))
    if decisions_path is not None:
        notes = read_json(decisions_path, 128 * 1024)
        _validate_contract(notes, 'review-decisions.schema.json')
        bundle['decisions'].extend(notes['decisions'])
    candidate = dict(report, evidence_bundle=normalize_bundle(bundle))
    derived = reconcile(candidate)
    report['evidence_bundle'] = candidate['evidence_bundle']
    report['requirement_assessment'] = derived
    return report


def wrap_execution(value):
    """A display envelope, explicitly not a repository inventory scan."""
    import pqscan
    value = validate_execution(value)
    snapshot = value.get('snapshot', {}).get('id')
    report = {'schema_version': '1.0', 'tool': 'pqscan', 'tool_version': pqscan.VERSION,
              'report_kind': 'execution_evidence_view', 'generated_at': value['generated_at'],
              'repository': 'Library snapshot ' + snapshot if snapshot else 'Provider validation (no repository binding)',
              'assessment': pqscan.assessment([], True),
              'summary': {'files_scanned': 0, 'bytes_scanned': 0, 'findings': 0, 'files_or_directories_skipped': 0,
                          'by_category': {}, 'by_severity': {}, 'by_context': {}},
              'coverage': {'incomplete': True, 'skipped': [], 'warnings': ['Inventory was not run. This view contains imported execution evidence.'], 'errors': []},
              'findings': [], 'limitations': [BOUNDARY],
              'evidence_bundle': dict(empty_bundle(), reports=[value])}
    report['fusion_assessment'] = pqscan.fusion_assessment(report)
    report['correctness_compliance'] = pqscan.correctness_compliance(report)
    report['specification_review'] = pqscan.specification_review(report)
    report['requirement_assessment'] = reconcile(report)
    return report


def subject_for(value):
    library = value['tool'] == 'pqscan-library'
    build = value.get('build') or {}
    runtime = value.get('runtime') or {}
    identity = {'kind': 'library' if library else 'provider', 'profile': value['profile'],
                'snapshot_id': value['snapshot']['id'] if library else None,
                'artifact': build.get('artifact_sha256') if library else runtime,
                'image_id': (value.get('image') or {}).get('id'),
                'recipe': value.get('recipe'), 'catalog': value['catalog'],
                'harness': value.get('harness_sha256', value.get('artifacts')),
                'vectors': value.get('vectors_sha256'), 'fixture': value.get('fixture', 'source'),
                'mutation': value.get('snapshot', {}).get('mutation')}
    sid = 'S' + fingerprint(identity)[:20]
    return {'id': sid, **identity, 'origin': 'imported_unverified',
            'inventory_binding': 'not_established',
            'backend': 'portable-no-asm/default' if library else 'fixed pqcrypto provider',
            'report_ids': [], 'reported_run_states': [], 'coverage': [], 'errors': [],
            'reproduction': [], 'source_locations': [], 'unmapped_case_ids': []}


def reconcile(report):
    catalog, sha = load_catalog()
    requirements = {r['id']: r for r in catalog['requirements']}
    bundle = normalize_bundle(report.get('evidence_bundle', empty_bundle()))
    subjects, evidence, duplicates = {}, {}, 0
    unmerged = []

    def add(item):
        nonlocal duplicates
        key = item['id']
        if key in evidence:
            duplicates += 1
            evidence[key]['provenance'] = sorted(set(evidence[key]['provenance'] + item['provenance']))
            if item['kind'] == 'hypothesis' and item['hypothesis'] != evidence[key]['hypothesis']:
                variants = evidence[key].setdefault('variants', [])
                if item['hypothesis'] not in variants: variants.append(item['hypothesis'])
        else: evidence[key] = item

    # Inventory is candidate location evidence, never a requirement evaluator.
    specification = build_specification_review(report)
    for row in specification['requirements']:
        rid = row['requirement']['id']
        for finding_id in row['evidence']['production_finding_ids'] + row['evidence']['nonproduction_finding_ids']:
            finding = next(f for f in report['findings'] if f['finding_id'] == finding_id)
            site = {k: finding[k] for k in ('path', 'line', 'evidence_kind', 'evidence')}
            eid = 'I' + fingerprint([rid, site])[:20]
            add({'id': eid, 'kind': 'inventory', 'subject_id': 'inventory', 'requirement_ids': [rid],
                 'provenance': [finding_id], 'status': 'candidate_location', 'source': site,
                 'interpretation': 'Family-level inventory pointer; applicability and execution are unknown.'})

    review = report.get('source_llm_analysis')
    if review is not None:
        from .review import validate_saved_review
        validate_saved_review(review, report)
        if review['status'] == 'completed':
            packet = review['evidence']
            matching_catalog = packet['catalog_file_sha256'] == sha and packet['catalog'] == catalog
            if not matching_catalog:
                unmerged.append({'kind': 'source_hypotheses', 'catalog_sha256': packet['catalog_file_sha256'],
                                 'count': len(review['analysis']['hypotheses']),
                                 'reason': 'Historical hypothesis catalog differs; retained in source review, not mapped onto current requirements.'})
            slices = {s['id']: s for s in packet['source_slices']}
            for hypothesis in review['analysis']['hypotheses'] if matching_catalog else []:
                # Exact normalized claim + source spans; no semantic equivalence inference.
                source = [{'path': slices[r['slice_id']]['path'], 'start_line': r['start_line'],
                           'end_line': r['end_line'], 'slice_id': r['slice_id'],
                           'file_sha256': slices[r['slice_id']]['file_sha256']} for r in hypothesis['source_refs']]
                claim = ' '.join(hypothesis['observed_behavior'].casefold().split())
                eid = 'H' + fingerprint([packet['snapshot_id'], sorted(hypothesis['requirement_ids']), source, claim])[:20]
                add({'id': eid, 'kind': 'hypothesis', 'subject_id': 'python:' + packet['snapshot_id'],
                     'requirement_ids': hypothesis['requirement_ids'], 'provenance': ['model:' + review['model']],
                     'status': 'unverified_hypothesis', 'source': source, 'hypothesis': deepcopy(hypothesis)})

    for value in bundle['reports']:
        report_id = 'R' + fingerprint(value)[:20]
        subject = subject_for(value)
        sid = subject['id']
        subject = subjects.setdefault(sid, subject)
        subject['report_ids'].append(report_id)
        subject['reported_run_states'].append(value['status'])
        if value.get('error'): subject['errors'].append(value['error'])
        if value['tool'] == 'pqscan-library':
            build = value.get('build')
            mutation = value['snapshot']['mutation']
            subject['reproduction'] = [['python3', '-m', 'pqscan_analysis.library', 'run',
                                       '<matching original source tree>', '--image',
                                       (value.get('image') or {}).get('id', '<prepared image>'),
                                       '--mutation', mutation['name'] if mutation else 'none',
                                       '--timeout', str(value['timeout_seconds']), '-o', '<new report.json>']]
            if build:
                subject['coverage'].append(build['native_source']['coverage'])
                subject['reproduction'].extend(build['commands'])
                wanted = {i for link in value['requirement_links'] for i in link['source_symbol_ids']}
                subject['source_locations'] = [dict(s, requirement_ids=[link['requirement_id'] for link in value['requirement_links']
                                              if s['id'] in link['source_symbol_ids']])
                                              for s in build['native_source']['symbols'] if s['id'] in wanted]
            else: subject['coverage'].append({'partial': True, 'reason': 'No completed source build/native index'})
        else:
            subject['coverage'].append(value['coverage'])
            subject['reproduction'] = [['python3', '-m', 'pqscan_analysis.validation', 'run', '--image',
                                        (value.get('image') or {}).get('requested', '<prepared image>'),
                                        '--fixture', value['fixture'], '-o', '<new report.json>']]
        for case in value['case_results']:
            if not set(case['requirement_ids']) <= requirements.keys(): raise ValueError('Unknown case requirement')
            if not case['requirement_ids']: subject['unmapped_case_ids'].append(case['id'])
            # Same subject, oracle, case and observation is one observation even if
            # copied into many reports. Different observations are retained.
            eid = 'T' + fingerprint([sid, case])[:20]
            add({'id': eid, 'kind': 'test', 'subject_id': sid, 'requirement_ids': case['requirement_ids'],
                 'provenance': [report_id], 'status': 'reported_' + case['status'], 'case': deepcopy(case)})

    notes = []
    for note in bundle['decisions']:
        if note['requirement_id'] not in requirements: raise ValueError('Unknown reviewer requirement')
        for eid in note['evidence_ids']:
            if eid not in evidence or note['requirement_id'] not in evidence[eid]['requirement_ids']:
                raise ValueError('Reviewer note cites unknown or unrelated evidence')
        try: datetime.fromisoformat(note['created_at'].replace('Z', '+00:00'))
        except ValueError as exc: raise ValueError('Invalid reviewer timestamp') from exc
        normalized = dict(note, origin='unverified_reviewer_note', id='N' + fingerprint(note)[:20])
        if normalized not in notes: notes.append(normalized)

    rows = []
    for rid, requirement in requirements.items():
        items = [e for e in evidence.values() if rid in e['requirement_ids']]
        groups = []
        for sid in sorted({e['subject_id'] for e in items if e['kind'] == 'test'}):
            cases = [e for e in items if e['kind'] == 'test' and e['subject_id'] == sid]
            by_case = {}
            for item in cases: by_case.setdefault(item['case']['id'], set()).add(item['case']['status'])
            contradictions = sorted(k for k, states in by_case.items() if 'passed' in states and 'failed' in states)
            statuses = {e['case']['status'] for e in cases}
            outcome = ('disputed' if contradictions else 'reported_failed' if 'failed' in statuses else
                       'reported_inconclusive' if 'error' in statuses else 'reported_passed')
            groups.append({'subject_id': sid, 'outcome': outcome, 'case_count': len(by_case),
                           'observations': dict(Counter(e['status'] for e in cases)),
                           'contradictory_case_ids': contradictions, 'evidence_ids': [e['id'] for e in cases]})
        relevant_notes = [n for n in notes if n['requirement_id'] == rid]
        decisions = {}
        for note in relevant_notes:
            for eid in note['evidence_ids']: decisions.setdefault(eid, set()).add(note['disposition'])
        review_disputed = any('disputed' in states or ('dismissed' in states and 'needs_reproduction' in states)
                              for states in decisions.values())
        rows.append({'requirement': deepcopy(requirement), 'status': 'inconclusive' if items else 'not_assessed',
                     'applicability': 'unknown', 'whole_requirement_verified': False,
                     'reason': 'Evidence is scoped and unauthenticated; applicability and full coverage remain unverified.' if items else 'No requirement-specific evidence supplied.',
                     'evidence_ids': [e['id'] for e in items], 'test_scopes': groups,
                     'review_note_ids': [n['id'] for n in relevant_notes], 'review_disputed': review_disputed,
                     'exploitability': 'not_assessed'})
    return {'schema_version': '1.0', 'profile': PROFILE,
            'catalog': {'id': catalog['catalog_id'], 'version': catalog['version'], 'sha256': sha},
            'requirements': rows, 'subjects': list(subjects.values()), 'evidence': list(evidence.values()),
            'review_notes': notes, 'duplicates_collapsed': duplicates,
            'coverage': {'partial': True, 'requirements_total': len(rows), 'requirements_verified': 0,
                         'requirements_with_evidence': sum(bool(r['evidence_ids']) for r in rows),
                         'source_review_status': (review or {}).get('status', 'not_requested'),
                         'unmerged_evidence': unmerged,
                         'excluded_topics': catalog['excluded_topics']},
            'correctness_verified': False, 'compliance_certified': False, 'boundary': BOUNDARY}


def summary_lines(view):
    lines = ['REQUIREMENT EVIDENCE', view['boundary'],
             'Catalog: ' + view['catalog']['id'] + ' v' + view['catalog']['version'] + ' | SHA-256 ' + view['catalog']['sha256'],
             f"{len(view['subjects'])} execution subject(s); {view['coverage']['requirements_with_evidence']} requirements with evidence; 0 fully verified."]
    for subject in view['subjects']:
        lines += ['', 'Subject ' + subject['id'] + ' | ' + subject['kind'] + ' | ' + subject['backend'],
                  'Origin: imported_unverified; inventory binding: not_established',
                  'Snapshot: ' + str(subject['snapshot_id']), 'Artifact: ' + (str(subject['artifact']) if subject['kind'] == 'library' else 'See provider runtime in JSON'),
                  'Reports: ' + ', '.join(subject['report_ids']), 'Reported states: ' + ', '.join(subject['reported_run_states'])]
        if subject['mutation']: lines.append('DESIGNATED SOURCE FIXTURE: ' + subject['mutation']['name'])
        if subject['kind'] == 'provider' and subject['fixture'] != 'provider': lines.append('DESIGNATED HARNESS FIXTURE: ' + subject['fixture'])
        lines += ['Setup error: ' + error for error in subject['errors']]
        lines += ['Reproduction recipe (data only): ' + canonical(command) for command in subject['reproduction']]
        lines.append('Coverage: partial; ' + str(sum(len(c.get('gaps', [])) for c in subject['coverage'])) + ' native omission/parse records retained in JSON.')
        gap_counts = Counter(g['reason'] for c in subject['coverage'] for g in c.get('gaps', []))
        if gap_counts: lines.append('Native coverage gaps: ' + canonical(dict(gap_counts)))
        lines.append('Outside scope: unindexed/generated/header/assembly code, unresolved dispatch, dataflow and timing proofs; see original JSON coverage.')
        if subject['unmapped_case_ids']: lines.append('Cases outside catalog mapping: ' + ', '.join(sorted(set(subject['unmapped_case_ids']))))
    for row in view['requirements']:
        lines += ['', row['requirement']['id'] + ': ' + row['status'] + ' | applicability unknown; not verified in full']
        for group in row['test_scopes']:
            lines.append(group['subject_id'] + ': ' + group['outcome'] + ' | ' + str(group['case_count']) + ' distinct cases')
            if group['contradictory_case_ids']: lines.append('Contradictions: ' + ', '.join(group['contradictory_case_ids']))
        if row['review_disputed']: lines.append('Reviewer dispositions disagree; retained for review.')
    lines += ['', 'Catalog exclusions: ' + '; '.join(view['coverage']['excluded_topics'])]
    lines += ['Unmerged evidence: ' + canonical(item) for item in view['coverage']['unmerged_evidence']]
    return lines


def detail_lines(view, requirement_id, include_tests=True):
    row = next(r for r in view['requirements'] if r['requirement']['id'] == requirement_id)
    requirement = row['requirement']
    lines = [requirement_id + ' | ' + row['status'], requirement['title'],
             'Specification: ' + requirement['source_id'] + ' / ' + requirement['locator'],
             'Applies when: ' + requirement['applicability'], 'Required behavior: ' + requirement['expected_behavior'],
             'Errata disposition: ' + requirement['errata_disposition'], row['reason']]
    for item in view['evidence']:
        if item['id'] not in row['evidence_ids']: continue
        if item['kind'] == 'test' and not include_tests: continue
        lines += ['', item['id'] + ' | ' + item['kind'] + ' | ' + item['status'],
                  'Subject: ' + item['subject_id'], 'Provenance: ' + ', '.join(item['provenance'])]
        if item['kind'] == 'test':
            case = item['case']
            lines += ['Case: ' + case['id'] + ' / ' + case['description'], 'Oracle: ' + case['locator'],
                      'Expected: ' + canonical(case['expected']), 'Observed: ' + canonical(case['observation'])]
        elif item['kind'] == 'hypothesis':
            h = item['hypothesis']
            lines += [h['title'], 'Source: ' + canonical(item['source']),
                      'Observed behavior: ' + h['observed_behavior'], 'Expected behavior: ' + h['expected_behavior'],
                      'Applicability: ' + h['applicability_reason'], 'Possible impact (unverified): ' + h['possible_impact'],
                      'Assumptions: ' + canonical(h['assumptions']), 'Proposed reproduction (not executed): ' + canonical(h['validation_plan'])]
            lines += ['Additional wording/assumptions for the same candidate: ' + canonical(variant) for variant in item.get('variants', [])]
        else: lines.append('Inventory pointer: ' + canonical(item['source']))
    for note in view['review_notes']:
        if note['id'] in row['review_note_ids']:
            lines += ['', 'Reviewer note (unverified): ' + note['reviewer'] + ' | ' + note['disposition'], note['note'],
                      'Evidence: ' + ', '.join(note['evidence_ids'])]
    for subject in view['subjects']:
        if any(g['subject_id'] == subject['id'] for g in row['test_scopes']):
            lines += ['Source candidate: ' + s['path'] + ':' + str(s['start_line']) + '-' + str(s['end_line']) +
                      ' | ' + s['name'] + ' | SHA-256 ' + s['file_sha256'] for s in subject['source_locations']
                      if requirement_id in s['requirement_ids']]
    lines += ['Impact: hypotheses and reviewer notes are claims; attacker control, reachability and security impact are not demonstrated.',
              'Coverage: selected cases and source candidates only; whole requirement remains unverified.']
    return lines
