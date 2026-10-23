"""Fixed, reviewed tests; no model-generated code or target paths."""
from copy import deepcopy

PROFILE = 'pqcrypto-0.3.4-v1'
FIXTURES = ('provider', 'zero-secret', 'accept-all-signatures')


def cases_from_vectors(vectors):
    cases = []
    for vector in vectors['cases']:
        kem = vector['operation'] == 'decapsulate'
        inputs = deepcopy(vector['inputs'])
        expected = {'kind': 'bytes', 'value': inputs.pop('k').lower()} if kem else {'kind': 'boolean', 'value': inputs.pop('testPassed')}
        refs = (['F203-IMPLICIT-REJECTION'] if vector['reason'] == 'modified ciphertext' else []) if kem else ['F204-VERIFY']
        cases.append({'id': vector['id'], 'operation': vector['operation'], 'inputs': inputs,
                      'expected': expected, 'requirement_ids': refs, 'vector_id': vector['id'],
                      'kind': 'nist_known_answer', 'description': vector['reason'],
                      'locator': 'FIPS 203 section 6.3, Algorithm 18' if kem else 'FIPS 204 sections 5.3 and 6.3, Algorithms 3 and 8'})
    kem = next(v for v in vectors['cases'] if v['operation'] == 'decapsulate' and v['reason'] == 'valid decapsulation')
    for field, size in [('c', 1087), ('c', 1089), ('dk', 2399), ('dk', 2401)]:
        inputs = {k: kem['inputs'][k] for k in ('dk', 'c')}
        inputs[field] = (inputs[field] + '00')[:size * 2]
        cases.append({'id': f'mlkem-{field}-length-{size}', 'operation': 'decapsulate', 'inputs': inputs,
                      'expected': {'kind': 'exception', 'value': 'ValueError'},
                      'requirement_ids': ['F203-DECAPS-INPUT'], 'vector_id': kem['id'],
                      'kind': 'derived_negative', 'description': f'{field} length {size}; Python API must reject with ValueError.',
                      'locator': 'FIPS 203 section 7.3; pqcrypto 0.3.4 Python length-check contract'})
    dsa = next(v for v in vectors['cases'] if v['operation'] == 'verify_context' and v['inputs']['testPassed'])
    for mutation in ('message', 'context', 'short-signature', 'overlong-context'):
        inputs = {k: dsa['inputs'][k] for k in ('pk', 'message', 'context', 'signature')}
        if mutation in ('message', 'context'):
            raw = bytearray.fromhex(inputs[mutation]); raw[0] ^= 1; inputs[mutation] = raw.hex()
        elif mutation == 'short-signature':
            inputs['signature'] = inputs['signature'][:-2]
        else:
            inputs['context'] = '00' * 256
        cases.append({'id': 'mldsa-' + mutation, 'operation': 'verify_context', 'inputs': inputs,
                      'expected': {'kind': 'boolean', 'value': False},
                      'requirement_ids': ['F204-CONTEXT'] if 'context' in mutation else ['F204-VERIFY'],
                      'vector_id': dsa['id'], 'kind': 'derived_negative',
                      'description': mutation + '; native verify_ctx must return -1 (mapped to false).',
                      'locator': 'FIPS 204 sections 5.3 and 6.3; native rejection only, not error-versus-false API conformance'})
    return cases


def observe(adapter, case, fixture='provider'):
    """Faults are designated harness fixtures, never edits to a real provider."""
    args = {k: bytes.fromhex(v) for k, v in case['inputs'].items()}
    try:
        if case['operation'] == 'decapsulate':
            value = adapter.decapsulate(args['dk'], args['c'])
            if fixture == 'zero-secret':
                value = bytes(32)
            if type(value) is not bytes or len(value) != 32:
                return {'kind': 'unexpected', 'value': 'decapsulation returned an invalid type or size'}
            return {'kind': 'bytes', 'value': value.hex()}
        value = adapter.verify_context(args['pk'], args['message'], args['context'], args['signature'])
        if fixture == 'accept-all-signatures':
            value = True
        if type(value) is not bool:
            return {'kind': 'unexpected', 'value': 'verification did not return a boolean'}
        return {'kind': 'boolean', 'value': value}
    except Exception as exc:
        # Exception text is bounded and not needed as a cryptographic oracle.
        return {'kind': 'exception', 'value': type(exc).__name__}


def evaluate(case, observation):
    if observation == case['expected']:
        return 'passed'
    if observation['kind'] == 'exception' and case['expected']['kind'] != 'exception':
        return 'error'
    if observation['kind'] == 'unexpected':
        return 'error'
    if case['expected']['kind'] == 'exception' and observation['kind'] == 'exception':
        return 'error'
    return 'failed'
