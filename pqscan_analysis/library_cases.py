"""OpenSSL API-specific expectations for the milestone 4 vector subset."""
if __package__:
    from .validation_cases import cases_from_vectors
else:
    from validation_cases import cases_from_vectors


def library_cases(vectors):
    cases = cases_from_vectors(vectors)
    for case in cases:
        if case['kind'] == 'derived_negative' and case['operation'] == 'decapsulate':
            case['description'] = 'Malformed key/ciphertext length rejected by EVP (mapped to ValueError by adapter).'
            case['locator'] = 'FIPS 203 section 7.3; OpenSSL EVP import/decapsulation rejection'
        elif case['kind'] == 'derived_negative' and case['operation'] == 'verify_context':
            case['description'] = case['id'] + ': EVP must reject; no error-versus-false API equivalence claimed.'
            case['locator'] = 'FIPS 204 sections 5.3 and 6.3; EVP rejection only'
    return cases
