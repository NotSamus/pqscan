# Milestone 4b — implementation and validation results

Implemented library-repository capture and an explicit OpenSSL source-build/test
adapter. See [usage and reproduction](LIBRARY_REVIEW.md) and
[overall implementation scope](../IMPLEMENTATION_SCOPE.md).

## Live source-build regressions

Five independent isolated builds exercised the local OpenSSL 4.2.0-dev checkout.
Each test phase loaded the binary exported by that run and checked its identity.

| Source variant / saved evidence | Outcome | Passed | Failed | Execution errors |
| --- | --- | ---: | ---: | ---: |
| [baseline](../reports/milestone-4b-openssl-baseline.json) | passed | 33 | 0 | 0 |
| [kem-mutant](../reports/milestone-4b-openssl-kem-mutant.json) | inconclusive | 23 | 0 | 10 |
| [kem-repaired](../reports/milestone-4b-openssl-kem-repaired.json) | passed | 33 | 0 | 0 |
| [dsa-mutant](../reports/milestone-4b-openssl-dsa-mutant.json) | failed | 18 | 15 | 0 |
| [dsa-repaired](../reports/milestone-4b-openssl-dsa-repaired.json) | passed | 33 | 0 | 0 |

The all-zero KEM mutation is blocked by OpenSSL's key-import pairwise consistency
check. Its ten known-answer operations cannot complete, so PQScan retains an
**inconclusive** result rather than treating exceptions as output mismatches.
The DSA mutation accepts invalid signatures and triggers **15 explicit failures**.
Both repaired source copies match the baseline snapshot and pass all 33 cases.
These deliberate mutations are detection fixtures, not discovered OpenSSL defects.

## Baseline provenance and native coverage

- OpenSSL revision hint: `b86f4c163100a4626597d28126c8b6807a83d1dc`.
- Captured snapshot: `da4b0bb7187464ad9e152b4faf353d871f5f8f0be7760f4091f13dff20865b03`.
- Capture: 6161 files, 139000136 bytes, including non-VCS untracked/ignored inputs.
- Toolchain image: `sha256:74c023b2c38ddc376ade04964c73f60a9d9bc739d486643179cc6e6cb6055708` (`linux/arm64`).
- Baseline artifact SHA-256: `c158447026c05bc33620a1d59d722d3c2e3decfba2f1ecde65c80dc6ef56e8d9`.
- Backend/provider: portable `no-asm` build, built-in `default` provider.
- Compiler records: 1012.
- Native index: 15 C translation units, 282 functions, 1458 call sites; no parse errors.
- Source excerpts: 30 slices, 23999 characters; omissions and truncation remain explicit.

Every JSON has a sibling `.artifacts` directory containing its binary, captured
file manifest and compilation records. Each binary's file hash was checked
against its report. Imported reports passed both semantic validation and an
independent JSON Schema validator. A fresh capture after the runs matched the
baseline, confirming that the original checkout was unchanged.

## Regression verification

The full test suite ran **200 tests: 199 passed, one skipped**. It included the
existing provider Docker integration. The skipped test is the opt-in library
build suite; its five build scenarios were run through the CLI above and checked
with assertions for expected counts, snapshot identities, native evidence and
artifact hashes. This avoids executing the same five builds a second time.

The new host tests cover capture limits, ignored/untracked inputs, source mutation
and repair, unsafe files and compiler metadata, isolation commands, substituted
artifacts, altered reports, case-result recomputation, error classification and
non-executing inspection/loading.

## Scope

Other libraries can be inspected; only the OpenSSL adapter is implemented.
Selected ML-KEM-768 decapsulation and ML-DSA-65 verification cases are covered.
Requirements remain `not_assessed_in_full`; this is not whole-algorithm proof,
constant-time analysis, exploitability evidence or NIST certification. Native
LLM review, GUI/PDF presentation and evidence fusion remain subsequent work.
