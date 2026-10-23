# Library and implementation repositories

PQC libraries and algorithm implementation repositories are primary analysis
subjects, alongside applications that use them. A chatroom is one downstream
integration example. This document records the current scope; the research
proposal and its PDF remain the original planning snapshot.

## Current support

| Subject | Implemented support | Remaining limits |
| --- | --- | --- |
| Application or protocol repository | Inventory, bounded Python source review and unverified LLM hypotheses | No deployed protocol validation |
| Library API and language bindings | Python source review; fixed pqcrypto 0.3.4 provider tests | No arbitrary provider or binding adapter |
| Implementation source repository | Bounded file capture, source identities and library-adapter detection | Unsupported library builds remain explicit |
| OpenSSL native implementation | Isolated source build, libclang index of selected C translation units, EVP tests of the exact built artifact | Portable C only; selected ML-KEM-768 decapsulation and ML-DSA-65 verification cases |
| A built library artifact | Recorded source/build/test chain, loaded artifact/provider identity and individual test results | Local provenance, not independent attestation or whole-implementation certification |

A repository can contain public APIs, bindings, reference code, optimized
backends, generated files and examples. Results apply only to the recorded
subject and configuration. A package with the same name does not establish
anything about another checkout or build.

## Milestone 4b implementation

The first end-to-end target is the existing OpenSSL 4.2.0-dev checkout at
`repos_to_test/openssl`, revision hint
`b86f4c163100a4626597d28126c8b6807a83d1dc`. The manifest, rather than this hint,
is the tested input identity. See [library analysis documentation](validation/LIBRARY_REVIEW.md)
for commands, limits, exact case coverage and reproduction.

The separate `python3 -m pqscan_analysis.library` CLI provides:

1. `inspect`: capture all non-VCS regular files, including ignored/untracked inputs,
   with hashes and executable bits; identify whether a reviewed adapter exists.
2. `run`: build a captured OpenSSL tree in a restricted, offline Docker container
   using a fixed recipe and prepared toolchain image; record compilation metadata.
3. A bounded libclang index of selected compiled C branches, functions, direct
   call declarations, macro counts and cited excerpts, with explicit coverage gaps.
4. A fresh isolated test container that loads the exact exported library and its
   built-in default provider, then executes 33 selected known-answer/negative cases.
5. Requirement-to-source-candidate-to-case links and a checked
   `source_build_binding`, scoped to the recorded snapshot, binary and backend.
6. Designated source mutations and repairs on disposable snapshots, with distinct
   input identities and the same test oracles.
7. `read`: schema, identity, recipe and result validation without executing code;
   imported reports remain unauthenticated.

The original checkout is not mounted or modified. Ordinary scans, source reviews,
LLM reviews and inspection execute no target code. Only the explicit library
`run` command executes target build scripts, inside its isolated build container.
The milestone 4 fixed-provider validator remains separate and correctly retains
`repository_binding=none`.

## Acceptance and evidence boundaries

- Modified inputs have different snapshot identities; repaired inputs match the
  baseline. Symlinks, special files and incomplete captures fail closed.
- The artifact tested is the artifact exported from the recorded source build;
  source, runtime provider, build recipe and artifact mismatches prevent attaching
  a completed result to the repository.
- Selected baseline cases pass; designated source defects are detected; repaired
  source passes the same regression suite. These fixtures are not OpenSSL defects.
- Build/setup failures, harness errors and test mismatches remain distinct.
- Requirements remain `not_assessed_in_full`. Tests and source references support
  only their stated scope. Imported evidence cannot authenticate itself.
- Unsupported code, unresolved dispatch and untested requirements remain unknown.
  Passing selected cases does not prove mathematical equivalence, constant-time
  execution, application security, exploitability or NIST certification.

## Subsequent work

The initial 12-control catalog is unchanged. Add reviewed requirements and
independent oracles before making claims about arithmetic, encodings, keygen,
encapsulation, signing, additional parameter sets or SLH-DSA. Each additional
library, language or optimized backend needs its own build/API adapter and tests.
The native index is not yet supplied to an LLM. Milestone 5 now imports the
recorded library evidence into a scoped requirement view, GUI, text and PDF;
reviewer triage notes remain unverified claims. An exploitability assessment
also needs attacker control, reachability and demonstrated security impact.
