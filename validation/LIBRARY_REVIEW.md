# Library implementation analysis — milestone 4b

PQScan now has a separate repository-to-artifact pipeline. Its first reviewed
adapter targets OpenSSL's portable C implementation. Other libraries can be
captured and identified as unsupported without executing their code. This is a
bounded implementation-validation feature, not a general native-code audit.

## Run it

From the PQScan project directory, with Python 3.9+ and Docker:

```bash
# Inspection never invokes Git, build scripts, target imports or Docker.
python3 -m pqscan_analysis.library inspect path/to/library -o reports/library-input.json

# Explicit dependency preparation; downloads the base/toolchain, not target code.
docker build -t pqscan-library:openssl-portable-v1 validation/library-container

# Use an unconfigured OpenSSL checkout, with no root Makefile or configdata.pm.
python3 -m pqscan_analysis.library run repos_to_test/openssl \
  --image pqscan-library:openssl-portable-v1 --timeout 900 \
  -o reports/library-validation.json

python3 -m pqscan_analysis.library read reports/library-validation.json
```

Use a new output filename outside the target repository. The `.artifacts`
directory beside a completed build contains its exact `libcrypto.so`, snapshot
manifest and compilation records. Loading JSON never executes the library or
recorded commands. It checks the schema, identities, case oracles, build recipe
and isolation settings, recomputes results and labels the report
`imported_unverified`. Preserve the matching PQScan revision: historical reports
with different runner, harness, snapshot code, recipe, vectors or catalog hashes
are rejected by the current reader. Hash consistency is not authenticity.

Exit codes: **0** means inspection completed or all selected tests passed;
**1** means at least one test mismatch; **2** means setup failure or inconclusive
execution. Build failures and malformed worker output never become test passes.
An early capture/preflight failure prints an error before a report exists;
once captured, the JSON checkpoint preserves subsequent setup failures.

## Recorded source and build

The initial exercised target is OpenSSL **4.2.0-dev**, revision hint
`b86f4c163100a4626597d28126c8b6807a83d1dc`. Adapter detection uses source-layout
markers, not that version string; another revision may have unsupported APIs or
build requirements and must be tested independently.

All non-VCS regular files are captured, including ignored/untracked files and
materialized submodule contents. File bytes, paths and executable bits determine
the snapshot ID. Git revision is only a hint: it is neither the identity nor a
cleanliness assertion. No Git hooks, commands or external worktree pointers run.
The capture is not an atomic filesystem snapshot; the bytes actually captured
and consumed are the recorded input. `.git`, `.hg` and `.svn` paths are omitted.

Symlinks and special files fail closed. Limits are 20,000 files, 40,000 directory
entries, depth 64, 32 MiB per file and 256 MiB total. Exceeding a limit rejects
the capture instead of building an incomplete snapshot. Uninitialized submodules,
LFS pointers or missing vendored inputs are not fetched; a required missing input
will fail the fixed build.

The Dockerfile pins the Python base digest and Debian package repository snapshot.
The report records the local immutable image ID, platform, compiler version and
installed-package-list hash. The runner never pulls/builds an image automatically.
The build invokes only this fixed recipe:

```text
perl /source/Configure linux-aarch64|linux-x86_64 shared no-asm no-module
    no-tests no-apps no-docs no-quic -O1
make -j2 build_generated
make -j2 libcrypto.so
```

`CC` is the staged command-recording wrapper around `/usr/bin/clang-14`.
Compilation records are data, never shell commands for the host to execute.
Build scripts still execute, but only in the explicit isolated build container.
The source mount and root filesystem are read-only; output goes to bounded tmpfs.
The original checkout, Docker socket and host home are not mounted.

Both phases require UID 65534, dropped capabilities, no-new-privileges, seccomp,
no active interface other than loopback and a read-only root. Limits include two
CPUs, 2 GiB memory, 128 processes, 1.5 GiB scratch space, file descriptors,
wall-clock time and output sizes. Only the exact exported ELF artifact is staged
into a fresh test container. The adapter checks its loaded path/hash and the
selected built-in `default` provider; it uses a separate OpenSSL library context.
Python uses built-in hashing to avoid loading a second system `libcrypto`.

Source manifests are checked before and after the build. This is a recorded local
pipeline, not independent build attestation or proof against a malicious compiler,
image or target build script. No binary-to-source mathematical equivalence is
claimed. Reproduction starts from the recorded source and recipe; binary hashes
may change across builds, and bit-for-bit reproducibility is not asserted.

## Native source evidence

libclang 14 parses selected compiled C translation units in ML-KEM, ML-DSA,
their provider adapters and EVP entry points. Include/define options are
allowlisted; plugin, response-file and unsupported parse options produce coverage
gaps. Functions, source spans, direct call declarations, macro counts and excerpts
are bound to source-file hashes. Function-pointer dispatch remains unresolved.

Limits are 24 translation units, 1,200 function definitions, 4,000 call sites,
24,000 source characters, 6,000 excerpt characters per translation unit and
4,000 per excerpt. Core algorithm files and verification/decapsulation/import
functions receive excerpt priority. Parse errors and omitted/truncated evidence
are recorded. The index handles only configured C branches; headers, generated
code, other files, optimized assembly and other languages remain outside it.
It is not a control/dataflow proof, arithmetic audit or timing analysis.

## Executed cases and requirement links

The pinned public NIST ACVP subset is described in [the vector manifest](vectors/manifest.json)
and [milestone 4 documentation](README.md). The EVP adapter runs:

| Scope | Cases |
| --- | ---: |
| ML-KEM-768 decapsulation, including invalid-ciphertext fallback secrets | 10 |
| ML-KEM malformed key/ciphertext lengths | 4 |
| ML-DSA-65 pure external verification, including contexts | 15 |
| ML-DSA modified message/context, short signature and overlong context | 4 |

Each case retains its input/vector locator, expected oracle, observation and
pass/fail/error classification. The adapter maps documented EVP input rejection
to the expected result; an operational verification error is not counted as a
signature rejection. The requirement links cover selected evidence for
`F203-IMPLICIT-REJECTION`, `F203-DECAPS-INPUT`, `F204-VERIFY` and `F204-CONTEXT`.
Function-name links are reviewed candidates, not proven execution paths.
Every requirement remains `not_assessed_in_full`.

The existing 12-requirement catalog is unchanged. This milestone makes no new
claims about arithmetic, encoding internals, key generation, encapsulation,
signing, SLH-DSA, other parameter sets, optimized backends, constant-time
execution or deployed protocol behavior. Extending those areas requires reviewed
requirements, API semantics and additional independent oracles. No exploitation
or NIST/ACVP/FIPS certification claim follows from these results.

## Source mutation regression

Mutations apply only to the disposable captured copy; the original files remain
untouched. Exact unique anchors prevent applying them to an unexpected revision.

```bash
python3 -m pqscan_analysis.library run repos_to_test/openssl \
  --image pqscan-library:openssl-portable-v1 --timeout 900 \
  --mutation kem-zero-secret -o reports/library-kem-mutant.json

python3 -m pqscan_analysis.library run repos_to_test/openssl \
  --image pqscan-library:openssl-portable-v1 --timeout 900 \
  --mutation kem-repaired -o reports/library-kem-repaired.json
```

`kem-zero-secret` replaces the selected shared-secret bytes in the C implementation
with zero. On the exercised revision, OpenSSL's key-import pairwise check rejects
the affected keys before decapsulation; those ten known-answer cases are recorded
as execution errors and the run is **inconclusive**, not passed or a claimed
output mismatch. `dsa-accept-invalid` bypasses the internal verification decision
and produces **15 explicit false-accept failures** on this revision.
`kem-repaired` and `dsa-repaired` apply then reverse the respective mutation before
building. Repaired snapshots must match the original input identity and pass the
same cases. These designated defects test the detection pipeline; they are not
claims of defects in OpenSSL.

Host regressions run without Docker. An optional integration test explicitly
builds the baseline and both mutated/repaired source pairs:

```bash
python3 -m unittest discover -s tests -p test_library.py
PQSCAN_LIBRARY_IMAGE=pqscan-library:openssl-portable-v1 \
PQSCAN_LIBRARY_REPO=repos_to_test/openssl \
python3 -m unittest discover -s tests -p test_library.py
```

Schemas live in `standards/library-{report,build,native,tests}.schema.json`.
Milestone 5 can import these records into GUI/text/PDF requirement views with
scoped outcomes and provenance. LLM consumption of the native index, broader
library adapters and authenticated repository verdicts remain subsequent work.
