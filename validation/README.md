# Isolated provider validation (milestone 4)

This release supplies a separate, explicit executable-validation command. It
exercises the `pqcrypto==0.3.4` provider build in a restricted Docker container.
The original repository scanner and LLM reviewer continue to execute no target
code. A provider import found in a repository does **not** establish that this
container matches the installed or deployed provider. No application repository,
custom primitive, or model-generated test code is accepted by this runner.

For an implementation checkout and tests of its actual built artifact, use the
separate [milestone 4b library workflow](LIBRARY_REVIEW.md). Its first adapter
supports OpenSSL; this provider runner retains `repository_binding=none`.

## Prepare and run

From the PQScan project directory, with a local Linux Docker daemon or Docker
Desktop running:

```bash
docker build -t pqscan-validation:pqcrypto-0.3.4 validation/container
python3 -m pqscan_analysis.validation run \
  --image pqscan-validation:pqcrypto-0.3.4 \
  -o reports/provider-validation.json
```

Building is an explicit network-enabled setup step. The small build context
contains only the Dockerfile and package lock. Python 3.11.14's base image is
pinned by manifest digest. `pqcrypto==0.3.4`, `cffi==1.17.1` and `pycparser==2.22`
are installed from hash-checked binary wheels; source builds are disabled.
Linux arm64 and amd64 wheels are pinned. The chosen versions define a reproducible
test profile, not a recommendation that they are the latest or suitable for a
production deployment.

The run command does not build images, pull them, download vectors or install
packages. It resolves the requested local image to an immutable SHA-256 ID before
execution. Missing Docker, unavailable images, wrong provider versions, missing
symbols and incompatible platforms produce setup errors. There is no fallback
that imports a provider into the scanner's host process.

Use a new output filename for each run. The runner checkpoints a `pending` report
before Docker execution and atomically updates its own report. Invalid CLI inputs
or damaged bundled vectors fail preflight before creating an execution report.
Use `--timeout 60` to change the default 45-second container deadline (maximum 120).
Image inspection and cleanup each have separate short deadlines.

```bash
python3 -m pqscan_analysis.validation read reports/provider-validation.json
```

Reading validates the current profile, fixed test definitions, hashes, references,
observations and derived outcomes. It never executes anything and labels the
origin `imported_unverified`. Preserve the matching scanner checkout with a report:
loading against changed runner/adapter/vector/catalog hashes fails explicitly.
These consistency checks are not signatures or proof that a JSON author actually
ran a test. Report fields cannot certify themselves.

## Exact test scope

The corpus is a projection of the public [NIST ACVP-Server vector repository](https://github.com/usnistgov/ACVP-Server)
at commit `975de31eb83d87039ec88934fdc47d8c312b892d`. It retains original input and
expected-output bytes, group/test IDs and reasons. `vectors/manifest.json` records
exact upstream URLs and SHA-256 checksums, plus the selected artifact checksum.
No vector is downloaded at runtime.

| Cases | Interface | Oracle and requirement scope |
| --- | --- | --- |
| 10 ML-KEM-768 decapsulation vectors, group 5 / cases 86–95 | `pqcrypto.kem.ml_kem_768.decrypt(dk, c)` | Exact 32-byte NIST expected secret, including five correctly sized modified ciphertexts exercising implicit rejection (`F203-IMPLICIT-REJECTION`) |
| 4 ML-KEM malformed length tests | Same Python API | Ciphertext lengths 1087/1089 and key lengths 2399/2401 must raise `ValueError`; partial `F203-DECAPS-INPUT` evidence |
| 15 ML-DSA-65 verification vectors, group 3 / cases 31–45 | Pinned wheel's native `PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx` | Three accepted and twelve rejected external, pure-mode vectors with original contexts (`F204-VERIFY`) |
| 4 ML-DSA derived negative tests | Same native API | Changed message, changed context, truncated signature and a 256-byte context must return native rejection; partial `F204-VERIFY` / `F204-CONTEXT` evidence |

The ML-DSA Python wrapper in this wheel exposes no context argument. The adapter
therefore uses the exported native function with its reviewed C signature,
explicit argument lengths and a fixed public-key length check. It maps native
return values 0/-1 to true/false and rejects unexpected return codes as errors.
This is a native provider test, not a claim that the Python wrapper supports
nonempty contexts. See the [PQClean API declaration](https://github.com/PQClean/PQClean/blob/master/crypto_sign/ml-dsa-65/clean/api.h)
and [implementation](https://github.com/PQClean/PQClean/blob/master/crypto_sign/ml-dsa-65/clean/sign.c);
the installed wheel and its runtime native-library hash identify the tested build.

The overlong-context check establishes native rejection only. It does not resolve
the published FIPS 204 versus proposed errata distinction between error and false.
The existing requirements catalog preserves that distinction. No entire catalog
requirement is marked supported or violated from these partial tests. Valid
ML-KEM decapsulation cases cite FIPS 203 Algorithm 18 directly because the initial
catalog has no separate full decapsulation-correctness requirement ID.

Not covered: key generation or encapsulation known-answer tests, key coefficient
canonicality, embedded-key hash checks, randomness/failure injection, deterministic
signing, prehash modes, positive signing/verification at every context boundary,
SLH-DSA, other parameter sets, side channels, protocol authentication, replay,
application failure handling or exploitability. Tests are neither comprehensive
NIST ACVP coverage nor formal CAVP or CMVP validation. Round trips are not used as
a substitute for known-answer oracles.

## Isolation and execution evidence

The container has no active network interface other than loopback, no repository/home/
Docker-socket mount, no writable root filesystem, and runs as UID/GID 65534.
Capabilities are dropped and `no-new-privileges` is enabled. Docker's seccomp
filter must be active. The worker checks UID, active network interfaces, root mount
flags, effective capabilities, `NoNewPrivs` and seccomp before importing the
provider. Dormant kernel tunnel interfaces can exist on Docker Desktop; only
loopback may be up. Unexpected settings are setup errors.

Limits are one CPU, 256 MiB memory with no additional swap, 64 processes, 64 open
file descriptors, a bounded wall time and 1 MiB combined stdout/stderr. The
runner overrides image entrypoints and healthchecks, disables Docker log storage,
uses isolated Python mode, and mounts only a temporary copy of three reviewed
harness modules plus the fixed corpus, read-only. Image-declared volumes are
rejected. The harness checksum is checked again when staging. Only the container
with this run's generated UUID name is removed on completion, timeout or failure;
temporary data is cleaned up. A cleanup failure is reported as a setup error.

Docker and the selected image are trusted infrastructure. This is an OS container
boundary, not a VM attestation or a defense against a compromised Docker daemon.
Use a local daemon and the provided image build. The runner is intentionally not
an arbitrary untrusted-repository execution service.

The standalone JSON report stores the vector source revision and byte checksums,
runner/worker/adapter/case-definition hashes, package lock and Dockerfile hashes,
resolved image ID/architecture, exact command, Python/provider/dependency
versions, wrapper and native artifact hashes, isolation checks, expected and
observed outputs, and requirement/section references. Compiler flags are not
exposed by these prebuilt wheels; that limitation is recorded. An exact replay
uses the same image ID and matching scanner artifacts with a new output path;
the recorded temporary mount path itself is not reusable.

## Outcomes and fault fixtures

- `passed` / exit 0: every selected case matched its oracle.
- `failed` / exit 1: at least one completed case returned a mismatching output.
- `inconclusive` / exit 2: an unexpected per-case exception or adapter result
  prevents interpretation. Any other case failures remain visible.
- `setup_error` / exit 2: provider/runtime setup, container execution, timeout,
  output overflow, incomplete worker output or cleanup failed.
- `pending`: execution was checkpointed but no final result was saved.

Unexpected exceptions are not automatically labeled cryptographic defects. The
parent computes outcomes from the fixed oracles rather than trusting a worker's
pass/fail flag. Missing, duplicate or fabricated case IDs invalidate the run.
Every report keeps `correctness_verified=false`, `compliance_certified=false`,
`exploitability=not_assessed`, and `repository_binding=none`. Inventory, LLM
hypotheses, static CI severity gates and specification verdicts are unchanged.
Fusion and GUI presentation belong to milestone 5.

Two designated harness mutants test that a falsely reassuring implementation is
caught. They wrap the real pinned provider inside the same container; they do not
modify package files. They are explicitly labeled fixtures in every report:

```bash
python3 -m pqscan_analysis.validation run --image pqscan-validation:pqcrypto-0.3.4 \
  --fixture zero-secret -o reports/mutant-zero-secret.json
python3 -m pqscan_analysis.validation run --image pqscan-validation:pqcrypto-0.3.4 \
  --fixture accept-all-signatures -o reports/mutant-accept-all.json
```

Expected results are 10 mismatches for `zero-secret` and 16 for
`accept-all-signatures`, both exit 1. These are deliberately injected failures,
not findings against the unmodified provider. Returning the wrong shared secret
or accepting invalid signatures demonstrates harness detection; it does not
establish an exploitable path in an unspecified application.

## Reproduce and test

To reproduce the corpus, download the two exact upstream URLs from
`vectors/manifest.json` explicitly, then run the offline extractor. It checks
both upstream hashes and the resulting projection hash and refuses overwrite:

```bash
python3 validation/extract_vectors.py mlkem-original.json mldsa-original.json reconstructed.json
```

Ordinary tests use fake observations and assert the trust boundaries without
Docker or a provider import. Docker integration is a separate explicit opt-in:

```bash
python3 -m unittest discover -s tests
PQSCAN_VALIDATION_IMAGE=pqscan-validation:pqcrypto-0.3.4 \
  python3 -m unittest discover -s tests -p test_validation.py
```

The integration test runs the real provider and both designated mutants, checks
all expected mismatch counts and validates the result contracts. This release
was exercised on Linux arm64 through Docker Desktop; the amd64 wheel is pinned
but has not been exercised here.
