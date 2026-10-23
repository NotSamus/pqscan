# PQScan

Analyze a local repository for quantum-vulnerable cryptography and evidence of
post-quantum cryptography (PQC). Scanning runs offline with **Python 3.9+ and no
third-party dependencies**. Optionally add a **local Ollama review** and export a
**PDF backed by JSON**. PDF export uses ReportLab. The scanner never imports,
builds, or executes the target code. A separate explicit validation command can
exercise a pinned provider build inside a restricted Docker container. A separate
library workflow can build and test a captured implementation checkout.

The intended scope includes **PQC libraries and algorithm implementation
repositories**, alongside applications that use them. **Milestone 4b** adds source
snapshots, a native C index and isolated source-to-artifact tests for OpenSSL.
Other libraries can be inspected but need their own reviewed build/test adapter.
See [implementation scope](IMPLEMENTATION_SCOPE.md) and
[library analysis instructions](validation/LIBRARY_REVIEW.md).

```bash
python3 /Users/notsamus/Desktop/pqscan/pqscan.py ~/path_to_repo
```

`pqscan.py` is self-contained. You can copy it to your home directory and run the
shorter command:

```bash
cp /Users/notsamus/Desktop/pqscan/pqscan.py ~/pqscan.py
python3 ~/pqscan.py ~/path_to_repo
```

Use `python` instead of `python3` if that command selects Python 3.9 or later on
your system. A target may be any local folder; it does not need to be a Git
checkout. Nothing needs to be installed in the target repository.

## Desktop app (PySide6)

The desktop app uses the same scanner, local Ollama client, and JSON/PDF pipeline:

```bash
cd /Users/notsamus/Desktop/pqscan
.venv/bin/python -m pip install -r requirements-gui.txt
.venv/bin/python pqscan_gui.py

# Preselect a repository, or inspect a previously saved report
.venv/bin/python pqscan_gui.py --repository ~/path_to_repo
.venv/bin/python pqscan_gui.py --report reports/scan.json
```

Choose a repository and report folder. Optionally enable local Ollama review and
refresh the downloaded-model list, then click **Analyze repository**. JSON is
always saved; PDF is enabled by default. Each scan gets a unique output filename.
Scanning, inference, and PDF generation run in a separate process, so the window
stays responsive. Cancel stops that process and retains any saved JSON checkpoint.
It does not stop your Ollama service.

The overview shows fusion evidence and missing verification. The findings tab
supports search, severity/context filters, sorting, and detailed source evidence.
Separate tabs show model commentary, coverage gaps, and activity/errors.
**Load JSON** reopens earlier scans, **Export PDF** renders the loaded report
without rescanning or calling the model, and **Open report** opens the PDF (or JSON
when no PDF exists). The GUI requires `pqscan_gui.py` and `pqscan.py` together;
the CLI remains portable as a single file.

## Fusion assessment: capability, implementation, verification

The `pqscan-evidence-fusion-v1` profile gives PQC declarations credit while
distinguishing what each signal actually establishes:

| Evidence | Fusion interpretation |
| --- | --- |
| Recognized PQC dependency or algorithm import | **PQC capability declared**. A possible adoption-intent signal; installed version and actual use remain unverified. |
| PQC algorithm in configuration | **PQC configuration evidence**. Does not prove that configuration was deployed or negotiated. |
| Recognized PQC call or source usage pattern | **PQC implementation evidence**. Stronger adoption evidence; reachability and correctness still require verification. |
| PQC only in tests, examples, or recognized development dependencies | **PQC limited to tests/examples**. Does not establish production protection or test success. |
| Classical production crypto alongside PQC signals | **Mixed evidence**. Positive findings do not cancel classical paths; inspect hybrid design and fallbacks. |

Declarations and usage together corroborate adoption. They are still static
observations, not independent proofs. Multiple findings on the same file/line and
evidence kind count as one site. No arbitrary percentage or score is presented
as the probability of being quantum-safe.

The name-based PQC library registry currently recognizes `pqcrypto`, `oqs`,
`liboqs`, `liboqs-python`, `oqs-provider`, `@noble/post-quantum`, and `circl`.
Their project documentation describes PQC capabilities:
[pqcrypto](https://github.com/backbone-hq/pqcrypto),
[Open Quantum Safe](https://openquantumsafe.org/liboqs/),
[noble-post-quantum](https://github.com/paulmillr/noble-post-quantum), and
[CIRCL](https://github.com/cloudflare/circl).
Recognition does not audit the declared version, provenance, installed provider,
or supported parameter sets. Generic dependencies such as `cryptography` and
OpenSSL receive no PQC capability credit based solely on their names.

`package.json` uses dependency fields rather than descriptions/scripts;
`devDependencies` are classified as test context. Requirements files use package
declarations rather than comments. Other supported manifests retain lexical
inventory rules, so inspect their evidence for false positives.

The profile explicitly records **runtime verification not performed**,
**implementation tests not executed**, and **security review not performed**.
Ollama explains the evidence but cannot raise its verification level. This
scan profile does not execute validation suites, observe deployed protocols, accept
reviewer attestations, or issue readiness certificates. The separate milestone 4
provider runner records bounded test results without changing these scan claims.
Broader conclusions require additional
evidence tied to a specific implementation and scope. The original scanner
assessment and CI severity gates remain unchanged.

Fusion results appear in `fusion_assessment` in JSON, in the text/PDF reports,
and in the desktop overview. Loading older JSON recomputes fusion from the saved
findings; a supplied derived claim cannot grant itself certification.

## Correctness and NIST compliance evidence

The `pqscan-nist-correctness-v1` profile adds a separate
`correctness_compliance` section. It does not turn adoption evidence into a
conformance claim. It records the exact evidence that can be checked statically:

| Algorithm | Approved parameter sets |
| --- | --- |
| ML-KEM (FIPS 203) | ML-KEM-512, ML-KEM-768, ML-KEM-1024 |
| ML-DSA (FIPS 204) | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| SLH-DSA (FIPS 205) | SHA2/SHAKE variants of 128s, 128f, 192s, 192f, 256s, and 256f |

An approved identifier is reported as **approved identifier observed**. A bare
family name such as `ML-KEM` is **parameter selection unresolved**. Explicit
unrecognized selectors such as `ML-KEM-999` create a compliance-gap finding.
This checks names in source; it does not prove that a provider maps a name to the
final standard or that a dynamic selector has the expected value.

The scanner also inventories recognizable ML-KEM decapsulation, PQC signature
verification, and FIPS encoding/decoding calls. Imports alone do not count as
validation paths. Evidence in tests is shown separately and tests are not run.
The JSON, desktop **Correctness & compliance** tab, text output, and PDF all state
that known-answer tests, negative tests, interoperability tests, ACVP/CAVP status,
and FIPS module validation remain unexecuted or unverified.

This division follows the final [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final),
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), and
[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) standards. NIST directs
implementers to the [Cryptographic Algorithm Validation Program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
for algorithm validation. Passing PQScan's static checks is therefore a review
milestone, not a NIST validation or a quantum-readiness certificate.

## Specification requirements catalog (milestone 1)

When `pqscan_analysis/` and `standards/` are present alongside `pqscan.py`, scans
add a separate `specification_review` JSON section and a short text summary.
The initial versioned catalog covers 12 selected requirements from FIPS 203,
FIPS 204, FIPS 205 and SP 800-227. It records exact section citations, conditional
applicability, expected behavior, verification methods, publication hashes and
reviewed errata dispositions. See [the catalog documentation](standards/README.md)
for scope and the JSON schemas.

```bash
python3 pqscan.py examples/pqc --format json -o reports/specification.json
```

This milestone defines the requirements and report contract. Every requirement
remains **not assessed**, applicability remains **unknown**, and exploitability
is **not assessed**. Production and nonproduction finding IDs are inventory
pointers, not validation results. Missing evidence never becomes a pass.
The catalog is partial, and the report lists excluded topics separately from
repository coverage gaps.

Older schema-1.0 reports load normally; the new section is recomputed from their
saved findings and the currently installed catalog. Imported derived claims
cannot certify themselves. Copying `pqscan.py` alone still works for inventory,
with specification review explicitly marked `catalog_unavailable`. No additional
dependencies or network access are needed. A present but invalid catalog fails
explicitly. Detailed GUI/PDF requirement views remain a later milestone. The
separate provider runner below supplies scoped execution evidence without
promoting this inventory-derived specification section.

## Python source evidence (milestone 2)

Opt in to a bounded Python source index and local source excerpts:

```bash
python3 pqscan.py examples/source_review --review-source --format json \
  -o reports/source-review.json
```

The `source_review` section contains file and excerpt hashes, symbol locations,
imports, candidate call paths, provider boundaries, dependency declarations and
selected source excerpts. It follows aliases, wrappers and re-exports across
files, while marking ambiguous bindings and dynamic dispatch unresolved. Excerpts
include source text and may contain sensitive literals; they are stored locally.
The **default scan and `--ollama` remain metadata-only**, including when
`--review-source` and `--ollama` are combined. Sending source to a model requires
the separate `--ollama-source` option below.

The collector uses the same bytes as the inventory scan and preserves its
exclusions. Default limits are 200 files / 2 MiB captured bytes, 50,000 AST nodes,
24 excerpts, 4,000 characters per excerpt, and 24,000 source characters overall.
Use `--source-max-chars 8000` to reduce the total excerpt budget. Omitted and
truncated context is explicit; other languages remain inventory-only. No target
code is run, and no requirement is promoted to verified status.

Saved source reports load without rereading repository files and are marked
`imported_unverified`. Source collection requires a live scan, so
`--from-json --review-source` is rejected. See [source-review documentation](pqscan_analysis/SOURCE_REVIEW.md)
for resolution limits, source handling, and the JSON contract.

## Requirement-grounded source review (milestone 3)

Explicitly send bounded source excerpts and the partial NIST catalog to a
downloaded local Ollama model (replace `YOUR_LOCAL_MODEL` with its installed name):

```bash
python3 pqscan.py examples/source_review --review-source \
  --ollama-source YOUR_LOCAL_MODEL --format json -o reports/source-hypotheses.json

# Review an existing snapshot without reopening the target repository
python3 pqscan.py --from-json reports/source-review.json \
  --ollama-source YOUR_LOCAL_MODEL --format json -o reports/saved-hypotheses.json
```

This sends exact code, including potentially sensitive literals and comments,
only to the explicitly selected loopback service. `--ollama` and `--ollama-source`
are mutually exclusive. Neither option downloads models or executes target code.
The desktop GUI retains its existing metadata-only model option.

The separate `source_llm_analysis` section contains **unverified hypotheses**
with requirement IDs, excerpt IDs and checked line ranges, applicability reasoning,
possible impact, assumptions and proposed validation. Hypotheses need not match
an inventory rule. Unknown IDs, omitted excerpts, out-of-range citations,
malformed output and claimed verified statuses are rejected. Citation validation
does not establish that the model's interpretation is correct. No hypothesis
changes the inventory, requirement verdicts, fusion assessment or `--fail-on` result.
An empty hypothesis list does not establish conformance.

JSON preserves the supplied evidence packet, catalog snapshot and hashes. Text
and PDF show a separate hypothesis section. The packet is capped at 24,000
serialized ASCII characters, including requirements and metadata; it can contain
less source than the collection budget. Coverage counts disclose omissions.
On model failure, JSON evidence is preserved and the command exits 2. Executable
conformance checks are available through the separate milestone 4 runner below;
requirement-level fusion and GUI integration are described below. See [source model review documentation](pqscan_analysis/LLM_REVIEW.md)
for contracts, provenance and limits.

## Isolated provider validation (milestone 4)

This optional command tests a specific provider build, independently of repository
scanning and model review. It supports **pqcrypto 0.3.4**, **ML-KEM-768** and
**ML-DSA-65**, with 25 pinned public NIST vectors and eight derived negative tests.
It does not execute application code or bind a passing provider to a repository's
deployed dependency. That distinction remains explicit in every result.

Prepare the dedicated image once (this explicit build downloads a digest-pinned
Python base and checksum-locked wheels; supports Linux arm64/amd64):

```bash
docker build -t pqscan-validation:pqcrypto-0.3.4 validation/container
```

Then run the fixed suite without network access or a repository mount:

```bash
python3 -m pqscan_analysis.validation run \
  --image pqscan-validation:pqcrypto-0.3.4 \
  -o reports/provider-validation.json

# Inspect saved evidence without execution
python3 -m pqscan_analysis.validation read reports/provider-validation.json
```

The runner never builds or pulls images automatically. It resolves the image to
an immutable ID, stages only its reviewed harness and vectors, and runs as a
non-root user with a read-only root, dropped capabilities, no network, seccomp,
and CPU/memory/process/time/output limits. There is no host-execution fallback.

Results include individual oracles and observations, requirement references,
vector revision/checksums, image ID, provider/native artifact hashes, runtime
details and the execution command. Exit codes are **0** for all selected cases
passing, **1** for test mismatches, and **2** for setup errors or inconclusive
execution. A pass is scoped to those cases, not full NIST conformance or
certification. Imported reports are labeled `imported_unverified`.

Designated `--fixture zero-secret` and `--fixture accept-all-signatures` modes
exercise known bad harness variants; their failures are not provider defects.
See [validation documentation](validation/README.md) for reproduction, exact
coverage, limitations and regression tests. The milestone 5 Requirement evidence view can import these reports.

## Library implementation analysis (milestone 4b)

The separate library CLI captures a repository without running it. The first
build adapter supports OpenSSL's native **ML-KEM-768 decapsulation** and
**ML-DSA-65 pure verification with contexts**, using the same 33 selected cases as
milestone 4 through a reviewed EVP adapter.

```bash
# Any supported-size repository: manifest and adapter detection; no execution
python3 -m pqscan_analysis.library inspect path/to/library -o reports/library-input.json

# Explicit one-time toolchain preparation (requires network)
docker build -t pqscan-library:openssl-portable-v1 validation/library-container

# OpenSSL only: capture, build in isolation, index selected C, test exact binary
python3 -m pqscan_analysis.library run repos_to_test/openssl \
  --image pqscan-library:openssl-portable-v1 --timeout 900 \
  -o reports/library-validation.json

# Read and validate evidence without executing anything
python3 -m pqscan_analysis.library read reports/library-validation.json
```

Build and test phases use separate restricted containers with no network. The
original repository is never mounted; the build receives a captured read-only
copy. Reports record file hashes (including untracked/ignored inputs), toolchain
image identity, compiler commands, generated-file hashes, native function/call
locations, selected source excerpts, artifact identity, test oracles and results.
The exact binary and manifest are saved beside the JSON in a `.artifacts` folder.

The C index uses libclang and the captured compile flags. Unsupported branches,
assembly, headers, indirect dispatch and exhausted budgets remain coverage gaps.
Passing cases do not establish whole-algorithm correctness or NIST certification.
The recorded build chain is local provenance, not independent attestation.
The milestone 5 view imports these results into the GUI, text and PDF with
scoped outcomes and provenance. Native-source LLM review remains future work. See [library validation documentation](validation/LIBRARY_REVIEW.md)
for supported revisions, mutations, limits and reproduction.

## Requirement evidence and reports (milestone 5)

The new `requirement_assessment` view reconciles inventory pointers, validated
source-model hypotheses, library/provider test reports and reviewer triage notes.
It keeps each source snapshot/artifact/backend separate, deduplicates repeated
observations, and exposes conflicting outcomes for the same case and subject.

```bash
# Attach existing test evidence to an inventory/source scan; no target execution
python3 pqscan.py path/to/repository --review-source \
  --evidence reports/library-validation.json \
  --pdf reports/combined-evidence.pdf

# Open a library/provider report directly, with no inventory scan
python3 pqscan.py --from-json reports/library-validation.json \
  --evidence reports/another-library-result.json \
  --pdf reports/implementation-evidence.pdf
```

Use **Load JSON** in the desktop app for scan, library or provider reports. The
**Requirement evidence** tab shows per-requirement status, scoped case outcomes,
source candidates, expected/observed values, provenance and coverage. Use
**Import test evidence** or **Import reviewer notes**, then **Save evidence review
as...** before exporting PDF. Attachments never run commands, rebuild code,
contact Ollama or read a repository path saved in a report.

Imported outcomes are labeled `reported_passed`, `reported_failed`,
`reported_inconclusive` or `disputed`. Requirements with evidence remain
`inconclusive`; those without evidence remain `not_assessed`. A self-consistent
JSON is not authenticated execution evidence. No passing report, model text,
reviewer disposition or edited derived status can grant verification. The ordinary
inventory verdict and `--fail-on` behavior remain separate.

See [evidence rules, reviewer-note format and reproduction](pqscan_analysis/EVIDENCE.md).

## Local Ollama review and PDF report

Set up the optional PDF dependency in the scanner's environment:

```bash
cd /Users/notsamus/Desktop/pqscan
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-pdf.txt
ollama list
```

Start Ollama (the desktop app or `ollama serve`) if it is not already running.
Choose a downloaded model from `ollama list`; PQScan does not download models.
For example, using the locally installed `gemma4:e4b`:

```bash
.venv/bin/python pqscan.py ~/path_to_repo \
  --ollama gemma4:e4b \
  --pdf reports/readiness.pdf
```

This command:

1. Scans the repository and saves `reports/readiness.json` immediately.
2. Sends a bounded selection of scan findings to the local Ollama HTTP API.
3. Validates the structured model response and adds it under `llm_analysis` in
   the JSON. The scanner assessment and findings remain unchanged.
4. Builds `reports/readiness.pdf` from the same report, with an assessment,
   model summary, grouped inventory counts, representative source locations,
   scoped test outcomes, provenance, and coverage. Complete evidence stays in JSON.

PDF export is concise by default in both the CLI and desktop app. It prints at
most eight representative findings, groups skipped paths by reason, and summarizes
requirement evidence instead of repeating every source pointer. Failed/error
counts, conflicting test scopes, and fixture identities remain visible. Test
counts include cases outside the partial requirement catalog. The PDF does not
replace the complete JSON or searchable desktop evidence views.

`--pdf` always creates a JSON sidecar, regardless of `--format`. Use `--output`
to choose a different JSON filename. Output directories are created as needed;
existing JSON or PDF files are never overwritten. If you copy `pqscan.py`
elsewhere, PDF export still needs ReportLab in the Python environment you use;
the script itself remains self-contained.

More workflows:

```bash
# Deterministic PDF and JSON, without an LLM
.venv/bin/python pqscan.py ~/path_to_repo --pdf reports/static.pdf

# Save JSON now; review it and build a PDF later without rescanning
python3 pqscan.py ~/path_to_repo --format json -o reports/scan.json
.venv/bin/python pqscan.py --from-json reports/scan.json \
  --ollama gemma4:e4b --pdf reports/reviewed.pdf

# Render a previously reviewed JSON without another model request
.venv/bin/python pqscan.py --from-json reports/reviewed.json \
  --pdf reports/reprinted.pdf

# Ollama-assisted JSON without a PDF or ReportLab dependency
python3 pqscan.py ~/path_to_repo --ollama gemma4:e4b \
  --format json -o reports/analysis.json

# Custom local port and timeout
.venv/bin/python pqscan.py ~/path_to_repo --ollama gemma4:e4b \
  --ollama-url http://127.0.0.1:11435 --ollama-timeout 300 \
  --pdf reports/readiness-custom.pdf
```

The model reviews **scan evidence**, not complete source files. Requests include
relative filenames, matched algorithm tokens, finding IDs, classifications,
summary counts, rule guidance, and coverage metadata. Full source lines, key
material, and the absolute repository root are not supplied. The client only
accepts loopback URLs, bypasses HTTP proxy settings, refuses redirects and known
cloud/remote models, and never downloads a model. Run it against a local Ollama
service you control.

The prompt includes at most 60 findings within a 12,000-character serialized
finding budget, prioritizing production usage and severity. `findings_sent` and
`findings_omitted` disclose this selection; **all** findings remain in JSON and
PDF. Large repositories may therefore receive a partial model review even when
the static scan completed. Each proposed priority must reference supplied IDs.
Responses are schema-checked, but factual correctness still needs human review.

Ollama failures, missing models, timeouts, incomplete generation, and invalid
model responses are recorded as `llm_analysis.status = "failed"`. The command
still produces a static PDF with an explicit failure notice and returns `2`.
If PDF rendering fails or ReportLab is missing, the JSON remains available. If
interrupted during model inference, an already saved JSON checkpoint records
`pending`. The default model request timeout is 180 seconds.

## What the report means

PQScan produces an evidence-based assessment, not a quantum-readiness certificate
or percentage score. Each finding includes the algorithm, rule, severity, file,
line, evidence kind, confidence, and a suggested next step. Reports include only
the matched algorithm/API token rather than copying full source lines or keys.

| Assessment | Meaning |
| --- | --- |
| `MIGRATION NEEDED` | Recognized quantum-vulnerable algorithms appear in production calls or configuration. Review whether those paths are used and plan migration. |
| `PQC EVIDENCE FOUND` | PQC identifiers appear in production calls/configuration, with no recognized quantum-vulnerable usage in the scanned scope. Verify the deployed implementation. |
| `REVIEW REQUIRED` | Evidence is insufficient, limited to imports/dependencies/tests, or scan coverage is incomplete. |
| `NO CRYPTO EVIDENCE` | The scanner found no recognized cryptography. Indirect or unsupported cryptography may still exist. |

“Production” means a path that does not look like a test, fixture, example, or
benchmark. That classification is a filename heuristic, not reachability
analysis. Tests and examples are included and labeled, but do not decide the
production assessment or trigger severity gates. When scanning an example
directory directly, its files are assessed relative to that directory.

Imports and direct dependency declarations are informational inventory. They do
not prove an algorithm is used. A `high` confidence Python finding identifies a
recognized call syntactically; it does not establish runtime reachability or
cryptographic correctness. Other languages use `medium` confidence lexical
patterns. Parse fallbacks have `low` confidence and mark coverage incomplete.

## Detection coverage

| Category | Recognized evidence |
| --- | --- |
| Quantum-vulnerable public-key crypto | Common RSA, DSA, DH, ECDH, ECDSA, X25519/X448, Ed25519/Ed448 APIs, named curves, and RSA/EC JWT algorithm selectors |
| Post-quantum evidence | ML-KEM, ML-DSA, SLH-DSA, and selected hybrid ML-KEM identifiers |
| Requires review | Earlier Kyber/Dilithium/SPHINCS+ names, selected other PQC/stateful schemes, TLS settings, and crypto dependencies |
| Symmetric/hash inventory | AES, ChaCha20, SHA-2, SHA-3, SHAKE; these alone do not establish PQC protection |

Python receives AST-based call and import analysis, including direct imported
function aliases and module aliases. Comments, docstrings, and unrelated logging
strings are not treated as Python implementation evidence.

Lexical rules cover recognizable patterns in JavaScript/TypeScript, Go, Rust,
Java/Kotlin, C/C++, C#, Swift, Ruby, PHP, shell files, and common configuration
formats. This is not a full parser, dependency resolver, or exhaustive API catalog
for those languages. Import aliases outside Python are not resolved.

Direct manifests such as `requirements.txt`, `pyproject.toml`, `package.json`,
`Cargo.toml`, `go.mod`, and `pom.xml` are inventoried. Dependency versions are not
audited. Lockfiles and transitive dependency code are not inspected.

A classical algorithm and a PQC algorithm in the same repository do not prove
secure hybrid composition. A named hybrid group is reported as PQC evidence; a
separate X25519/RSA/etc. fallback is still flagged for review. TLS 1.3 and AES-256
alone do not prove post-quantum key exchange or authentication.

## Commands

```bash
# Human-readable report
python3 pqscan.py /path/to/repo

# Machine-readable report on stdout
python3 pqscan.py /path/to/repo --format json

# Save a JSON report; an existing output file is never overwritten
python3 pqscan.py /path/to/repo --format json --output report.json

# CI: flag production findings of high severity
python3 pqscan.py /path/to/repo --fail-on high

# Include medium-severity review findings in the CI gate
python3 pqscan.py /path/to/repo --fail-on medium

# Exclude paths or shell globs; quote globs to avoid shell expansion
python3 pqscan.py /path/to/repo --exclude 'generated/*' --exclude fixtures

# Raise the default 1 MiB input-file limit
python3 pqscan.py /path/to/repo --max-file-bytes 4194304
```

Exit codes:

- `0`: report completed; no configured severity gate was triggered. **Not a
  quantum-ready verdict.** Without `--fail-on`, findings do not change this code.
- `1`: a production usage/configuration finding meets the `--fail-on` threshold.
- `2`: invalid input, read/traversal/output error, requested Ollama/PDF failure, or incomplete coverage when a
  severity gate was requested and no finding already triggered exit `1`.
- `130`: interrupted with Ctrl+C.

`--fail-on` is a severity gate, not a requirement to find PQC. An empty or
crypto-free repository can return `0`; inspect the assessment in JSON if your CI
policy requires specific evidence. Read/traversal errors always return `2`.

The JSON report has schema version `1.0`, the assessment, category/severity/context
counts, findings with `F0001`-style IDs, limitations, and coverage details. It records each skipped path
and reason, exclusions, parse warnings, and read errors. Findings are ordered
deterministically; the timestamp reflects when the scan ran.
When requested, `llm_analysis` stores the model name/digest, review status,
evidence selection counts, and validated advisory analysis. Model output never
changes CI severity decisions; a failed requested model review returns `2`.

## Scan scope and exclusions

The scanner skips common generated/dependency directories such as `.git`,
`node_modules`, `vendor`, `.venv`, `build`, `dist`, and `target`. It skips docs,
lockfiles, its own JSON reports, minified JavaScript, unsupported extensions, and binary files. It never
follows file or directory symlinks. Supported source files that are too large,
unreadable, binary, unparseable Python, or unsupported in encoding produce explicit
coverage gaps; symlinks also mark coverage incomplete. Standard exclusions and
unsupported file types remain outside the declared scan scope.

By default, text must be UTF-8; Python encoding cookies are also supported. The
scanner does not decode certificates, private keys, compiled libraries, packet
captures, or archives.

`.gitignore` is **not** interpreted: ignored first-party source can still matter
for cryptographic inventory. Instead, create `.pqscanignore` in the target root:

```text
# Lines are simple case-sensitive shell globs or relative paths.
legacy/
generated/*
*.min.js
```

A pattern without `/` matches any path component. A relative directory path also
excludes its descendants. Patterns use Python `fnmatch`: `*` can match `/`, and
there is no negation or special `**` behavior. Blank lines and lines beginning
with `#` are ignored. `--exclude` adds patterns to this file's exclusions.

## Limitations to review

The scanner cannot establish end-to-end quantum readiness. Review deployed
algorithm negotiation, authentication and certificate signatures, key storage,
fallback policy, protocol composition, and implementation correctness separately.
Custom algorithms, indirect wrappers, reflection, dynamic selectors, dependency
internals, and remote services may be missed. Aliases are not resolved across
Python scopes, reassignment, or data flow; lexical matching in other languages
can also produce false positives. No source match validates a cryptographic
module or proves FIPS conformance.

## Examples and development

```bash
python3 pqscan.py examples/classical   # MIGRATION NEEDED
python3 pqscan.py examples/pqc         # PQC EVIDENCE FOUND
python3 pqscan.py examples/mixed       # MIGRATION NEEDED, with PQC evidence
python3 pqscan.py examples/no_crypto   # NO CRYPTO EVIDENCE
python3 pqscan.py examples/declared    # Fusion: PQC capability declared
python3 -m unittest discover -s tests -v
# Include optional PDF and offscreen desktop integration tests
.venv/bin/python -m unittest discover -s tests -v
```

Examples are scan fixtures, not complete secure protocol implementations. Their
dependencies are unnecessary for scanning or running tests. Tests use temporary
repositories and check classification, source locations, aliases, mixed/hybrid
code, exclusions, coverage gaps, portability, JSON, and CI exit codes.

Add new algorithm/API patterns to `RULES` in `pqscan.py`, and add regression tests
for both detection and plausible false positives. Keep the scanner and Ollama
client free of third-party dependencies. Import PDF dependencies only when PDF
export is requested.

The earlier GUI/network/packet scanner and its capture were preserved in
[`legacy/`](legacy/NOTICE.md). The new analyzer does not use those files.

## References

Rules distinguish the finalized algorithm names in
[FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final),
[FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final), and
[FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
from earlier submission names. See the
[NIST PQC project](https://csrc.nist.gov/projects/post-quantum-cryptography)
for the evolving standardization program. The
[NIST FAQ](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs)
discusses hybrid designs and the different quantum impact on symmetric
cryptography; this scanner does not label AES-128 as quantum-broken.

The Ollama client uses the official [chat API](https://docs.ollama.com/api/chat)
and [structured JSON outputs](https://docs.ollama.com/capabilities/structured-outputs).
