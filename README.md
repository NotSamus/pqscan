# PQScan

Analyze a local repository for quantum-vulnerable cryptography and evidence of
post-quantum cryptography (PQC). Scanning runs offline with **Python 3.9+ and no
third-party dependencies**. Optionally add a **local Ollama review** and export a
**PDF backed by JSON**. PDF export uses ReportLab. The scanner never imports,
builds, or executes the target code.

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
release does not execute validation suites, observe deployed protocols, accept
reviewer attestations, or issue readiness certificates. Those require additional
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
   model-assisted action plan, full finding inventory, coverage, and references.

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
