# PQScan

Analyze a local repository for quantum-vulnerable cryptography and evidence of
post-quantum cryptography (PQC). Runs offline with **Python 3.9+ and no third-party
dependencies**. The scanner never imports, builds, or executes the target code.

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
- `2`: invalid input, read/traversal/output error, or incomplete coverage when a
  severity gate was requested and no finding already triggered exit `1`.
- `130`: interrupted with Ctrl+C.

`--fail-on` is a severity gate, not a requirement to find PQC. An empty or
crypto-free repository can return `0`; inspect the assessment in JSON if your CI
policy requires specific evidence. Read/traversal errors always return `2`.

The JSON report has schema version `1.0`, the assessment, category/severity/context
counts, findings, limitations, and coverage details. It records each skipped path
and reason, exclusions, parse warnings, and read errors. Findings are ordered
deterministically; the timestamp reflects when the scan ran.

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
python3 -m unittest discover -s tests -v
```

Examples are scan fixtures, not complete secure protocol implementations. Their
dependencies are unnecessary for scanning or running tests. Tests use temporary
repositories and check classification, source locations, aliases, mixed/hybrid
code, exclusions, coverage gaps, portability, JSON, and CI exit codes.

Add new algorithm/API patterns to `RULES` in `pqscan.py`, and add regression tests
for both detection and plausible false positives. Keep the standalone file free
of third-party dependencies.

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
