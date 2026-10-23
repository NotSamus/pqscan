# Python source evidence (milestone 2)

`--review-source` adds a `source_review` JSON section. This is opt-in local
evidence collection; the default scanner and `--ollama` requests still contain
only inventory metadata. No target modules are imported, built or run. Milestone 3
adds explicit `--ollama-source` review; see [LLM_REVIEW.md](LLM_REVIEW.md).

```bash
python3 pqscan.py examples/source_review --review-source --format json \
  -o reports/source-review.json
```

The example is a static fixture, not a secure chatroom. It demonstrates a renamed
entrypoint calling a wrapper through a package re-export and relative import,
then reaching an external provider. It is not executed by the scanner.

## Snapshot and graph

The source collector receives exactly the bytes read by `scan_repository` after
the existing exclusions, file-type checks, encoding checks and size limits. It
does not perform a second repository traversal or reopen source files. SHA-256
hashes identify each original file's bytes, including uncommitted changes. A
deterministic manifest hash identifies the selected files. This is a sequence of
file reads, not an atomic repository snapshot or proof of a Git commit.

Python modules at the repository root and under `src/` are indexed. Functions,
async functions, nested functions, classes, module scopes, imports and calls get
stable identifiers and source locations. Symbols and excerpts use inclusive,
one-based line ranges. Calls have one-based Unicode character columns with an
exclusive end column. Excerpt text preserves physical line endings after source
decoding; its hash is over UTF-8 encoding of that decoded text. The separate file
hash is always over original bytes, including any original BOM or encoding.

The resolver follows direct imports, aliases, package re-exports, relative
imports and simple callable assignments across files. Resolution is deliberately
flow-insensitive: multiply assigned or conditionally bound names stay unknown.
Parameters and scoped imports do not leak into other functions. Root/src module
collisions, alias cycles, wildcard imports, runtime dispatch, class descriptors,
instance methods, decorators and unavailable dependency code have explicit
boundaries or coverage notes. Local edges are static candidates only.

Every indexed call is retained, including calls without an inventory match.
Potential entrypoints are module scopes and functions without incoming resolved
edges. These are review leads, not an assertion that a framework invokes them or
that other entrypoints do not exist. Dynamic dispatch and framework registration
can hide edges. The graph does not establish execution order or dataflow.

`providers.py` identifies external `pqcrypto` and `oqs` names. The boundary says
`external_or_native_uninspected`; it does not assert that the selected provider
binary is present, correct or validated. Local source takes precedence over an
external provider name. Simple requirements-file constraints are captured as
`declared_only`, without installation or dependency resolution. Provider API
contracts, lockfile resolution and installed versions remain unverified.

## Excerpt selection and limits

Inventory findings and recognized provider calls seed excerpt selection. The
collector expands up to three caller/callee hops, then considers other potential
entrypoints. Complete function bodies include their branches and error handling
when they fit the budget. Long bodies are truncated at physical line boundaries;
omissions identify the full symbol and missing-line count. Inventory pointers can
refer to an omitted part of a truncated symbol, so consumers must check its range.

Default limits are 200 captured files, 2 MiB of captured file bytes, 50,000 AST
nodes, 24 excerpts, 4,000 characters per excerpt, and 24,000 source characters in
total. Python nesting beyond 100 AST levels is recorded as unsupported. Reduce
the excerpt budget with `--source-max-chars`; values above the default are
rejected. The Python API supports reducing other limits through `Collector`.

The report distinguishes snapshot omissions, parse failures, unsupported file
types, unresolved calls, external boundaries, unselected symbols and truncated
excerpts. Existing scanner skip/error information is copied into source coverage.
Coverage is always marked partial: a completed collection is not a complete
semantic analysis. Non-Python files and `.pyi` stubs remain inventory-only; their
file hashes and coverage boundaries are retained within the snapshot budget.

## Source handling and saved reports

Opt-in excerpts include exact source text and may contain sensitive literals or
comments. Collection stores them in local JSON. Explicit `--ollama-source`
review also sends selected excerpts to a local model. Combining `--review-source` with
`--ollama` still sends only the existing inventory payload; source is not silently
added to the model prompt. Treat excerpts as untrusted data, never instructions.

`build_source_evidence(report)` returns a validated copy of the bounded local
bundle alongside the metadata-only `build_review_evidence`. It does not
call a model or introduce requirement verdicts. Specification requirements remain
`not_assessed`, and the readiness/fusion assessment is unchanged.

The report contract is `standards/source-review.schema.json`. Loading a source
report checks hashes for internal consistency, source ranges, references, bounds
and fixed non-certification fields. It labels the origin `imported_unverified`.
It never follows the saved repository path or rereads files. Self-consistent
hashes are not authentication: a file author can replace both evidence and its
hash. `--from-json --review-source` is rejected; obtain a new snapshot by scanning
a live repository explicitly. The original saved JSON remains unchanged.

The optional package and schemas must be present for source collection and for
loading source-rich reports. A standalone copy of `pqscan.py` still supports
ordinary inventory scans and legacy reports. Detailed source views in the GUI
are deferred to the reporting milestone; text and PDF include model hypothesis
summaries, while JSON contains full source evidence.
