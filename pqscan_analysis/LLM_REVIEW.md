# Requirement-grounded source review (milestone 3)

`--ollama-source MODEL` opts in to sending source excerpts to a downloaded local
Ollama model. Use it with `--review-source` for a fresh scan or with `--from-json`
for an existing source snapshot. Loading or rendering a report alone never sends
anything. The baseline `--ollama` reviewer remains metadata-only, even when a
source bundle exists. The two model options are mutually exclusive; separate
runs can retain both sections in the same report.

```bash
python3 pqscan.py examples/source_review --review-source \
  --ollama-source YOUR_LOCAL_MODEL --format json -o reports/hypotheses.json
python3 pqscan.py --from-json reports/hypotheses.json --pdf reports/hypotheses.pdf
```

Use an installed model name from `ollama list`. The example wrapper is a static
fixture, not a secure application or a known faulty implementation. No target
modules are imported, built or run. No model tools are supplied. Models are never
downloaded automatically. Loopback-only URLs, proxy bypass, redirect rejection
and installed-model checks are shared with the baseline reviewer.

## Evidence and source handling

Excerpts contain exact decoded code, including potentially sensitive comments,
strings and credentials. Explicit source review sends that content to the local
service; server storage and logging are controlled by the service operator.
The system prompt treats repository content as untrusted data. This reduces
instruction confusion but is not a guarantee against prompt injection or model
hallucination. Model prose is advisory and has no execution or verdict authority.

`build_requirement_evidence` validates the source bundle, includes all 12 controls
in the current partial catalog, then packs whole available excerpts in source
selection order. It includes applicability, source publication hashes, section
locators and reviewed errata dispositions. Including the small complete catalog
allows investigation beyond original inventory hits. There is no embedding-based
retrieval or fine-tuned model in this milestone. Unsupported requirements remain
outside the review scope.

The exact canonical JSON packet is limited to 24,000 ASCII characters (Unicode
is escaped). Requirements and metadata count toward this limit. Oversized
excerpts are omitted whole, not silently clipped. Up to 32 calls located inside
supplied excerpts and 16 dependency declarations follow the excerpts if space
permits. Counts disclose packet omissions, source collection truncation,
unresolved calls, external boundaries, scanner warnings and source coverage gaps.
Detailed source omissions remain in `source_review`. Calls can reference symbols
outside the supplied snippets; these are unresolved context for the reviewer,
not permission to cite unseen code. Provider contracts and binaries remain
uninspected. This is not dataflow or reachability verification.

The request uses temperature 0, a requested 32,768-token context and a 4,096-token
output budget. Server/model support and practical memory use vary. The client
rejects incomplete generations and locally validates every response; it does not
measure model quality or independently prove that a server honored its requested
context. A packet without any source excerpts fails before contacting Ollama.

## Hypothesis contract

`standards/source-hypotheses.schema.json` describes the model output. At most
eight hypotheses are accepted, each with:

- `status: unverified_hypothesis` and `exploitability: not_assessed`;
- supplied requirement IDs and supplied excerpt IDs with inclusive physical line ranges;
- observed behavior, applicability reasoning and expected behavior;
- possible impact, explicit assumptions and a falsifiable validation plan.

There is no requirement for an inventory finding ID. A model may propose a new
candidate in a wrapper or entrypoint that had no regex match. File paths and file
hashes are resolved through the supplied excerpt, rather than invented by the
model. Unknown IDs, ranges outside the exact supplied snippet, extra fields,
wrong types, oversized output, duplicate JSON keys and verification claims in
status fields are rejected. One invalid hypothesis rejects the entire response;
there is no silent filtering or automatic repair. Free-form prose cannot be
mechanically checked for truth or correct interpretation of a citation.

The prompt specifically distinguishes ML-KEM implicit rejection from malformed
input lengths, and wrapper behavior from provider checks. These instructions
help guide review but do not validate a cryptographic implementation. Missing
checks in an excerpt may be implemented in the provider or omitted context.
Validation plans are suggestions only; the separate milestone 4 runner executes only fixed provider checks, never
model-generated validation plans.

## Persistence and reporting

`source_llm_analysis` is independent of `llm_analysis`, the static findings and
`specification_review`. It never raises verification, changes readiness or adds
CI severity findings. All specification requirements remain `not_assessed`.
`--fail-on` continues to evaluate static production findings; a requested model
review failure returns 2. No hypotheses is an inconclusive result.

Completed reviews use `standards/source-llm-review.schema.json`. The report embeds
the exact evidence packet, its SHA-256, the original catalog file hash, historical
catalog content, model name/digest, endpoint, timestamp and fixed non-verification
fields. The response schema checks shape; `validate_saved_review` also rebuilds
the packet deterministically against the saved source and validates the historical
catalog, hashes and references. Catalog updates therefore do not silently change
previously supplied requirements. The static specification section independently
uses the scanner's current catalog.

Saved evidence and model output are marked `imported_unverified` on load. Original
packet provenance is retained as historical metadata, not a claim that the current
target files still match. A complete replacement of evidence and hashes cannot be
authenticated; these hashes detect inconsistency, not forgery. Loading never opens
the saved target path. A fresh model review of imported evidence remains explicitly
based on an imported source snapshot.

When a JSON output is selected, the scanner checkpoints static and source evidence
before inference, then atomically replaces its own checkpoint with the completed
or failed result. Timeouts, unavailable models, incomplete generations and invalid
citations retain the scan and record a failed review. A crash can leave `pending`.
Without a JSON output path there is no durable checkpoint. Source hypothesis
summaries and citations are included in text and PDF; full excerpts stay in JSON.
The desktop GUI source-review controls and richer evidence fusion remain milestone 5.

## Validation

`tests/test_source_llm_review.py` exercises explicit source consent, unchanged
metadata prompts and verdicts, hypotheses beyond inventory hits, fabricated IDs,
truncated/omitted code, prompt injection text, provider boundaries, saved evidence
tampering, historical snapshot reloads without target reads, model failures and
checkpoint persistence. It uses a mocked transport to test behavior deterministically;
these tests do not establish actual model reasoning accuracy.
