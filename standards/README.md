# Specification catalog v1

This is a partial, versioned review catalog for milestone 1. It contains 12
requirements: four from FIPS 203, three from FIPS 204, two from FIPS 205 and three
application requirements from SP 800-227. The latter are currently scoped to
ML-KEM; they do not inventory every KEM covered by that publication.

`nist-pqc-v1.json` is the source of truth. `catalog.schema.json` describes its
format; `specification-review.schema.json` describes the new JSON report section.
Both are JSON Schema Draft 2020-12 documents. The standard-library-only loader
validates the subset of schema features these files use, then checks source IDs,
requirement IDs, dates and errata provenance. Updating a schema to use additional
features requires updating the validator and its tests.

Each requirement records its standard, section/algorithm locator, obligation,
conditional applicability, expected behavior, proposed verification methods,
review date and errata disposition. Sources include the SHA-256 of the exact
downloaded publication bytes. These hashes identify artifacts; they are not
signatures, validation certificates or proof of a trustworthy origin. No runtime
downloads occur. All paths resolve from the scanner distribution, not the scanned
repository. Keep this directory and `pqscan_analysis/` beside `pqscan.py`.

## Publication review

Reviewed against the final NIST publications and publication pages on 2026-10-20:

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), 2024-08-13.
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), 2024-08-13.
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), 2024-08-13.
- [SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final), 2025-09-18.

The FIPS 203 and FIPS 204 potential-update spreadsheets were downloaded and
reviewed, and their byte hashes are recorded in the catalog. FIPS 203's listed
corrections concern Appendix A indexing explanation and an Algorithm 15 comment;
they do not change the selected interface requirements. FIPS 204's proposed
Algorithm 3 correction changes the overlong-context result from an error to
`false`. The affected requirement explicitly records that difference. The
formatted-message clarification is recorded for internal verification. Other
arithmetic and signing-loop corrections fall outside this initial catalog.
Potential updates have not been silently applied as a new final edition.

No errata attachment was listed on the FIPS 205 or SP 800-227 publication page
when reviewed. This does not mean that those publications are error-free. Review
dates describe source inspection, not independent cryptographic approval.

## Report semantics

`specification_review` is derived anew on scan and when loading any schema-1.0
report. An old report's findings are mapped to the current installed catalog;
its original file is not modified. Catalog ID, version and SHA-256 make that
mapping explicit. Saved derived statuses, source metadata and model prose are
not trusted or imported as validation evidence.

Every listed requirement currently has `status: not_assessed`,
`applicability_status: unknown`, and `exploitability: not_assessed`. Family-level
finding IDs help locate future review work and are divided into production and
nonproduction evidence. They do not establish that a conditional requirement
applies. Generic provider functions do not establish an algorithm family.
Missing matches, unsupported algorithms, excluded paths and dynamic selection
never result in a pass or `not_applicable` status.

The report distinguishes catalog coverage from repository coverage. Counts
describe this catalog, not all NIST requirements. Excluded topics include full
arithmetic equivalence, side-channel resistance, full randomness validation,
chatroom protocol policies, other KEM families and formal CAVP/CMVP validation.

Copying `pqscan.py` alone still supports inventory scanning. Its specification
section then says `catalog_unavailable`, with no requirements and no compliance
claim. If the optional package is present but its catalog/schema is missing or
invalid, the operation fails explicitly. A damaged installation cannot silently
claim to have completed specification review.

Milestone 1 supplies JSON and a short CLI summary. Source review and executable
provider tests now have separate contracts described below. Milestone 5 adds separate GUI/PDF
requirement evidence views. This specification report contract still
allows only inventory-derived states; future evidence-bearing requirement
states require a versioned contract change.

## Updating the catalog

1. Download the authoritative publication and applicable errata; record their
   URLs, exact byte hashes and inspection dates.
2. Review applicability and permitted variants in context. Preserve distinctions
   between mandatory language, algorithm definitions, recommendations and local
   policies. Do not relabel a recommendation as a mandatory requirement.
3. Keep stable requirement IDs for the same obligation. Increment the catalog
   version for content changes; record changed meaning and affected IDs in the
   change history below. Increment schema versions for contract changes.
4. Run `python3 -m unittest discover -s tests`. Check catalog/schema agreement,
   legacy report loading, absent-package behavior and non-promotion of evidence.
5. Maintain the explicit excluded-topic list. A larger catalog is still partial
   until a reviewed completeness analysis establishes otherwise.

History: `1.0.0` (2026-10-20) introduces the initial 12 requirements; no
conformance evaluators or exploitability tests are implemented.

## Source model hypotheses (milestone 3)

`source-hypotheses.schema.json` defines bounded model proposals with requirement
IDs and source-slice line citations. `source-llm-review.schema.json` defines a
completed source model review. The evidence packet also requires semantic
validation by `pqscan_analysis.review.validate_saved_review`, which checks the
historical catalog contract and reconstructs the exact bounded packet against
the saved source bundle. JSON Schema alone cannot check these relationships.
Neither contract permits verified status or changes any requirement verdict.
See [the review documentation](../pqscan_analysis/LLM_REVIEW.md).

## Executed provider tests (milestone 4)

The separate `pqscan-validation` report uses `validation-report.schema.json`,
`validation-runtime.schema.json` and `validation-observation.schema.json`. It
records individual test outcomes against a pinned provider/image/corpus. It does
not promote the inventory-derived specification section or assess entire
requirements. Semantic validation recomputes outcomes from fixed case oracles
and checks artifact identities; imported reports remain unauthenticated.
See [validation scope and reproduction](../validation/README.md).

## Source-built library evidence (milestone 4b)

`library-report.schema.json` is the separate repository/build/test contract;
`library-build.schema.json`, `library-native.schema.json` and
`library-tests.schema.json` validate its components. Semantic validation checks
snapshot identities, cited source references, the fixed build recipe, runtime
artifact/provider identity and all case outcomes. Source links remain candidate
locations, and requirements remain `not_assessed_in_full`. The catalog and
ordinary scanner verdicts are unchanged. See
[library analysis and reproduction](../validation/LIBRARY_REVIEW.md).

## Requirement evidence reconciliation (milestone 5)

`evidence-bundle.schema.json` bounds the library/provider report attachments and
triage notes; `review-decisions.schema.json` is the standalone reviewer-note input
contract. Each attachment must pass its existing schema and semantic validator.
The derived `requirement_assessment` view is rebuilt on import and rendering;
its saved values are never trusted. Reported outcomes remain scoped to their
snapshot/artifact and imported provenance, and requirements remain inconclusive
or unassessed. Conflicting observations and reviewer notes are retained. See
[evidence rules and desktop/CLI usage](../pqscan_analysis/EVIDENCE.md).
