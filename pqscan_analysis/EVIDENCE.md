# Requirement evidence and reports — milestone 5

`pqscan_analysis.evidence` reconciles existing evidence into a separate
`requirement_assessment` view. It runs no target code, Docker commands or model
requests. The scanner's adoption assessment, original specification inventory and
CI severity gates retain their existing meaning.

## Use the CLI

```bash
# Scan and optionally collect Python source, attaching existing test reports.
python3 pqscan.py path/to/repository --review-source \
  --evidence reports/library-validation.json \
  --evidence reports/provider-validation.json \
  --pdf reports/combined-evidence.pdf

# Read an existing library/provider report directly: inventory is NOT run.
python3 pqscan.py --from-json reports/library-validation.json \
  --pdf reports/implementation-evidence.pdf

# Add another report to a previously saved review.
python3 pqscan.py --from-json reports/combined-evidence.json \
  --evidence reports/second-build.json --format json \
  -o reports/combined-evidence-next.json
```

All output files must be new. PDF export keeps a JSON sidecar containing the
original attachments and their hashes/metadata. `--evidence` accepts up to eight
library/provider reports; each input is capped at 16 MiB and the whole saved
report at 64 MiB. Unknown types, invalid schemas, inconsistent oracles, modified
build settings and mismatched runner/catalog revisions fail explicitly. Retain
the matching scanner revision for historical evidence.

The optional package remains separate: copying only `pqscan.py` preserves the
portable inventory CLI. Importing execution evidence requires this package and
`standards/`. A supplied report path is read as data; repository paths, container
commands, compiler commands, model proposals and reproduction recipes inside it
are never followed or executed by import, display or export.

## Desktop workflow

1. **Load JSON** accepts ordinary scan reports and the library/provider runner
   reports directly. A direct execution report is labeled as an evidence view;
   it does not pretend an inventory scan took place.
2. Open **Requirement evidence**. Select a requirement to inspect source
   candidates, observed and expected results, oracles, hypothesis assumptions,
   proposed reproductions, reviewer notes and coverage.
3. **Import test evidence** attaches existing JSON results. **Import reviewer
   notes** attaches the structured triage notes below. An invalid import leaves
   the current review unchanged.
4. **Save evidence review as...** writes a new combined JSON. Until saving,
   PDF export is disabled to prevent exporting an old file without the new
   attachments. The original input reports remain unchanged.
5. **Export concise PDF** renders the saved review without scanning, executing
   tests or contacting a model. It summarizes all case outcomes by subject,
   requirement-level test scopes, conflicts, and provenance; at most six adverse
   observations include expected/observed excerpts. The JSON carries every exact
   oracle, observation, source/compiler record and reviewer note. Inventory
   examples and skipped-path summaries are bounded so large repositories do not
   produce thousands of printed pages.

## Evidence rules

| Evidence | Treatment |
| --- | --- |
| Inventory finding | Candidate location, mapped by algorithm family; applicability unknown |
| Validated source-model hypothesis | Unverified claim with checked citations, assumptions and proposed falsification |
| Imported selected tests | Reported outcomes for their recorded subject/cases; not authenticated execution |
| Conflicting pass/fail observations for the same subject and case | `disputed`; both observations remain visible |
| Test setup/operation error | `reported_inconclusive`, distinct from a failed oracle comparison |
| Reviewer disposition | Unverified triage note; cannot erase a case, verify a requirement or certify a build |
| Missing evidence | `not_assessed`; never a pass |

A test scope is identified by source snapshot (where available), artifact/runtime,
backend/build profile, image, catalog, harness/vector identities and designated
mutation/fixture. Results for a different binary or source are separate scopes.
Passing cases never cancel a failed case. A library's recorded source-to-artifact
chain remains visible, but it is **not** an automatic binding to an attached
application scan or deployed dependency. Matching names/paths are insufficient.

Exact repeated observations collapse into one observation with all report
provenance retained. Different observations remain separate. Identical source
locations and normalized observed behavior group model candidates without
counting repetitions as corroboration; alternate assumptions/wording are retained.
This is exact candidate grouping, not semantic root-cause equivalence. Historical source-model
packets are retained under their original catalog; they are listed as unmerged
evidence instead of being silently remapped to current requirements.

The requirement-level status is `inconclusive` when scoped evidence exists and
`not_assessed` otherwise. Test scopes separately display `reported_passed`,
`reported_failed`, `reported_inconclusive` or `disputed`. This first fusion profile
does not issue `supported`, `violated` or `not_applicable` requirement verdicts:
imported JSON cannot authenticate its own execution or applicability. All
requirements remain unverified in full; exploitability remains `not_assessed`.
A model's possible-impact prose is displayed as a claim, not demonstrated impact.

`requirement_assessment` is a disposable derived cache. Load, text/PDF rendering
and GUI display recompute it from the validated input bundle and source evidence.
Editing its statuses or certification flags has no effect. Input hashes detect
inconsistency, not fabrication by someone replacing an entire self-consistent
report. Signed receipts, independent attestation and reviewer authentication are
outside this milestone.

## Reviewer notes

Use `--review-decisions notes.json` or the desktop import button. Copy a requirement
ID and evidence ID from the combined JSON's `requirement_assessment` (or its text
view). Notes must refer to existing evidence for that exact requirement.

```json
{
  "schema_version": "1.0",
  "decisions": [
    {
      "requirement_id": "F204-VERIFY",
      "evidence_ids": ["T_REPLACE_WITH_AN_ACTUAL_EVIDENCE_ID"],
      "reviewer": "Reviewer name",
      "created_at": "2026-10-21T12:00:00-06:00",
      "disposition": "needs_reproduction",
      "note": "Confirm the selected artifact and the API path before assessing impact."
    }
  ]
}
```

Replace the placeholder before import. Accepted dispositions are
`needs_reproduction`, `dismissed` and `disputed`; no disposition grants verification.
Notes are bounded to 64 entries, 16 evidence references per entry and 2,000
characters of prose. Conflicting dispositions for the same evidence remain
visible. Reviewer names/timestamps are recorded claims, not authenticated identity.
Evidence IDs depend on the subject, oracle and observation; after changing an
attachment, choose references from the newly generated view.

Schemas: `standards/evidence-bundle.schema.json` and
`standards/review-decisions.schema.json`. Existing source-hypothesis and execution
report schemas and semantic validators remain authoritative for the attachments.

## Scope and checks

The requirement catalog remains partial (12 controls). Native-library source
locations are candidates, indirect dispatch stays unresolved, and passing
selected tests does not establish arithmetic equivalence, constant-time behavior,
application security or NIST/ACVP/FIPS certification. The current native index is
not automatically sent to an LLM. Running new tests remains an explicit action
through the existing isolated library/provider CLI.

Run `python3 -m unittest discover -s tests`. Milestone 5 regressions cover subject
separation, contradictions, repeated evidence, execution errors, model/triage
non-promotion, forged references, tampered derived fields, read-only transactional
imports, CLI round trips and desktop save/export behavior. The sample
`output/pdf/milestone-5-evidence-review.pdf` compares the recorded healthy OpenSSL
build with the designated signature-verification mutant; it does not claim a
vulnerability in the original OpenSSL checkout.
