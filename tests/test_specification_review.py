"""Requirement provenance, unknown states, compatibility and trust boundaries."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import pqscan
from pqscan_analysis import requirements as spec


class SpecificationReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()

    def scan(self, source="", path="app.py"):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source)
        return pqscan.scan_repository(self.repo)

    def test_catalog_has_resolvable_citations_and_byte_provenance(self):
        catalog, digest = spec.load_catalog()
        self.assertEqual(digest, hashlib.sha256((spec.STANDARDS_DIR / spec.CATALOG_FILE).read_bytes()).hexdigest())
        sources = {s["id"]: s for s in catalog["sources"]}
        self.assertEqual(len(catalog["requirements"]), 12)
        self.assertEqual(set(sources), {"FIPS203", "FIPS204", "FIPS205", "SP800227"})
        for requirement in catalog["requirements"]:
            self.assertIn(requirement["source_id"], sources)
            self.assertIn("Section", requirement["locator"])
            self.assertTrue(requirement["applicability"])
            self.assertTrue(requirement["expected_behavior"])
            self.assertTrue(requirement["verification_methods"])
            self.assertTrue(requirement["errata_disposition"])
        self.assertEqual(sources["FIPS203"]["sha256"], "fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac")

    def test_errata_and_conditional_requirements_preserve_important_distinctions(self):
        catalog, _ = spec.load_catalog()
        by_id = {r["id"]: r for r in catalog["requirements"]}
        context = by_id["F204-CONTEXT"]
        self.assertIn("error to false", context["errata_disposition"])
        self.assertIn("Empty contexts are permitted", context["expected_behavior"])
        self.assertIn("prior key checks", by_id["F203-DECAPS-INPUT"]["applicability"])
        self.assertIn("each execution", by_id["F203-DECAPS-INPUT"]["expected_behavior"])
        self.assertIn("J(z || c)", by_id["F203-IMPLICIT-REJECTION"]["expected_behavior"])
        self.assertIn("designated ephemeral", by_id["SP227-EPHEMERAL"]["applicability"])

    def test_invalid_catalogs_fail_explicitly(self):
        original, _ = spec.load_catalog()
        changes = [
            lambda c: c.update(schema_version="9.0"),
            lambda c: c.update(unexpected=True),
            lambda c: c["requirements"][0].update(source_id="invented"),
            lambda c: c["requirements"][1].update(id=c["requirements"][0]["id"]),
            lambda c: c["sources"][1].update(id=c["sources"][0]["id"]),
            lambda c: c["sources"][0].update(sha256="not-a-hash"),
            lambda c: c["sources"][0]["errata"].update(sha256=None),
            lambda c: c["requirements"][0].update(locator=""),
            lambda c: c["requirements"][0].update(verification_methods=[]),
            lambda c: c["requirements"][0].update(reviewed_on="2026-02-30"),
            lambda c: c["requirements"][0].update(reviewed_on="2099-01-01"),
        ]
        for i, change in enumerate(changes):
            catalog = copy.deepcopy(original)
            change(catalog)
            with self.subTest(case=i), self.assertRaises(ValueError):
                spec.validate_catalog(catalog)

    def test_present_but_missing_catalog_does_not_silently_disable_review(self):
        with mock.patch.object(spec, "STANDARDS_DIR", self.root), self.assertRaises(FileNotFoundError):
            self.scan()

    def test_duplicate_json_keys_are_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"version":"1.0.0","version":"9.0.0"}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            spec._read_json(path)

    def test_empty_and_unsupported_scope_remain_unknown(self):
        for source in ("print('hello')", "algorithm = 'Kyber768'", "algorithm = 'ML-KEM-999'"):
            with self.subTest(source=source):
                result = self.scan(source)["specification_review"]
                self.assertEqual(result["coverage"]["catalog_coverage"], "partial")
                self.assertEqual(result["coverage"]["requirements_assessed"], 0)
                self.assertEqual(result["coverage"]["applicability_unknown"], 12)
                self.assertFalse(result["correctness_verified"])
                self.assertFalse(result["compliance_certified"])
                for entry in result["requirements"]:
                    self.assertEqual(entry["status"], "not_assessed")
                    self.assertEqual(entry["applicability_status"], "unknown")
                    self.assertEqual(entry["exploitability"], "not_assessed")

    def test_family_evidence_is_separated_from_execution_and_production(self):
        self.scan("algorithm = 'ML-KEM-768'")
        report = self.scan("algorithm = 'ML-DSA-65'", "tests/test_sign.py")
        findings = {f["finding_id"]: f for f in report["findings"]}
        for entry in report["specification_review"]["requirements"]:
            ev = entry["evidence"]
            self.assertEqual(ev["kind"], "inventory_only")
            if entry["requirement"]["algorithm"] == "ML-KEM":
                self.assertTrue(ev["production_finding_ids"])
                self.assertEqual(ev["nonproduction_finding_ids"], [])
            elif entry["requirement"]["algorithm"] == "ML-DSA":
                self.assertEqual(ev["production_finding_ids"], [])
                self.assertTrue(ev["nonproduction_finding_ids"])
            else:
                self.assertEqual(ev["production_finding_ids"] + ev["nonproduction_finding_ids"], [])
            for fid in ev["production_finding_ids"]:
                self.assertEqual(findings[fid]["context"], "production")
            for fid in ev["nonproduction_finding_ids"]:
                self.assertNotEqual(findings[fid]["context"], "production")
            self.assertEqual(entry["status"], "not_assessed")

    def test_generic_provider_call_cannot_select_ml_kem(self):
        result = self.scan("value = OQS_KEM_decaps(key, ciphertext)")["specification_review"]
        for entry in result["requirements"]:
            self.assertEqual(entry["evidence"]["production_finding_ids"], [])

    def test_coverage_gaps_remain_visible(self):
        report = self.scan("def broken(:")
        self.assertTrue(report["specification_review"]["coverage"]["repository_coverage_incomplete"])
        self.assertEqual(report["specification_review"]["coverage"]["requirements_assessed"], 0)

    def test_legacy_load_recomputes_section_without_modifying_original(self):
        report = self.scan("algorithm = 'ML-KEM-768'")
        expected = copy.deepcopy(report["specification_review"])
        del report["specification_review"]
        for finding in report["findings"]:
            del finding["finding_id"]
        path = self.root / "legacy.json"
        pqscan.save_json(report, path)
        before = path.read_bytes()
        self.assertEqual(pqscan.load_report(path)["specification_review"], expected)
        self.assertEqual(path.read_bytes(), before)

    def test_imported_claims_and_model_text_cannot_promote_results(self):
        report = self.scan("algorithm = 'ML-KEM-768'")
        expected = copy.deepcopy(report["specification_review"])
        # No schema-validity requirement is placed on untrusted derived data:
        # ignore it and regenerate it, including metadata, from saved findings.
        report["specification_review"] = {"compliance_certified": True, "status": "passed", "catalog": "fake"}
        report["llm_analysis"] = {"status": "not_requested", "claim": "all requirements pass"}
        path = self.root / "forged.json"
        pqscan.save_json(report, path)
        self.assertEqual(pqscan.load_report(path)["specification_review"], expected)
        self.assertEqual(pqscan.specification_review(report), expected)
        self.assertIn("0 assessed", pqscan.render_text(report))
        self.assertNotIn("fake", pqscan.render_text(report))

    def test_report_contract_rejects_premature_verification(self):
        original = self.scan()["specification_review"]
        for change in (
            lambda r: r.update(correctness_verified=True),
            lambda r: r.update(compliance_certified=True),
            lambda r: r["requirements"][0].update(status="supported"),
            lambda r: r["requirements"][0].update(applicability_status="not_applicable"),
            lambda r: r["coverage"].update(requirements_assessed=True),
        ):
            result = copy.deepcopy(original)
            change(result)
            with self.assertRaises(ValueError):
                spec._validate_contract(result, "specification-review.schema.json")

    def test_report_build_is_deterministic_and_does_not_mutate_input(self):
        report = self.scan("algorithm = 'SLH-DSA-SHAKE-128s'")
        before = copy.deepcopy(report)
        first = pqscan.specification_review(report)
        self.assertEqual(first, pqscan.specification_review(report))
        self.assertEqual(report, before)
        first["sources"][0]["title"] = "changed"
        self.assertEqual(report, before)

    def test_single_file_portability_and_no_target_package_import(self):
        script = self.root / "pqscan.py"
        shutil.copy2(pqscan.__file__, script)
        poison = self.repo / "pqscan_analysis"
        poison.mkdir()
        marker = self.root / "executed"
        (poison / "__init__.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
        (poison / "requirements.py").write_text("raise RuntimeError('target imported')\n")
        env = dict(os.environ, PYTHONPATH=str(self.repo))
        run = subprocess.run([sys.executable, "-S", str(script), str(self.repo), "--format", "json"],
                             cwd=self.repo, env=env, text=True, capture_output=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)["specification_review"]
        self.assertEqual(result["status"], "catalog_unavailable")
        self.assertEqual(result["requirements"], [])
        self.assertFalse(result["compliance_certified"])
        self.assertFalse(marker.exists())
        spec._validate_contract(result, "specification-review.schema.json")

    @unittest.skipUnless(importlib.util.find_spec("jsonschema"), "optional independent JSON Schema validator not installed")
    def test_contracts_with_independent_json_schema_validator(self):
        import jsonschema
        catalog, _ = spec.load_catalog()
        for value, filename in ((catalog, "catalog.schema.json"), (self.scan()["specification_review"], "specification-review.schema.json")):
            schema = json.loads((spec.STANDARDS_DIR / filename).read_text())
            jsonschema.Draft202012Validator.check_schema(schema)
            jsonschema.Draft202012Validator(schema).validate(value)


if __name__ == "__main__":
    unittest.main()
