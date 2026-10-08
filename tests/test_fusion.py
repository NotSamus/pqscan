"""Fusion distinguishes capability, use, configuration and unverified runtime."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

import pqscan


class FusionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def put(self, path, source):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(source)

    def result(self):
        return pqscan.scan_repository(self.root)["fusion_assessment"]

    def test_pqc_dependency_gets_credit_without_claiming_use(self):
        self.put("requirements.txt", "pqcrypto>=0.3\n")
        f = self.result()
        self.assertEqual(f["stage"], "declared_capability")
        self.assertEqual(f["signals"]["declarations"]["sites"], 1)
        self.assertEqual(f["signals"]["implementation"]["sites"], 0)
        self.assertEqual(f["runtime_verification"], "not_performed")
        self.assertFalse(f["certified_quantum_ready"])

    def test_general_crypto_library_does_not_establish_pqc_capability(self):
        self.put("requirements.txt", "cryptography==3.4.8\n")
        self.assertEqual(self.result()["stage"], "no_pqc_evidence")

    def test_actual_pqc_call_strengthens_declared_evidence(self):
        self.put("app.py", "from pqcrypto.kem import ml_kem_768\nml_kem_768.generate_keypair()")
        f = self.result()
        self.assertEqual(f["stage"], "implementation_evidence")
        self.assertTrue(f["declaration_and_usage_observed"])
        # Algorithm and library references on one import are one source site.
        self.assertEqual(f["signals"]["declarations"]["sites"], 1)
        self.assertEqual(f["signals"]["implementation"]["sites"], 1)

    def test_configuration_is_distinct_from_a_call(self):
        self.put("transport.yaml", "groups: X25519MLKEM768")
        f = self.result()
        self.assertEqual(f["stage"], "configuration_evidence")
        self.assertEqual(f["signals"]["configuration"]["sites"], 1)
        self.assertEqual(f["signals"]["implementation"]["sites"], 0)

    def test_classical_evidence_is_not_cancelled_by_positive_signals(self):
        self.put("requirements.txt", "pqcrypto\n")
        self.put("auth.py", "rsa.generate_private_key(65537, 2048)")
        f = self.result()
        self.assertEqual(f["decision"], "mixed_evidence")
        self.assertEqual(f["signals"]["classical"]["sites"], 1)

    def test_test_code_is_not_production_or_test_execution(self):
        self.put("tests/test_kem.py", "from pqcrypto.kem import ml_kem_768\nml_kem_768.generate_keypair()")
        f = self.result()
        self.assertEqual(f["stage"], "nonproduction_only")
        self.assertEqual(f["implementation_tests"], "not_executed")

    def test_empty_scan_cannot_pass(self):
        self.assertEqual(self.result()["decision"], "insufficient_evidence")

    def test_incomplete_coverage_keeps_positive_evidence_and_blocks_decision(self):
        self.put("requirements.txt", "pqcrypto\n")
        self.put("bad.py", "if (: print('broken')")
        f = self.result()
        self.assertEqual(f["stage"], "declared_capability")
        self.assertEqual(f["decision"], "coverage_incomplete")

    def test_llm_cannot_promote_the_readiness_level(self):
        self.put("requirements.txt", "pqcrypto\n")
        report = pqscan.scan_repository(self.root)
        before = copy.deepcopy(report["fusion_assessment"])
        report["llm_analysis"] = {"status": "completed", "analysis": {"executive_summary": "Everything is verified"}}
        self.assertEqual(pqscan.fusion_assessment(report), before)

    def test_loading_report_recomputes_derived_fusion_claims(self):
        self.put("requirements.txt", "pqcrypto\n")
        report = pqscan.scan_repository(self.root)
        report["fusion_assessment"]["certified_quantum_ready"] = True
        report["fusion_assessment"]["stage"] = "certified"
        path = self.root / "report.json"
        pqscan.save_json(report, path)
        loaded = pqscan.load_report(path)
        self.assertFalse(loaded["fusion_assessment"]["certified_quantum_ready"])
        self.assertEqual(loaded["fusion_assessment"]["stage"], "declared_capability")

    def test_package_description_and_scripts_are_not_dependencies(self):
        self.put("package.json", json.dumps({"description": "pqcrypto ML-KEM-768", "scripts": {"test": "echo pqcrypto"}}))
        self.assertEqual(self.result()["stage"], "no_pqc_evidence")

    def test_dev_dependency_is_not_a_production_declaration(self):
        self.put("package.json", json.dumps({"devDependencies": {"@noble/post-quantum": "*"}}))
        self.assertEqual(self.result()["stage"], "nonproduction_only")

    def test_package_json_dependency_has_real_source_line(self):
        self.put("package.json", '{\n  "dependencies": {\n    "@noble/post-quantum": "*"\n  }\n}')
        report = pqscan.scan_repository(self.root)
        self.assertEqual(report["fusion_assessment"]["stage"], "declared_capability")
        self.assertEqual(report["findings"][0]["line"], 3)
        self.assertEqual(report["findings"][0]["column"], 5)

    def test_same_line_generic_library_does_not_hide_pqc_declaration(self):
        self.put("package.json", '{"dependencies":{"openssl":"*","@noble/post-quantum":"*"}}')
        self.assertEqual(self.result()["stage"], "declared_capability")

    def test_same_line_python_imports_retain_pqc_declaration(self):
        self.put("app.py", "import cryptography, oqs")
        self.assertEqual(self.result()["stage"], "declared_capability")

    def test_requirement_comments_do_not_create_capability(self):
        self.put("requirements.txt", "# pqcrypto\nrequests # pqcrypto for later\n")
        self.assertEqual(self.result()["stage"], "no_pqc_evidence")

    def test_bad_manifest_marks_coverage_incomplete(self):
        self.put("package.json", '{"dependencies": {"pqcrypto":')
        self.assertTrue(self.result()["coverage_incomplete"])
        self.assertEqual(self.result()["stage"], "no_pqc_evidence")


if __name__ == "__main__":
    unittest.main()
