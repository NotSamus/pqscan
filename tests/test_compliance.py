"""NIST parameter and validation evidence stays separate from certification."""

from pathlib import Path
import tempfile
import unittest

import pqscan


class ComplianceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def scan(self, source, path="app.py"):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
        return pqscan.scan_repository(self.root)["correctness_compliance"]

    def test_all_final_parameter_families_are_reported(self):
        result = self.scan(
            "kem_algorithm = 'ML-KEM-768'\n"
            "signature_algorithm = 'ML-DSA-65'\n"
            "other_signature = 'SLH-DSA-SHAKE-256f'\n"
        )
        self.assertEqual(result["status"], "static_evidence_only")
        self.assertEqual(result["algorithms"]["ML-KEM"]["observed_parameter_sets"], ["ML-KEM-768"])
        self.assertEqual(result["algorithms"]["ML-DSA"]["observed_parameter_sets"], ["ML-DSA-65"])
        self.assertEqual(result["algorithms"]["SLH-DSA"]["observed_parameter_sets"], ["SLH-DSA-SHAKE-256f"])

    def test_parameter_table_contains_every_fips_205_set(self):
        result = self.scan("print('no crypto')")
        approved = result["algorithms"]["SLH-DSA"]["approved_parameter_sets"]
        self.assertEqual(len(approved), 12)
        self.assertIn("SLH-DSA-SHA2-128s", approved)
        self.assertIn("SLH-DSA-SHAKE-256f", approved)

    def test_bare_algorithm_requires_parameter_review(self):
        result = self.scan("kem_algorithm = 'ML-KEM'")
        self.assertEqual(result["status"], "parameter_review_required")
        self.assertEqual(result["algorithms"]["ML-KEM"]["status"], "parameter_selection_unresolved")

    def test_hybrid_identifier_contributes_its_explicit_ml_kem_parameter(self):
        result = self.scan("group = 'X25519MLKEM768'")
        self.assertEqual(result["algorithms"]["ML-KEM"]["observed_parameter_sets"], ["ML-KEM-768"])
        self.assertEqual(result["status"], "static_evidence_only")

    def test_hybrid_name_without_parameter_remains_unresolved(self):
        result = self.scan("group = 'XWing'")
        self.assertEqual(result["algorithms"]["ML-KEM"]["status"], "parameter_selection_unresolved")

    def test_unrecognized_parameter_is_an_explicit_issue(self):
        result = self.scan("kem_algorithm = 'ML-KEM-999'")
        self.assertEqual(result["status"], "parameter_issue_detected")
        self.assertTrue(result["unrecognized_parameter_findings"])

    def test_decapsulation_call_is_supporting_evidence_not_validation(self):
        result = self.scan(
            "from pqcrypto.kem.ml_kem_768 import decrypt\n"
            "shared_secret = decrypt(secret_key, ciphertext)\n"
        )
        control = result["controls"]["ml_kem_decapsulation"]
        self.assertEqual(control["status"], "source_evidence_observed")
        self.assertTrue(control["finding_ids"])
        self.assertFalse(result["correctness_verified"])
        self.assertEqual(result["validation"]["negative_tests"], "not_executed")

    def test_signature_verify_call_is_recognized(self):
        result = self.scan(
            "from pqcrypto.sign.ml_dsa_65 import verify\n"
            "valid = verify(public_key, message, signature)\n"
        )
        self.assertEqual(result["controls"]["signature_verification"]["status"], "source_evidence_observed")
        self.assertFalse(result["compliance_certified"])

    def test_import_alone_is_not_a_validation_path(self):
        result = self.scan("from pqcrypto.kem.ml_kem_768 import decrypt\n")
        self.assertEqual(result["controls"]["ml_kem_decapsulation"]["status"], "not_observed")

    def test_encoding_primitive_is_reported_without_claiming_correctness(self):
        result = self.scan("ML_KEM_768()\nvalue = ByteDecode(data)\n")
        self.assertEqual(result["controls"]["encoding_decoding"]["status"], "source_evidence_observed")
        self.assertFalse(result["correctness_verified"])

    def test_test_validation_is_nonproduction_and_not_executed(self):
        result = self.scan(
            "from pqcrypto.sign.slh_dsa_sha2_128s import verify\n"
            "assert verify(public_key, message, signature)\n",
            "tests/test_signature.py",
        )
        control = result["controls"]["signature_verification"]
        self.assertEqual(control["status"], "not_observed")
        self.assertTrue(control["nonproduction_finding_ids"])
        self.assertEqual(result["validation"]["known_answer_tests"], "not_executed")

    def test_empty_repository_is_not_a_compliance_pass(self):
        result = pqscan.scan_repository(self.root)["correctness_compliance"]
        self.assertEqual(result["status"], "no_nist_pqc_scope")
        self.assertFalse(result["compliance_certified"])


if __name__ == "__main__":
    unittest.main()
