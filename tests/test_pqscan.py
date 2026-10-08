"""Behavioral tests. Fixture code is analyzed as text and never executed."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import pqscan


SCRIPT = Path(pqscan.__file__).resolve()


class DetectionTests(unittest.TestCase):
    def active_ids(self, source, filename="app.py"):
        found, warnings = pqscan.analyze_source(source, filename)
        self.assertFalse(warnings)
        return {f.rule_id for f in found if pqscan.is_active(f)}

    def test_python_rsa_alias_and_line(self):
        found, warnings = pqscan.analyze_source(
            "from cryptography.hazmat.primitives.asymmetric import rsa as public_key\n"
            "key = public_key.generate_private_key(65537, 3072)\n", "auth.py")
        self.assertFalse(warnings)
        usages = [f for f in found if pqscan.is_active(f)]
        self.assertEqual([(f.rule_id, f.line, f.column) for f in usages], [("Q001", 2, 7)])
        self.assertEqual(pqscan.assessment(found, False)["status"], "migration_needed")

    def test_python_direct_import_alias(self):
        ids = self.active_ids("from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as gen\nkey = gen(65537, 2048)\n")
        self.assertEqual(ids, {"Q001"})

    def test_python_multiline_call(self):
        ids = self.active_ids("import oqs\nkem = oqs.KeyEncapsulation(\n    'ML-KEM-768'\n)\n")
        self.assertEqual(ids, {"P001"})

    def test_unused_pqc_import_is_not_usage(self):
        found, _ = pqscan.analyze_source("from pqcrypto.kem import ml_kem_768\n", "app.py")
        self.assertTrue(found)
        self.assertEqual(pqscan.assessment(found, False)["status"], "review_required")
        self.assertTrue(all(f.severity == "info" for f in found))

    def test_unused_classical_import_does_not_require_migration(self):
        found, _ = pqscan.analyze_source("from cryptography.hazmat.primitives.asymmetric import rsa\n", "app.py")
        self.assertEqual(pqscan.assessment(found, False)["production_quantum_vulnerable"], 0)

    def test_comments_docstrings_and_prints_are_not_crypto(self):
        source = '\"\"\"Use RSA or ML-KEM-768.\"\"\"\n# rsa.generate_private_key()\nprint("ML-KEM-768")\nmessage = "RSA"\n'
        found, _ = pqscan.analyze_source(source, "app.py")
        self.assertEqual(found, [])

    def test_python_config_and_jwt(self):
        self.assertEqual(self.active_ids('import jwt\ntoken = jwt.encode(payload, key, algorithm="RS256")\n'), {"Q001"})
        self.assertEqual(self.active_ids('import jwt\npayload = jwt.decode(token, key, algorithms=["RS256"])\n'), {"Q001"})
        self.assertEqual(self.active_ids('options = {"algorithm": "ES256"}\n'), {"Q002"})
        self.assertEqual(self.active_ids('kem_algorithm = "ML-KEM-768"\n'), {"P001"})

    def test_standard_pqc_families(self):
        cases = [("ml_kem_768", "kem", "P001"), ("ml_dsa_65", "sign", "P002"), ("slh_dsa_sha2_128s", "sign", "P003")]
        for name, module, rule in cases:
            with self.subTest(name=name):
                ids = self.active_ids(f"from pqcrypto.{module} import {name} as scheme\npk, sk = scheme.generate_keypair()\n")
                self.assertEqual(ids, {rule})

    def test_earlier_pqc_names_require_review(self):
        found, _ = pqscan.analyze_source('import oqs\nkem = oqs.KeyEncapsulation("Kyber768")\n', "app.py")
        self.assertEqual(pqscan.assessment(found, False)["status"], "review_required")
        self.assertTrue(any(f.rule_id == "R001" for f in found))

    def test_symmetric_and_hashes_do_not_establish_pqc(self):
        found, _ = pqscan.analyze_source("from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nimport hashlib\ncipher = AESGCM(key)\nhashlib.sha256(data)\n", "app.py")
        self.assertEqual(pqscan.assessment(found, False)["status"], "review_required")
        self.assertFalse(any(f.category in {"pqc", "quantum_vulnerable"} for f in found))

    def test_aes128_is_not_reported_quantum_broken(self):
        self.assertEqual(self.active_ids('cipher = "AES-128-GCM"\n'), {"S001"})

    def test_tls13_does_not_establish_pqc(self):
        ids = self.active_ids('minVersion: "TLSv1.3"\nciphers: "TLS_AES_256_GCM_SHA384"\n', "tls.yaml")
        self.assertIn("R003", ids)
        self.assertNotIn("P001", ids)

    def test_hybrid_identifier_does_not_trigger_classical_component(self):
        ids = self.active_ids("var groups = []tls.CurveID{tls.X25519MLKEM768}\n", "tls.go")
        self.assertEqual(ids, {"P004"})

    def test_hybrid_with_classical_fallback_flags_both(self):
        found, _ = pqscan.analyze_source("var groups = []tls.CurveID{tls.X25519MLKEM768, tls.X25519}\n", "tls.go")
        verdict = pqscan.assessment(found, False)
        self.assertEqual(verdict["status"], "migration_needed")
        self.assertEqual(verdict["production_pqc_evidence"], 1)
        self.assertEqual(next(f.evidence for f in found if f.rule_id == "Q002"), "X25519")

    def test_tests_and_examples_do_not_drive_production_verdict(self):
        for filename in ("tests/auth.py", "examples/auth.py", "auth_test.go", "auth.test.ts", "AuthTest.java"):
            with self.subTest(filename=filename):
                found, _ = pqscan.analyze_source("rsa.generate_private_key(65537, 2048)\n", filename)
                self.assertTrue(found)
                self.assertEqual(pqscan.assessment(found, False)["production_quantum_vulnerable"], 0)

    def test_multilanguage_detection(self):
        cases = [
            ("auth.js", "const pair = crypto.generateKeyPairSync('rsa-pss', {modulusLength: 4096});", "Q001"),
            ("auth.ts", "const pair = crypto.generateKeyPairSync('ec', {namedCurve: 'P-256'});", "Q002"),
            ("auth.java", 'Signature signature = Signature.getInstance("SHA256withRSA");', "Q001"),
            ("auth.java", 'KeyPairGenerator k = KeyPairGenerator.getInstance("DH");', "Q003"),
            ("auth.cs", "using var key = RSA.Create(3072);", "Q001"),
            ("auth.c", "EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, \"RSA\", 3072);", "Q001"),
            ("auth.c", "EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);", "Q001"),
            ("auth.cpp", "auto *k = OQS_KEM_new(\"ML-KEM-768\");", "P001"),
            ("auth.c", "OQS_KEM *k = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);", "P001"),
            ("auth.rs", "let secret = x25519_dalek::StaticSecret::random_from_rng(rng);", "Q002"),
            ("auth.go", "key, err := rsa.GenerateKey(rand.Reader, 3072)", "Q001"),
            ("auth.go", "key, err := mlkem.GenerateKey768()", "P001"),
        ]
        for filename, code, expected in cases:
            with self.subTest(filename=filename, code=code):
                self.assertIn(expected, self.active_ids(code, filename))

    def test_multiline_js_selector(self):
        self.assertIn("Q001", self.active_ids("const keys = crypto.generateKeyPairSync(\n  'rsa',\n  {modulusLength: 2048}\n);", "app.js"))

    def test_c_style_comments_are_removed_with_line_numbers_preserved(self):
        found, _ = pqscan.analyze_source('/* ML-KEM-768\nRSA */\n// X25519\nconst a = crypto.generateKeyPairSync("rsa");\n', "auth.js")
        self.assertEqual([(f.rule_id, f.line) for f in found], [("Q001", 4)])

    def test_go_multiline_import_is_inventory(self):
        found, _ = pqscan.analyze_source('package main\nimport (\n  "crypto/rsa"\n  "crypto/mlkem"\n)\n', "app.go")
        self.assertTrue(found)
        self.assertTrue(all(f.evidence_kind == "import" for f in found))
        self.assertEqual(pqscan.assessment(found, False)["status"], "review_required")

    def test_dependency_only_never_proves_usage(self):
        for filename, content in [("requirements.txt", "pqcrypto==0.3.4\n"), ("package.json", '{"dependencies": {"@noble/post-quantum": "*"}}'), ("Cargo.toml", '[dependencies]\nml-kem = "*"\n')]:
            with self.subTest(filename=filename):
                found, _ = pqscan.analyze_source(content, filename)
                self.assertTrue(found)
                self.assertTrue(all(f.evidence_kind == "dependency" for f in found))
                self.assertEqual(pqscan.assessment(found, False)["status"], "review_required")

    def test_invalid_python_is_explicitly_incomplete(self):
        found, warnings = pqscan.analyze_source("if (: \n rsa.generate_private_key()", "invalid.py")
        self.assertTrue(warnings)
        self.assertTrue(all(f.confidence == "low" for f in found))
        self.assertEqual(pqscan.assessment(found, True)["status"], "review_required")

    def test_algorithm_boundaries_avoid_business_words(self):
        self.assertEqual(self.active_ids('const values = ["rsalink", "dsa_backup", "mlkemish", "sausage"];', "app.js"), set())

    def test_crypto_detection_regex_is_not_a_crypto_configuration(self):
        self.assertEqual(self.active_ids('import re\nCRYPTO_CALL = re.compile(r"rsa.generate_private_key|ML-KEM-768")'), set())


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def test_empty_repo_is_unknown(self):
        report = pqscan.scan_repository(self.root)
        self.assertEqual(report["assessment"]["status"], "no_crypto_evidence")
        self.assertFalse(report["assessment"]["certified_quantum_ready"])

    def test_files_are_never_executed(self):
        sentinel = self.root / "executed"
        self.write("app.py", f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\nrsa.generate_private_key(65537, 2048)\n")
        report = pqscan.scan_repository(self.root)
        self.assertFalse(sentinel.exists())
        self.assertEqual(report["assessment"]["status"], "migration_needed")

    def test_default_exclusions_and_ignore_file(self):
        for path in ("node_modules/x/app.py", "vendor/a.py", ".git/a.py", "legacy/a.py", "skip/a.py", "src/old.py"):
            self.write(path, "rsa.generate_private_key(65537, 2048)")
        self.write(".pqscanignore", "# excludes\nlegacy/\nsrc/old.py\n")
        self.write("src/main.py", "print('Hello')")
        report = pqscan.scan_repository(self.root, excludes=["skip"])
        self.assertEqual(report["summary"]["files_scanned"], 1)
        self.assertEqual(report["findings"], [])
        self.assertFalse(report["coverage"]["incomplete"])

    def test_does_not_silently_honor_gitignore(self):
        self.write(".gitignore", "app.py")
        self.write("app.py", "rsa.generate_private_key(65537, 2048)")
        self.assertEqual(pqscan.scan_repository(self.root)["assessment"]["status"], "migration_needed")

    def test_binary_large_file_and_symlink_are_reported(self):
        self.write("too_big.py", "a" * 201)
        self.write("binary.py", "\x00\x01")
        self.write("normal.py", "print('hi')")
        (self.root / "link.py").symlink_to(self.root / "normal.py")
        report = pqscan.scan_repository(self.root, max_file_bytes=200)
        reasons = {s["reason"] for s in report["coverage"]["skipped"]}
        self.assertTrue({"oversized", "binary", "symlink"} <= reasons)
        self.assertTrue(report["coverage"]["incomplete"])
        self.assertEqual(report["assessment"]["status"], "review_required")

    def test_directory_symlink_is_not_traversed(self):
        (self.root / "loop").symlink_to(self.root, target_is_directory=True)
        report = pqscan.scan_repository(self.root)
        self.assertEqual(report["summary"]["files_scanned"], 0)
        self.assertTrue(report["coverage"]["incomplete"])

    def test_permission_error_is_reported_and_fails(self):
        self.write("app.py", "print('hello')")
        with mock.patch("pqscan.read_regular_file", side_effect=PermissionError(13, "permission denied")):
            report = pqscan.scan_repository(self.root)
        self.assertTrue(report["coverage"]["errors"])
        self.assertEqual(pqscan.exit_status(report, "none"), 2)

    def test_non_utf8_python_encoding_cookie(self):
        (self.root / "app.py").write_bytes(b"# coding: latin-1\n# caf\xe9\nrsa.generate_private_key(65537, 2048)\n")
        self.assertEqual(pqscan.scan_repository(self.root)["assessment"]["status"], "migration_needed")

    def test_findings_order_is_deterministic(self):
        self.write("z.py", "rsa.generate_private_key(65537, 2048)")
        self.write("a.py", "rsa.generate_private_key(65537, 2048)")
        first = pqscan.scan_repository(self.root)
        second = pqscan.scan_repository(self.root)
        self.assertEqual(first["findings"], second["findings"])
        self.assertEqual([f["path"] for f in first["findings"]], ["a.py", "z.py"])

    def test_documentation_and_lockfiles_not_treated_as_implementation(self):
        self.write("README.md", "RSA ML-KEM-768")
        self.write("package-lock.json", '{"algorithm":"RSA"}')
        report = pqscan.scan_repository(self.root)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["files_scanned"], 0)

    def test_ci_severity_gate(self):
        self.write("auth.py", "rsa.generate_private_key(65537, 2048)")
        report = pqscan.scan_repository(self.root)
        self.assertEqual(pqscan.exit_status(report, "none"), 0)
        self.assertEqual(pqscan.exit_status(report, "high"), 1)

    def test_ci_gate_ignores_tests_but_not_incomplete_scan(self):
        self.write("tests/auth.py", "rsa.generate_private_key(65537, 2048)")
        report = pqscan.scan_repository(self.root)
        self.assertEqual(pqscan.exit_status(report, "high"), 0)
        self.write("broken.py", "if (: \n rsa.generate_private_key()")
        report = pqscan.scan_repository(self.root)
        self.assertEqual(pqscan.exit_status(report, "high"), 2)

    def test_only_matched_evidence_is_exported(self):
        self.write("auth.py", 'import jwt\njwt.encode(payload, "do-not-leak-this-key", algorithm="RS256")')
        rendered = json.dumps(pqscan.scan_repository(self.root))
        self.assertNotIn("do-not-leak-this-key", rendered)

    def test_previous_reports_are_not_scanned_as_implementation(self):
        report = pqscan.scan_repository(self.root)
        report["findings"] = [{"algorithm": "RSA"}]
        self.write("report.json", json.dumps(report))
        result = pqscan.scan_repository(self.root)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["coverage"]["skipped"][0]["reason"], "generated_report")

    def test_cli_json_and_exit_code(self):
        self.write("auth.py", "rsa.generate_private_key(65537, 2048)")
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.root), "--format", "json", "--fail-on", "high"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["assessment"]["status"], "migration_needed")
        self.assertEqual(result.stderr, "")

    def test_cli_output_does_not_overwrite_source(self):
        source = self.write("auth.py", "print('hello')")
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.root), "-o", str(source)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(source.read_text(), "print('hello')")
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_output_and_invalid_paths(self):
        output = self.root / "report.json"
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.root), "--format", "json", "-o", str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(json.loads(output.read_text())["schema_version"], "1.0")
        result = subprocess.run([sys.executable, str(SCRIPT), str(self.root / "missing")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_portable_single_file_from_another_directory(self):
        copy = self.root / "pqscan.py"
        copy.write_bytes(SCRIPT.read_bytes())
        repo = self.root / "repo"
        repo.mkdir()
        result = subprocess.run([sys.executable, str(copy), str(repo), "--format", "json"], cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["assessment"]["status"], "no_crypto_evidence")

    def test_terminal_control_characters_are_escaped(self):
        self.assertEqual(pqscan.terminal_safe("a\x1b[31m.py"), "a\\u001b[31m.py")


if __name__ == "__main__":
    unittest.main()
