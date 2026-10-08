"""Ollama contract, report persistence, and PDF regression tests."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import pqscan


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "auth.py").write_text('import jwt\njwt.encode(payload, "private-value-not-for-prompt", algorithm="RS256")\n')
        self.report = pqscan.scan_repository(self.repo)
        self.finding_id = self.report["findings"][0]["finding_id"]
        self.analysis = {
            "executive_summary": "RSA signature usage requires a migration review; runtime reachability remains unverified.",
            "priorities": [{"title": "Review signing", "reason": "An RSA selector appears in a production call.",
                            "action": "Confirm the signing path and assess a compatible post-quantum signature protocol.",
                            "finding_ids": [self.finding_id]}],
            "validation_steps": ["Confirm deployed provider versions and verifier compatibility."],
            "uncertainties": ["The scan does not prove runtime reachability."],
        }
        self.tags = {"models": [{"name": "test-model:latest", "size": 123456, "digest": "local-digest"}]}

    def tearDown(self):
        self.temp.cleanup()

    def completed_review(self):
        return {"status": "completed", "provider": "ollama", "model": "test-model:latest", "findings_sent": 1,
                "findings_omitted": 0, "analysis": copy.deepcopy(self.analysis)}

    def invoke(self, *arguments):
        with mock.patch("sys.stderr", new_callable=io.StringIO), mock.patch("sys.stdout", new_callable=io.StringIO):
            return pqscan.main(list(arguments))

    def test_successful_review_keeps_scan_authoritative(self):
        before = copy.deepcopy(self.report)
        response = {"done": True, "done_reason": "stop", "message": {"content": json.dumps(self.analysis)}}
        with mock.patch("pqscan.ollama_request", side_effect=[self.tags, response]) as client:
            review = pqscan.review_with_ollama(self.report, "test-model")
        self.assertEqual(self.report, before)
        self.assertEqual(review["status"], "completed")
        self.assertEqual(review["model_digest"], "local-digest")
        payload = client.call_args_list[1].args[2]
        self.assertFalse(payload["stream"])
        self.assertEqual(payload["format"], pqscan.REVIEW_SCHEMA)
        self.assertNotIn("private-value-not-for-prompt", json.dumps(payload))
        self.assertNotIn(str(self.repo), json.dumps(payload))
        self.assertNotIn("tools", payload)

    def test_only_loopback_urls_are_accepted(self):
        for url in ("http://example.com:11434", "https://ollama.com", "http://127.0.0.1.evil.test", "file:///tmp/model", "http://user:pass@localhost:11434", "http://localhost:11434/path", "http://localhost:11434?proxy=1", "http://[broken"):
            with self.subTest(url=url), self.assertRaises(pqscan.OllamaError):
                pqscan.local_ollama_url(url)
        self.assertEqual(pqscan.local_ollama_url("http://localhost:11434/"), "http://127.0.0.1:11434")
        self.assertEqual(pqscan.local_ollama_url("http://[::1]:11434"), "http://[::1]:11434")

    def test_cloud_and_missing_models_are_not_pulled(self):
        with mock.patch("pqscan.ollama_request", return_value={"models": []}) as client:
            with self.assertRaises(pqscan.OllamaError):
                pqscan.review_with_ollama(self.report, "missing")
            self.assertEqual(client.call_count, 1)
        with mock.patch("pqscan.ollama_request") as client:
            with self.assertRaises(pqscan.OllamaError):
                pqscan.review_with_ollama(self.report, "some-model:cloud")
            client.assert_not_called()

    def test_http_transport_disables_proxies_and_redirects(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"done": true}'
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch("pqscan.urlrequest.build_opener", return_value=opener) as build:
            pqscan.ollama_request("http://127.0.0.1:11434", "/api/chat", {"model": "test"}, 12)
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], pqscan.NoRedirect)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/api/chat")
        self.assertEqual(json.loads(request.data), {"model": "test"})
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 12)

    def test_http_errors_and_timeout_are_actionable(self):
        for failure in (TimeoutError("timed out"), pqscan.urlerror.URLError("refused"), pqscan.urlerror.HTTPError("local", 404, "not found", {}, None)):
            with self.subTest(failure=failure), mock.patch("pqscan.urlrequest.build_opener") as build:
                build.return_value.open.side_effect = failure
                with self.assertRaises(pqscan.OllamaError):
                    pqscan.ollama_request("http://127.0.0.1:11434", "/api/chat", {})

    def test_prompt_size_is_bounded_and_omissions_are_explicit(self):
        report = copy.deepcopy(self.report)
        report["findings"] = [dict(report["findings"][0], finding_id=f"F{i:04d}") for i in range(1, 201)]
        payload = pqscan.build_review_evidence(report, max_findings=5, max_chars=1500)
        self.assertLessEqual(len(payload["findings"]), 5)
        self.assertEqual(payload["findings_sent"] + payload["findings_omitted"], 200)
        self.assertLessEqual(sum(len(json.dumps(f)) for f in payload["findings"]), 1500)

    def test_schema_rejects_fabricated_evidence_references(self):
        self.analysis["priorities"][0]["finding_ids"] = ["F9999"]
        with self.assertRaises(pqscan.OllamaError):
            pqscan.validate_review(self.analysis, {self.finding_id})

    def test_schema_rejects_verdict_override_and_invalid_types(self):
        for changed in (dict(self.analysis, assessment="quantum ready"), dict(self.analysis, priorities="safe"), dict(self.analysis, executive_summary="")):
            with self.subTest(changed=changed), self.assertRaises(pqscan.OllamaError):
                pqscan.validate_review(changed, {self.finding_id})

    def test_incomplete_or_malformed_generation_is_not_accepted(self):
        for response in ({"done": False}, {"done": True, "done_reason": "length"}, {"done": True, "message": {"content": "not JSON"}}):
            with self.subTest(response=response), mock.patch("pqscan.ollama_request", side_effect=[self.tags, response]):
                with self.assertRaises(pqscan.OllamaError):
                    pqscan.review_with_ollama(self.report, "test-model")

    def test_json_exists_before_ollama_and_is_augmented_afterwards(self):
        output = self.root / "result.json"

        def inference(*args):
            saved = json.loads(output.read_text())
            self.assertEqual(saved["assessment"], self.report["assessment"])
            self.assertEqual(saved["llm_analysis"]["status"], "pending")
            return self.completed_review()

        with mock.patch("pqscan.review_with_ollama", side_effect=inference):
            code = self.invoke(str(self.repo), "--format", "json", "-o", str(output), "--ollama", "test-model")
        self.assertEqual(code, 0)
        saved = json.loads(output.read_text())
        self.assertEqual(saved["assessment"], self.report["assessment"])
        self.assertEqual(saved["llm_analysis"]["status"], "completed")
        self.assertFalse(list(self.root.glob(".pqscan-*")))

    def test_failed_model_retains_json_and_still_requests_pdf(self):
        pdf = self.root / "failed.pdf"
        with mock.patch("pqscan.review_with_ollama", side_effect=pqscan.OllamaError("server unavailable")), mock.patch("pqscan.render_pdf") as render:
            code = self.invoke(str(self.repo), "--pdf", str(pdf), "--ollama", "test-model")
        self.assertEqual(code, 2)
        saved = json.loads(pdf.with_suffix(".json").read_text())
        self.assertEqual(saved["llm_analysis"]["status"], "failed")
        self.assertEqual(saved["assessment"]["status"], "migration_needed")
        self.assertEqual(render.call_args.args[0]["llm_analysis"]["status"], "failed")

    def test_pdf_failure_preserves_json(self):
        pdf = self.root / "failed.pdf"
        with mock.patch("pqscan.render_pdf", side_effect=ValueError("missing dependency")):
            code = self.invoke(str(self.repo), "--pdf", str(pdf))
        self.assertEqual(code, 2)
        self.assertTrue(pdf.with_suffix(".json").is_file())

    def test_existing_pdf_is_never_overwritten(self):
        pdf = self.root / "existing.pdf"
        pdf.write_bytes(b"original PDF")
        self.assertEqual(self.invoke(str(self.repo), "--pdf", str(pdf)), 2)
        self.assertEqual(pdf.read_bytes(), b"original PDF")
        self.assertFalse(pdf.with_suffix(".json").exists())

    def test_pdf_and_json_cannot_share_a_path(self):
        pdf = self.root / "report.pdf"
        self.assertEqual(self.invoke(str(self.repo), "--pdf", str(pdf), "--output", str(pdf)), 2)
        self.assertFalse(pdf.exists())

    def test_report_can_be_reused_without_rescanning(self):
        original = self.root / "original.json"
        pqscan.save_json(self.report, original)
        old_bytes = original.read_bytes()
        pdf = self.root / "new" / "report.pdf"
        with mock.patch("pqscan.scan_repository") as scan, mock.patch("pqscan.render_pdf") as render:
            code = self.invoke("--from-json", str(original), "--pdf", str(pdf))
        self.assertEqual(code, 0)
        scan.assert_not_called()
        render.assert_called_once()
        self.assertEqual(original.read_bytes(), old_bytes)
        self.assertTrue(pdf.with_suffix(".json").exists())

    def test_older_reports_receive_finding_ids_on_load(self):
        for f in self.report["findings"]:
            del f["finding_id"]
        original = self.root / "old.json"
        pqscan.save_json(self.report, original)
        loaded = pqscan.load_report(original)
        self.assertEqual(loaded["findings"][0]["finding_id"], "F0001")

    def test_malformed_report_fails_cleanly(self):
        original = self.root / "bad.json"
        original.write_text('{"tool":"pqscan","schema_version":"1.0","findings":[{}]}')
        self.assertEqual(self.invoke("--from-json", str(original), "--pdf", str(self.root / "out.pdf")), 2)

    def test_json_only_scanning_stays_dependency_free(self):
        output = self.root / "scan.json"
        with mock.patch("pqscan.render_pdf") as render, mock.patch("pqscan.review_with_ollama") as review:
            self.assertEqual(self.invoke(str(self.repo), "--format", "json", "-o", str(output)), 0)
        render.assert_not_called()
        review.assert_not_called()

    @unittest.skipUnless(importlib.util.find_spec("reportlab"), "optional ReportLab is not installed")
    def test_pdf_handles_long_paths_model_markup_and_page_breaks(self):
        report = copy.deepcopy(self.report)
        report["llm_analysis"] = self.completed_review()
        report["llm_analysis"]["analysis"]["executive_summary"] = '<b>Literal model text</b> & "quotes"; review - do not certify.'
        for index in range(15):
            item = dict(report["findings"][0], finding_id=f"F{index+2:04d}", path=("verylongpath" * 25) + "/auth.py")
            report["findings"].append(item)
        report["summary"]["findings"] = len(report["findings"])
        output = self.root / "stress.pdf"
        pqscan.render_pdf(report, output)
        self.assertTrue(output.read_bytes().startswith(b"%PDF-"))
        self.assertGreater(output.stat().st_size, 5000)
        if importlib.util.find_spec("pypdf"):
            from pypdf import PdfReader
            reader = PdfReader(output)
            text = "\n".join(page.extract_text() for page in reader.pages)
            self.assertGreater(len(reader.pages), 3)
            self.assertIn("<b>Literal model text</b>", text)
            self.assertIn("F0016", text)
            self.assertIn("Coverage and limitations", text)
            for page in reader.pages:
                self.assertIn("Not a certification", page.extract_text())


if __name__ == "__main__":
    unittest.main()
