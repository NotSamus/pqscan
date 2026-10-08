"""Offscreen integration tests for the desktop workflow; never opens user apps."""

import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import pqscan

HAS_QT = importlib.util.find_spec("PySide6") is not None
if HAS_QT:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication
    from pqscan_gui import MainWindow, list_local_models


@unittest.skipUnless(HAS_QT, "optional PySide6 is not installed")
class DesktopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setStyle("Fusion")
        cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo with spaces; echo nothing"
        self.repo.mkdir()
        (self.repo / "app.py").write_text("from pqcrypto.kem import ml_kem_768\nml_kem_768.generate_keypair()\nrsa.generate_private_key(65537, 2048)\n")
        self.window = MainWindow(repository=self.repo)
        self.window.output_input.setText(str(self.root / "reports"))
        self.window.pdf_check.setChecked(False)
        self.window.show()
        self.app.processEvents()

    def tearDown(self):
        self.window.close()
        self.app.processEvents()
        self.temp.cleanup()

    def wait_until(self, predicate, timeout=8):
        deadline = time.monotonic() + timeout
        while not predicate() and time.monotonic() < deadline:
            QTest.qWait(20)
        self.assertTrue(predicate(), self.window.activity.toPlainText())

    def load_fixture(self):
        path = self.root / "fixture.json"
        pqscan.save_json(pqscan.scan_repository(self.repo), path)
        self.assertTrue(self.window.load_path(path))
        return path

    def test_scan_button_runs_cli_and_loads_fusion(self):
        QTest.mouseClick(self.window.start_button, Qt.MouseButton.LeftButton)
        self.assertTrue(self.window.busy)
        self.assertFalse(self.window.start_button.isEnabled())
        self.assertTrue(self.window.cancel_button.isEnabled())
        self.wait_until(lambda: not self.window.busy)
        self.assertEqual(self.window.report["fusion_assessment"]["decision"], "mixed_evidence")
        self.assertEqual(self.window.metrics["implementation"].text(), "1")
        self.assertEqual(self.window.metrics["classical"].text(), "1")
        self.assertEqual(self.window.report["correctness_compliance"]["status"], "static_evidence_only")
        self.assertIn("Observed: ML-KEM-768", self.window.compliance_text.toPlainText())
        self.assertTrue(self.window.report_path.is_file())
        self.assertTrue(self.window.start_button.isEnabled())

    def test_filters_and_selection_keep_correct_finding_after_sort(self):
        self.load_fixture()
        self.window.severity.setCurrentText("high")
        self.assertEqual(self.window.finding_table.rowCount(), 1)
        self.window.finding_table.sortItems(2, Qt.SortOrder.DescendingOrder)
        self.window.finding_table.selectRow(0)
        self.assertIn("RSA", self.window.finding_details.toPlainText())
        self.window.search.setText("absent-algorithm")
        self.assertEqual(self.window.finding_table.rowCount(), 0)
        self.window.search.clear()
        self.window.severity.setCurrentText("All severities")
        self.assertGreater(self.window.finding_table.rowCount(), 1)

    def test_malformed_report_shows_error_without_crashing(self):
        old = self.load_fixture()
        bad = self.root / "invalid.json"
        bad.write_text("not-json")
        self.assertFalse(self.window.load_path(bad))
        self.assertEqual(self.window.report_path, old)
        self.assertIn("Could not load", self.window.run_status.text())

    def test_bad_repository_does_not_start_a_process(self):
        self.window.repo_input.setText(str(self.root / "missing"))
        self.window.start_scan()
        self.assertFalse(self.window.busy)
        self.assertIsNone(self.window.process)

    def test_cancel_stops_only_scanner_and_restores_controls(self):
        for i in range(150):
            (self.repo / f"extra{i}.py").write_text("rsa.generate_private_key(65537, 2048)\n" * 10)
        self.window.start_scan()
        self.assertTrue(self.window.process.waitForStarted(2000))
        self.window.cancel_run()
        self.wait_until(lambda: not self.window.busy)
        self.assertIn("Cancelled", self.window.run_status.text())
        self.assertTrue(self.window.start_button.isEnabled())

    @unittest.skipUnless(importlib.util.find_spec("reportlab"), "optional ReportLab is not installed")
    def test_pdf_export_uses_loaded_json_without_ollama(self):
        original = self.load_fixture()
        expected = self.root / "export.pdf"
        with mock.patch("pqscan_gui.QFileDialog.getSaveFileName", return_value=(str(expected), "PDF")):
            self.window.export_pdf()
        self.wait_until(lambda: not self.window.busy)
        self.assertTrue(expected.read_bytes().startswith(b"%PDF"))
        self.assertTrue(expected.with_suffix(".json").is_file())
        self.assertTrue(original.is_file())
        self.assertEqual(self.window.report["fusion_assessment"]["decision"], "mixed_evidence")

    def test_model_list_filters_remote_entries(self):
        response = {"models": [{"name": "local:latest", "size": 123}, {"name": "remote:cloud", "size": 123}, {"name": "proxy", "size": 123, "remote_host": "example.org"}]}
        with mock.patch("pqscan.ollama_request", return_value=response):
            self.assertEqual(list_local_models("http://localhost:11434"), ["local:latest"])

    def test_repository_labels_are_plain_text(self):
        self.load_fixture()
        self.window.report["repository"] = "<b>untrusted name</b>"
        self.window.display_report()
        self.assertEqual(self.window.repository_label.textFormat(), Qt.TextFormat.PlainText)
        self.assertIn("<b>", self.window.repository_label.text())


if __name__ == "__main__":
    unittest.main()
