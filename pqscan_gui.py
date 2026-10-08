#!/usr/bin/env python3
"""PySide6 desktop interface for the same PQScan CLI and report schema."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys
import uuid

import pqscan

ROOT = Path(__file__).resolve().parent


def list_local_models(url):
    data = pqscan.ollama_request(pqscan.local_ollama_url(url), "/api/tags", timeout=10)
    return [m["name"] for m in data.get("models", []) if isinstance(m, dict)
            and isinstance(m.get("name"), str) and m.get("size")
            and not m.get("remote_host") and not m.get("remote_model")
            and "cloud" not in m["name"].lower()]


# Model discovery runs as a separate process, so no HTTP request blocks the UI.
if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--list-models":
    try:
        print(json.dumps(list_local_models(sys.argv[2])))
    except (ValueError, OSError, TypeError) as exc:
        print(pqscan.terminal_safe(exc), file=sys.stderr)
        sys.exit(2)
    sys.exit(0)

try:
    from PySide6.QtCore import QProcess, Qt, QTimer, QUrl
    from PySide6.QtGui import QColor, QDesktopServices
    from PySide6.QtWidgets import (
        QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QHBoxLayout,
        QHeaderView, QLabel, QLineEdit, QMainWindow, QPlainTextEdit, QProgressBar,
        QPushButton, QSplitter, QTableWidget, QTableWidgetItem, QTabWidget,
        QVBoxLayout, QWidget, QAbstractItemView,
    )
except ImportError:
    if __name__ == "__main__":
        print("The desktop app needs PySide6. Run: .venv/bin/python -m pip install -r requirements-gui.txt", file=sys.stderr)
        sys.exit(2)
    raise


STYLE = """
QMainWindow, QWidget#shell { background: #f3f6f8; }
QWidget { color: #173047; font-family: 'Inter', 'Arial'; font-size: 13px; }
QFrame#sidebar { background: #142c40; border: none; }
QFrame#sidebar QLabel, QFrame#sidebar QCheckBox { color: #d3e3ef; }
QFrame#sidebar QLabel#brand { color: white; font-size: 26px; font-weight: 700; }
QFrame#sidebar QLabel#muted { color: #9eb6c8; font-size: 12px; }
QLabel#eyebrow { color: #187e84; font-size: 11px; font-weight: 700; }
QLabel#title { font-size: 28px; font-weight: 700; color: #142c40; }
QLabel#muted { color: #607688; font-size: 12px; }
QLabel#section { font-size: 16px; font-weight: 700; }
QLabel#metric { font-size: 28px; font-weight: 700; }
QLabel#headline { font-size: 20px; font-weight: 700; }
QFrame#card, QFrame#banner { background: white; border: 1px solid #dce5eb; border-radius: 10px; }
QFrame#banner { background: #eaf5f4; border: 1px solid #c7dfdd; }
QLineEdit, QComboBox { background: white; color: #173047; border: 1px solid #cfdae3;
    border-radius: 6px; padding: 8px; min-height: 18px; selection-background-color: #cee8e8; }
QLineEdit:focus, QComboBox:focus { border-color: #19878c; }
QComboBox QAbstractItemView { background: white; color: #173047; selection-background-color: #d6ecec; }
QPushButton { background: white; color: #173047; border: 1px solid #ccd9e3; border-radius: 6px; padding: 9px 12px; font-weight: 600; }
QPushButton:hover { background: #e9f2f4; border-color: #5c9ca3; }
QPushButton:disabled { background: #e9eef2; color: #8797a4; border-color: #dde4e9; }
QPushButton#primary { background: #238e91; border-color: #238e91; color: white; padding: 12px; }
QPushButton#primary:hover { background: #16777e; }
QPushButton#primary:disabled { background: #446773; color: #a7bcc6; }
QPushButton#secondary { background: #203e53; border-color: #456477; color: #e6eff5; }
QPushButton#secondary:disabled { color: #7793a5; }
QTabWidget::pane { background: white; border: 1px solid #dce5eb; border-radius: 8px; }
QTabBar::tab { background: transparent; color: #607688; padding: 12px 17px; border-bottom: 3px solid transparent; }
QTabBar::tab:selected { color: #16777e; border-bottom: 3px solid #238e91; font-weight: 700; }
QTableWidget { background: white; alternate-background-color: #f6f9fa; gridline-color: #e5ebf0; border: none; selection-background-color: #d5eceb; selection-color: #173047; }
QHeaderView::section { background: #eef3f6; color: #4a6377; padding: 9px; border: none; border-bottom: 1px solid #dce5eb; font-size: 11px; font-weight: 700; }
QPlainTextEdit { background: #ffffff; border: 1px solid #e0e7ed; border-radius: 6px; padding: 10px; color: #25435b; selection-background-color: #cde8e7; }
QProgressBar { border: none; background: #29485e; border-radius: 3px; min-height: 5px; max-height: 5px; }
QProgressBar::chunk { background: #6bd1c5; }
QSplitter::handle { background: #e5ecf1; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; }
QToolTip { background: #142c40; color: white; border: none; padding: 6px; }
"""


def label(text="", name=None, wrap=False):
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setWordWrap(wrap)
    if name:
        widget.setObjectName(name)
    return widget


def readonly_text():
    widget = QPlainTextEdit()
    widget.setReadOnly(True)
    return widget


class MainWindow(QMainWindow):
    def __init__(self, repository=None, report_path=None):
        super().__init__()
        self.setWindowTitle("PQScan - Repository readiness")
        self.resize(1360, 900)
        self.setMinimumSize(1100, 780)
        self.report = None
        self.report_path = None
        self.pdf_path = None
        self.process = None
        self.model_process = None
        self.busy = False
        self.cancelled = False
        self.run_id = 0
        self.setStyleSheet(STYLE)
        shell = QWidget()
        shell.setObjectName("shell")
        layout = QHBoxLayout(shell)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.setCentralWidget(shell)
        self.build_sidebar(layout)
        self.build_content(layout)
        if repository:
            self.repo_input.setText(str(Path(repository).expanduser().absolute()))
        if report_path:
            self.load_path(Path(report_path).expanduser())

    def build_sidebar(self, root):
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(290)
        box = QVBoxLayout(sidebar)
        box.setContentsMargins(22, 27, 22, 24)
        box.setSpacing(11)
        box.addWidget(label("PQ / SCAN", "brand"))
        box.addWidget(label("POST-QUANTUM REPOSITORY ANALYSIS", "muted", True))
        box.addSpacing(25)
        box.addWidget(label("Repository folder"))
        self.repo_input = QLineEdit()
        self.repo_input.setPlaceholderText("/path/to/repository")
        box.addWidget(self.repo_input)
        self.browse_button = QPushButton("Choose repository")
        self.browse_button.setObjectName("secondary")
        self.browse_button.clicked.connect(self.choose_repository)
        box.addWidget(self.browse_button)
        box.addSpacing(9)
        box.addWidget(label("Report folder"))
        self.output_input = QLineEdit(str(ROOT / "reports"))
        box.addWidget(self.output_input)
        box.addSpacing(12)
        self.use_ollama = QCheckBox("Include local Ollama review")
        self.use_ollama.toggled.connect(self.update_controls)
        box.addWidget(self.use_ollama)
        self.model = QComboBox()
        self.model.setEditable(True)
        self.model.addItem("gemma4:e4b")
        box.addWidget(self.model)
        self.url_input = QLineEdit("http://127.0.0.1:11434")
        self.url_input.setToolTip("Local Ollama server. Only loopback addresses are accepted.")
        box.addWidget(self.url_input)
        self.refresh_button = QPushButton("Refresh local models")
        self.refresh_button.setObjectName("secondary")
        self.refresh_button.clicked.connect(self.refresh_models)
        box.addWidget(self.refresh_button)
        self.model_status = label("Optional. Your source files stay local.", "muted", True)
        box.addWidget(self.model_status)
        box.addSpacing(14)
        self.pdf_check = QCheckBox("Create PDF alongside JSON")
        self.pdf_check.setChecked(True)
        box.addWidget(self.pdf_check)
        self.start_button = QPushButton("Analyze repository")
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self.start_scan)
        box.addWidget(self.start_button)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("secondary")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_run)
        box.addWidget(self.cancel_button)
        box.addStretch()
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        box.addWidget(self.progress)
        self.run_status = label("Ready to analyze", "muted", True)
        box.addWidget(self.run_status)
        box.addSpacing(10)
        box.addWidget(label("PQC dependencies signal capability.\nDeployment protection needs verification.", "muted", True))
        root.addWidget(sidebar)

    def build_content(self, root):
        content = QWidget()
        box = QVBoxLayout(content)
        box.setContentsMargins(28, 25, 28, 22)
        box.setSpacing(17)
        header = QHBoxLayout()
        title = QVBoxLayout()
        title.addWidget(label("EVIDENCE FUSION", "eyebrow"))
        title.addWidget(label("Repository readiness", "title"))
        title.addWidget(label("Connect declared capability, implementation and verification.", "muted"))
        header.addLayout(title)
        header.addStretch()
        self.load_button = QPushButton("Load JSON")
        self.load_button.clicked.connect(self.choose_report)
        header.addWidget(self.load_button)
        self.export_button = QPushButton("Export PDF")
        self.export_button.clicked.connect(self.export_pdf)
        header.addWidget(self.export_button)
        self.open_button = QPushButton("Open report")
        self.open_button.clicked.connect(self.open_output)
        header.addWidget(self.open_button)
        box.addLayout(header)
        self.repository_label = label("Choose a repository to begin, or load a previous JSON report.", "muted", True)
        self.repository_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        box.addWidget(self.repository_label)
        banner = QFrame()
        banner.setObjectName("banner")
        banner_box = QVBoxLayout(banner)
        banner_box.setContentsMargins(18, 15, 18, 15)
        self.headline = label("Build a picture of PQC adoption", "headline")
        self.reason = label("The assessment combines observable evidence. Runtime verification and certification remain separate.", wrap=True)
        self.static_status = label("No repository assessed", "muted", True)
        banner_box.addWidget(self.headline)
        banner_box.addWidget(self.reason)
        banner_box.addWidget(self.static_status)
        box.addWidget(banner)
        cards = QHBoxLayout()
        self.metrics = {}
        for key, title in (("declarations", "PQC DECLARATIONS"), ("implementation", "PQC USAGE SITES"), ("classical", "CLASSICAL SITES"), ("coverage", "SCAN COVERAGE")):
            card = QFrame()
            card.setObjectName("card")
            card_box = QVBoxLayout(card)
            card_box.setContentsMargins(16, 12, 16, 12)
            card_box.addWidget(label(title, "muted"))
            value = label("--", "metric")
            self.metrics[key] = value
            card_box.addWidget(value)
            cards.addWidget(card)
        box.addLayout(cards)
        self.tabs = QTabWidget()
        box.addWidget(self.tabs, 1)
        overview = QWidget()
        overview_box = QVBoxLayout(overview)
        overview_box.setContentsMargins(18, 17, 18, 15)
        overview_box.addWidget(label("Evidence sources", "section"))
        self.fusion_table = self.make_table(["SOURCE", "OBSERVATION", "SITES", "WHAT IT ESTABLISHES"])
        self.fusion_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.fusion_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.fusion_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.fusion_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.fusion_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        overview_box.addWidget(self.fusion_table, 3)
        overview_box.addWidget(label("Next verification steps", "section"))
        self.steps = readonly_text()
        self.steps.setPlainText("Scan a repository to see evidence and the checks still needed.")
        overview_box.addWidget(self.steps, 2)
        self.tabs.addTab(overview, "Overview")

        self.compliance_text = readonly_text()
        self.compliance_text.setPlainText("Scan a repository to inspect NIST parameter sets and correctness evidence.")
        self.tabs.addTab(self.compliance_text, "Correctness and compliance")

        findings = QWidget()
        findings_box = QVBoxLayout(findings)
        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search algorithm, path, rule or evidence")
        self.search.textChanged.connect(self.populate_findings)
        filters.addWidget(self.search, 1)
        self.severity = QComboBox()
        self.severity.addItems(["All severities", "high", "medium", "low", "info"])
        self.severity.currentTextChanged.connect(self.populate_findings)
        filters.addWidget(self.severity)
        self.context = QComboBox()
        self.context.addItems(["All contexts", "production", "test", "example"])
        self.context.currentTextChanged.connect(self.populate_findings)
        filters.addWidget(self.context)
        findings_box.addLayout(filters)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.finding_table = self.make_table(["ID", "SEVERITY", "ALGORITHM", "CONTEXT", "EVIDENCE", "LOCATION"])
        self.finding_table.setSortingEnabled(True)
        self.finding_table.itemSelectionChanged.connect(self.show_finding)
        splitter.addWidget(self.finding_table)
        self.finding_details = readonly_text()
        self.finding_details.setPlaceholderText("Select a finding to inspect its evidence and suggested next step.")
        splitter.addWidget(self.finding_details)
        splitter.setSizes([300, 150])
        findings_box.addWidget(splitter)
        self.tabs.addTab(findings, "Findings")
        self.ai_text = readonly_text()
        self.ai_text.setPlainText("No model review loaded. Enable local Ollama review to add advisory analysis.")
        self.tabs.addTab(self.ai_text, "Local model")
        self.coverage_text = readonly_text()
        self.tabs.addTab(self.coverage_text, "Coverage")
        self.activity = readonly_text()
        self.activity.setMaximumBlockCount(2000)
        self.tabs.addTab(self.activity, "Activity")
        root.addWidget(content, 1)
        self.update_controls()

    @staticmethod
    def make_table(headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(37)
        table.horizontalHeader().setStretchLastSection(True)
        return table

    def update_controls(self):
        # Signals can fire while the initial widget tree is still being built.
        if not hasattr(self, "open_button"):
            return
        for widget in (self.repo_input, self.output_input, self.browse_button, self.use_ollama, self.pdf_check, self.start_button, self.load_button):
            widget.setEnabled(not self.busy)
        enabled = self.use_ollama.isChecked() and not self.busy
        self.model.setEnabled(enabled)
        self.url_input.setEnabled(enabled)
        self.refresh_button.setEnabled(enabled and self.model_process is None)
        self.cancel_button.setEnabled(self.busy)
        self.export_button.setEnabled(not self.busy and self.report_path is not None)
        self.open_button.setEnabled(not self.busy and self.report_path is not None)

    def choose_repository(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose a local repository", self.repo_input.text() or str(Path.home()))
        if folder:
            self.repo_input.setText(folder)

    def choose_report(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load PQScan JSON", self.output_input.text(), "JSON reports (*.json)")
        if path:
            self.load_path(Path(path))

    def load_path(self, path):
        try:
            report = pqscan.load_report(path)
        except (OSError, ValueError, RecursionError) as exc:
            self.run_status.setText("Could not load report. See Activity.")
            self.activity.appendPlainText(str(exc))
            return False
        self.report = report
        self.report_path = path.absolute()
        self.repo_input.setText(report["repository"])
        self.repo_input.setCursorPosition(0)
        candidate = self.report_path.with_suffix(".pdf")
        self.pdf_path = candidate if candidate.is_file() else None
        self.display_report()
        self.update_controls()
        return True

    def display_report(self):
        report = self.report
        fusion = report["fusion_assessment"]
        self.repository_label.setText(report["repository"] + "  |  " + report["generated_at"])
        self.headline.setText(fusion["label"])
        self.reason.setText(fusion["reason"])
        self.static_status.setText("Scanner: " + report["assessment"]["status"].replace("_", " ") + "  /  Runtime: unverified  /  Certification: not issued")
        for key in ("declarations", "implementation", "classical"):
            self.metrics[key].setText(str(fusion["signals"][key]["sites"]))
        self.metrics["coverage"].setText("Incomplete" if fusion["coverage_incomplete"] else "In scope")
        rows = []
        for signal in fusion["signals"].values():
            rows.append((signal["label"], "Observed" if signal["observed"] else "Not observed", str(signal["sites"]), signal["explanation"]))
        rows.extend([
            ("Runtime / test validation", "Not performed", "--", "Source inspection does not prove test success or deployed protection."),
            ("Local model review", report.get("llm_analysis", {}).get("status", "not_requested").replace("_", " "), "--", fusion["model_role"]),
        ])
        self.fusion_table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.fusion_table.setItem(row, col, item)
        self.steps.setPlainText("\n\n".join(f"{i}. {step}" for i, step in enumerate(fusion["next_steps"], 1)))
        compliance = report["correctness_compliance"]
        compliance_lines = [
            "CORRECTNESS AND NIST COMPLIANCE",
            "Status: " + compliance["status"].replace("_", " "),
            compliance["reason"], "",
            "APPROVED PARAMETER SETS AND OBSERVATIONS",
        ]
        for name, item in compliance["algorithms"].items():
            compliance_lines.extend([
                "",
                f"{name} / {item['standard']}",
                "Approved: " + ", ".join(item["approved_parameter_sets"]),
                "Observed: " + (", ".join(item["observed_parameter_sets"]) or "none resolved"),
                "Static status: " + item["status"].replace("_", " "),
            ])
            if item["unresolved_finding_ids"]:
                compliance_lines.append("Unresolved evidence: " + ", ".join(item["unresolved_finding_ids"]))
        compliance_lines.extend(["", "REQUIRED VALIDATION EVIDENCE"])
        for control in compliance["controls"].values():
            compliance_lines.extend([
                "", control["label"].upper(),
                "Status: " + control["status"].replace("_", " "),
                control["requirement"], control["interpretation"],
            ])
            if control["finding_ids"]:
                compliance_lines.append("Production evidence: " + ", ".join(control["finding_ids"]))
            if control["nonproduction_finding_ids"]:
                compliance_lines.append("Test/example evidence (not executed): " + ", ".join(control["nonproduction_finding_ids"]))
        compliance_lines.extend([
            "", "EXECUTED CONFORMANCE BOUNDARY",
            "Known-answer tests: not executed",
            "Negative tests: not executed",
            "Interoperability tests: not executed",
            "ACVP/CAVP validation: not verified",
            "FIPS-validated module: not verified",
            "Correctness verified: no",
            "Compliance certified: no",
            "", compliance["boundary"],
        ])
        self.compliance_text.setPlainText("\n".join(compliance_lines))
        self.populate_findings()
        coverage = report["coverage"]
        lines = [f"Files scanned: {report['summary']['files_scanned']}",
                 "Coverage incomplete: " + str(coverage["incomplete"]),
                 "\nWarnings / errors:", *coverage["warnings"], *coverage["errors"],
                 "\nSkipped paths:", *[f"{s['path']}  |  {s['reason']}" for s in coverage["skipped"]],
                 "\nLimits of this assessment:", *report["limitations"]]
        self.coverage_text.setPlainText("\n".join(lines))
        review = report.get("llm_analysis", {"status": "not_requested"})
        lines = ["LOCAL MODEL REVIEW - ADVISORY", "Status: " + review["status"], ""]
        if review["status"] == "completed":
            a = review["analysis"]
            lines.extend(["Model: " + review["model"], f"Findings supplied: {review['findings_sent']}; omitted: {review['findings_omitted']}", "", a["executive_summary"], "", "PRIORITIES"])
            for priority in a["priorities"]:
                lines.extend([priority["title"] + "  [" + ", ".join(priority["finding_ids"]) + "]", priority["reason"], "Action: " + priority["action"], ""])
            lines.extend(["VALIDATION STEPS", *a["validation_steps"], "", "UNCERTAINTIES", *a["uncertainties"]])
        else:
            lines.append(str(review.get("error", "A model review does not count as runtime validation. Enable Ollama review when starting a new scan.")))
        self.ai_text.setPlainText("\n".join(lines))

    def populate_findings(self, *_):
        if self.report is None:
            return
        needle = self.search.text().casefold()
        severity, context = self.severity.currentText(), self.context.currentText()
        rows = [f for f in self.report["findings"]
                if (severity == "All severities" or f["severity"] == severity)
                and (context == "All contexts" or f["context"] == context)
                and (not needle or needle in " ".join(str(v) for v in f.values()).casefold())]
        self.finding_table.setSortingEnabled(False)
        self.finding_table.setRowCount(len(rows))
        self.finding_details.clear()
        for row, f in enumerate(rows):
            values = [f["finding_id"], f["severity"].upper(), f["algorithm"], f["context"], f["evidence_kind"], f"{f['path']}:{f['line']}"]
            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, f)
                if col == 1:
                    item.setForeground(QColor({"high": "#a34835", "medium": "#996015", "low": "#526b81", "info": "#16777e"}[f["severity"]]))
                self.finding_table.setItem(row, col, item)
        self.finding_table.setSortingEnabled(True)
        self.finding_table.resizeColumnsToContents()
        for column in range(self.finding_table.columnCount() - 1):
            self.finding_table.setColumnWidth(column, self.finding_table.columnWidth(column) + 16)
        self.tabs.setTabText(2, f"Findings ({len(rows)})")

    def show_finding(self):
        row = self.finding_table.currentRow()
        item = self.finding_table.item(row, 0)
        f = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not f:
            return
        self.finding_details.setPlainText(
            f"{f['finding_id']} / {f['rule_id']} / {f['algorithm']}\n"
            f"{f['path']}:{f['line']}:{f['column']}\n"
            f"{f['context']} | {f['evidence_kind']} | confidence: {f['confidence']}\n\n"
            f"Matched evidence: {f['evidence']}\n\n{f['recommendation']}\n\nReference: {f['reference']}")

    def start_scan(self):
        text = self.repo_input.text().strip()
        target = Path(text).expanduser()
        if not text or not target.is_dir():
            self.run_status.setText("Choose an existing repository folder.")
            return
        if not self.output_input.text().strip():
            self.run_status.setText("Choose a report folder.")
            return
        if self.use_ollama.isChecked() and not self.model.currentText().strip():
            self.run_status.setText("Select or enter a local Ollama model.")
            return
        output = Path(self.output_input.text().strip()).expanduser().absolute()
        stem = "pqscan-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        result_path = output / (stem + ".json")
        args = [str(target.absolute()), "--format", "json", "--output", str(result_path)]
        if self.pdf_check.isChecked():
            args.extend(["--pdf", str(output / (stem + ".pdf"))])
        if self.use_ollama.isChecked():
            args.extend(["--ollama", self.model.currentText().strip(), "--ollama-url", self.url_input.text().strip()])
        self.begin_process(args, result_path, "Scanning repository...")

    def export_pdf(self):
        if self.report_path is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export PDF with JSON sidecar", str(self.report_path.with_name(self.report_path.stem + "-export.pdf")), "PDF reports (*.pdf)")
        if not path:
            return
        pdf = Path(path)
        if pdf.suffix.lower() != ".pdf":
            pdf = pdf.with_suffix(".pdf")
        self.begin_process(["--from-json", str(self.report_path), "--pdf", str(pdf)], pdf.with_suffix(".json"), "Exporting report...")

    def begin_process(self, args, result_path, status):
        if self.busy:
            return
        self.busy, self.cancelled = True, False
        self.run_id += 1
        run_id = self.run_id
        self.run_status.setText(status)
        self.progress.setRange(0, 0)
        self.activity.clear()
        self.activity.appendPlainText(status)
        self.update_controls()
        if self.process is not None:
            self.process.deleteLater()
        process = QProcess(self)
        self.process = process
        process.setWorkingDirectory(str(ROOT))
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        process.readyReadStandardOutput.connect(self.read_process_output)
        process.finished.connect(lambda code, exit_state: self.process_finished(code, result_path, run_id))
        process.errorOccurred.connect(lambda error: self.process_error(error, run_id))
        # No shell: repository paths and model names are passed as literal args.
        process.start(sys.executable, [str(ROOT / "pqscan.py"), *args])

    def read_process_output(self):
        if self.process is None:
            return
        text = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace").strip()
        if text:
            self.activity.appendPlainText(text)
        if "Reviewing scan evidence" in text:
            self.run_status.setText("Scan saved. Reviewing with local Ollama...")
        elif "JSON saved:" in text:
            self.run_status.setText("Evidence saved. Preparing report...")

    def process_error(self, error, run_id):
        if run_id != self.run_id or error != QProcess.ProcessError.FailedToStart:
            return
        self.activity.appendPlainText(self.process.errorString())
        self.busy = False
        self.progress.setRange(0, 1)
        self.run_status.setText("Could not start scanner. See Activity.")
        self.update_controls()

    def process_finished(self, code, result_path, run_id):
        if run_id != self.run_id:
            return
        self.read_process_output()
        self.busy = False
        self.progress.setRange(0, 1)
        self.progress.setValue(1 if code == 0 else 0)
        loaded = result_path.is_file() and self.load_path(result_path)
        if self.cancelled:
            self.run_status.setText("Cancelled. Any saved JSON checkpoint is retained.")
        elif code == 0 and loaded:
            self.run_status.setText("Report complete. Evidence is ready to review.")
        else:
            self.run_status.setText("Finished with errors. See Activity; saved evidence is retained.")
        self.update_controls()

    def cancel_run(self):
        if not self.busy or self.process is None:
            return
        self.cancelled = True
        self.run_status.setText("Cancelling...")
        self.process.terminate()
        run_id = self.run_id
        QTimer.singleShot(2000, lambda: self.process.kill() if self.busy and self.run_id == run_id else None)

    def refresh_models(self):
        if self.model_process is not None:
            return
        self.model_status.setText("Checking local Ollama...")
        process = QProcess(self)
        self.model_process = process
        self.update_controls()
        process.finished.connect(self.models_finished)
        process.errorOccurred.connect(lambda error: self.models_finished(2) if error == QProcess.ProcessError.FailedToStart else None)
        process.start(sys.executable, [str(Path(__file__).resolve()), "--list-models", self.url_input.text().strip()])

    def models_finished(self, code, *_):
        process = self.model_process
        if process is None:
            return
        self.model_process = None
        try:
            if code != 0:
                raise ValueError(bytes(process.readAllStandardError()).decode("utf-8", errors="replace"))
            names = json.loads(bytes(process.readAllStandardOutput()))
            if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
                raise ValueError("Invalid local model list")
            selected = self.model.currentText()
            self.model.clear()
            self.model.addItems(names)
            if selected in names:
                self.model.setCurrentText(selected)
            self.model_status.setText(f"{len(names)} downloaded local model(s)." if names else "No downloaded models found. Use ollama list.")
        except (ValueError, TypeError) as exc:
            self.model_status.setText("Ollama unavailable. You can still scan without it.")
            self.activity.appendPlainText(str(exc))
        process.deleteLater()
        self.update_controls()

    def open_output(self):
        path = self.pdf_path or self.report_path
        if path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def closeEvent(self, event):
        # Only our own scanner/discovery processes are stopped, never Ollama.
        for process in (self.process, self.model_process):
            if process is not None and process.state() != QProcess.ProcessState.NotRunning:
                process.kill()
                process.waitForFinished(2000)
        event.accept()


def main(argv=None):
    parser = argparse.ArgumentParser(description="PQScan desktop evidence review")
    parser.add_argument("--repository", help="preselect a local repository")
    parser.add_argument("--report", type=Path, help="open an existing JSON report")
    args = parser.parse_args(argv)
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("PQScan")
    app.setStyle("Fusion")
    window = MainWindow(args.repository, args.report)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
