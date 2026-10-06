"""Supreme Shoggoth defensive security center.

An unofficial federal-investigative visual stack focused on local integrity,
privacy, chain-of-custody, auditability, and human-approved security actions.
"""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel,
    QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from shoggoth.security_layer import (
    build_evidence_manifest,
    inspect_directory,
    posture_label,
    redact_sensitive_text,
    write_manifest,
)
from shoggoth.supreme import build_diagnostic_snapshot, governance_gate, tev_check


STYLE = """
QDialog {
    background: #020608;
    color: #dff9ff;
}
QLabel#Title {
    color: #5fe3ff;
    font-size: 22px;
    font-weight: 800;
    letter-spacing: 1px;
}
QLabel#Subtitle {
    color: #7fa7b5;
    font-size: 10px;
}
QFrame#Card {
    background: #06131a;
    border: 1px solid #164f66;
    border-radius: 6px;
}
QLabel#Metric {
    color: #62e6ff;
    font-size: 24px;
    font-weight: 800;
}
QLabel#MetricLabel {
    color: #83aab8;
    font-size: 9px;
}
QPushButton {
    background: #071b24;
    color: #dff9ff;
    border: 1px solid #1b6682;
    border-radius: 4px;
    padding: 8px 10px;
    text-align: left;
}
QPushButton:hover {
    border-color: #58ddff;
    color: #58ddff;
    background: #0a2733;
}
QPlainTextEdit {
    background: #030b0f;
    color: #c8f6ff;
    border: 1px solid #164f66;
    selection-background-color: #164f66;
    font-family: Menlo, Consolas, monospace;
    font-size: 10px;
}
"""


class SecurityCenterDialog(QDialog):
    """Read-only defensive security center with explicit export actions."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Supreme Shoggoth // Federal Security Layer")
        self.resize(1120, 760)
        self.setStyleSheet(STYLE)
        self._last_scan = None
        self._build_ui()
        self._set_banner("READY // LOCAL-ONLY DEFENSIVE MODE")

    def _metric_card(self, label: str, value: str) -> tuple[QFrame, QLabel]:
        frame = QFrame()
        frame.setObjectName("Card")
        layout = QVBoxLayout(frame)
        value_label = QLabel(value)
        value_label.setObjectName("Metric")
        caption = QLabel(label)
        caption.setObjectName("MetricLabel")
        layout.addWidget(value_label)
        layout.addWidget(caption)
        return frame, value_label

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(10)

        top = QHBoxLayout()
        title_wrap = QVBoxLayout()
        title = QLabel("🛡 SUPREME SHOGGOTH // FEDERAL SECURITY LAYER")
        title.setObjectName("Title")
        subtitle = QLabel(
            "UNOFFICIAL DEFENSIVE PROTOTYPE • INTEGRITY • PRIVACY • CHAIN OF CUSTODY • AUDIT • HUMAN-FIRST"
        )
        subtitle.setObjectName("Subtitle")
        title_wrap.addWidget(title)
        title_wrap.addWidget(subtitle)
        top.addLayout(title_wrap, 1)

        self.banner = QLabel()
        self.banner.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.banner.setStyleSheet("color:#5bff9d;font-weight:700;")
        top.addWidget(self.banner)
        root.addLayout(top)

        metrics = QGridLayout()
        card, self.score_metric = self._metric_card("SECURITY POSTURE", "—")
        metrics.addWidget(card, 0, 0)
        card, self.files_metric = self._metric_card("FILES VERIFIED", "0")
        metrics.addWidget(card, 0, 1)
        card, self.high_metric = self._metric_card("HIGH FINDINGS", "0")
        metrics.addWidget(card, 0, 2)
        card, self.medium_metric = self._metric_card("MEDIUM FINDINGS", "0")
        metrics.addWidget(card, 0, 3)
        card, self.low_metric = self._metric_card("LOW FINDINGS", "0")
        metrics.addWidget(card, 0, 4)
        root.addLayout(metrics)

        body = QHBoxLayout()
        controls = QVBoxLayout()
        controls.setSpacing(5)

        self.scan_button = QPushButton("◉ SELECT + SCAN FOLDER")
        self.package_button = QPushButton("⬡ VERIFY SHOGGOTH PACKAGE")
        self.governance_button = QPushButton("◇ RUN GOVERNANCE / TEVV")
        self.manifest_button = QPushButton("▣ EXPORT SHA-256 EVIDENCE MANIFEST")
        self.copy_button = QPushButton("⌁ COPY REDACTED SECURITY REPORT")
        self.clear_button = QPushButton("× CLEAR SESSION")

        for button in (
            self.scan_button, self.package_button, self.governance_button,
            self.manifest_button, self.copy_button, self.clear_button,
        ):
            controls.addWidget(button)

        controls.addSpacing(8)
        policy = QLabel(
            "SECURITY POLICY\n"
            "• Local-first inspection\n"
            "• Read-only scanning\n"
            "• SHA-256 integrity records\n"
            "• Secret-exposure warnings\n"
            "• Human approval for mutations\n"
            "• Telemetry remains opt-in\n"
            "• No remote exploitation or surveillance"
        )
        policy.setStyleSheet(
            "color:#8db3c0;background:#06131a;border:1px solid #164f66;"
            "border-radius:6px;padding:10px;"
        )
        controls.addWidget(policy)
        controls.addStretch(1)

        controls_widget = QWidget()
        controls_widget.setLayout(controls)
        controls_widget.setMaximumWidth(315)
        body.addWidget(controls_widget)

        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        self.console.setPlainText(
            "SUPREME SHOGGOTH SECURITY CENTER\n"
            "Select a folder or verify the installed Shoggoth package.\n"
            "All scans are local and read-only.\n"
        )
        body.addWidget(self.console, 1)
        root.addLayout(body, 1)

        self.scan_button.clicked.connect(self._scan_folder)
        self.package_button.clicked.connect(self._scan_package)
        self.governance_button.clicked.connect(self._governance_check)
        self.manifest_button.clicked.connect(self._export_manifest)
        self.copy_button.clicked.connect(self._copy_redacted_report)
        self.clear_button.clicked.connect(self._clear)

    def _set_banner(self, text: str, color: str = "#5bff9d"):
        self.banner.setText(text)
        self.banner.setStyleSheet(f"color:{color};font-weight:700;")

    def _scan_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select folder for local security verification")
        if folder:
            self._run_scan(Path(folder))

    def _scan_package(self):
        package_root = Path(__file__).resolve().parents[1]
        self._run_scan(package_root)

    def _run_scan(self, root: Path):
        self._set_banner("SCANNING // READ-ONLY", "#ffd45e")
        self.console.setPlainText(f"Scanning {root}\n")
        try:
            scan = inspect_directory(root)
        except Exception as exc:
            self._set_banner("SCAN ERROR", "#ff6b6b")
            QMessageBox.warning(self, "Security scan failed", str(exc))
            return

        self._last_scan = scan
        counts = scan["severity_counts"]
        score = scan["posture_score"]
        self.score_metric.setText(f"{score} / 100")
        self.files_metric.setText(str(scan["files_scanned"]))
        self.high_metric.setText(str(counts["high"]))
        self.medium_metric.setText(str(counts["medium"]))
        self.low_metric.setText(str(counts["low"]))

        lines = [
            "SUPREME SHOGGOTH // SECURITY VERIFICATION",
            f"ROOT: {scan['root']}",
            f"FILES: {scan['files_scanned']}",
            f"POSTURE: {score}/100 // {posture_label(score)}",
            "",
            "FINDINGS:",
        ]
        if not scan["findings"]:
            lines.append("  [PASS] No findings in the bounded inspection.")
        for item in scan["findings"]:
            lines.append(
                f"  [{item['severity'].upper()}] {item['category']} :: "
                f"{item['path']} :: {item['message']}"
            )
        lines.extend([
            "",
            "CONTROL PLANE:",
            "  OBSERVE -> VERIFY -> TEVV -> HUMAN GATE -> APPLY -> AUDIT",
            "  Mutation authority: HUMAN-FIRST",
            "  Network actions: explicit only",
        ])
        self.console.setPlainText("\n".join(lines))
        color = "#5bff9d" if score >= 75 else "#ffd45e" if score >= 55 else "#ff6b6b"
        self._set_banner(f"{posture_label(score)} // SCORE {score}", color)

    def _governance_check(self):
        telemetry_level = None
        try:
            telemetry_level = self.parent().config.get("Shoggoth", "telemetry_level", "off")
        except Exception:
            telemetry_level = "off"

        snapshot = build_diagnostic_snapshot(
            project_name=getattr(getattr(self.parent(), "active_project", None), "name", None),
            card_count=None,
            telemetry_level=telemetry_level,
            plugin_count=None,
            export_ready=None,
        )
        tev = tev_check(snapshot)
        gate = governance_gate("run_diagnostics")
        report = {
            "governance_gate": {
                "allowed": gate.allowed,
                "reason": gate.reason,
                "requires_human_approval": gate.requires_human_approval,
            },
            "tev": tev,
            "snapshot": snapshot,
        }
        self.console.appendPlainText("\n\nGOVERNANCE / TEVV\n" + json.dumps(report, indent=2))
        self._set_banner("TEVV PASS" if tev["passed"] else "TEVV REVIEW", "#5bff9d" if tev["passed"] else "#ffd45e")

    def _export_manifest(self):
        if not self._last_scan:
            QMessageBox.information(self, "No scan", "Run a security scan first.")
            return
        destination, _ = QFileDialog.getSaveFileName(
            self, "Export evidence manifest", "supreme-shoggoth-evidence.json", "JSON (*.json)"
        )
        if not destination:
            return
        path = write_manifest(build_evidence_manifest(self._last_scan), destination)
        self.console.appendPlainText(f"\nMANIFEST EXPORTED: {path}")
        self._set_banner("EVIDENCE MANIFEST WRITTEN")

    def _copy_redacted_report(self):
        from PySide6.QtWidgets import QApplication
        text = redact_sensitive_text(self.console.toPlainText())
        QApplication.clipboard().setText(text)
        self._set_banner("REDACTED REPORT COPIED")

    def _clear(self):
        self._last_scan = None
        self.score_metric.setText("—")
        self.files_metric.setText("0")
        self.high_metric.setText("0")
        self.medium_metric.setText("0")
        self.low_metric.setText("0")
        self.console.setPlainText("Security session cleared. No files were modified.")
        self._set_banner("READY // LOCAL-ONLY DEFENSIVE MODE")


def open_security_center(window):
    dialog = SecurityCenterDialog(window)
    dialog.setAttribute(Qt.WA_DeleteOnClose, True)
    window._supreme_security_center = dialog
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()
