"""
Export Service for Mobile Analyzer
Handles PDF, CSV, and JSON export of reports
"""

import io
import csv
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, ListFlowable, ListItem
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from logger import get_logger

logger = get_logger(__name__)


class PDFExporter:
    """Export reports to PDF format"""

    # Color scheme
    COLORS = {
        "primary": colors.HexColor("#2563eb"),
        "critical": colors.HexColor("#dc2626"),
        "high": colors.HexColor("#ea580c"),
        "medium": colors.HexColor("#ca8a04"),
        "low": colors.HexColor("#16a34a"),
        "info": colors.HexColor("#6b7280"),
        "header_bg": colors.HexColor("#1e3a5f"),
        "row_alt": colors.HexColor("#f3f4f6"),
    }

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=self.COLORS["header_bg"],
            alignment=TA_CENTER
        ))

        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=self.COLORS["primary"],
            borderWidth=1,
            borderColor=self.COLORS["primary"],
            borderPadding=5
        ))

        self.styles.add(ParagraphStyle(
            name='SubSection',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceBefore=15,
            spaceAfter=8,
            textColor=self.COLORS["header_bg"]
        ))

        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6
        ))

        self.styles.add(ParagraphStyle(
            name='CodeSnippet',
            parent=self.styles['Code'],
            fontSize=8,
            backColor=colors.HexColor("#f5f5f5"),
            borderColor=colors.HexColor("#e0e0e0"),
            borderWidth=1,
            borderPadding=5,
            leftIndent=10,
            rightIndent=10
        ))

    def export(self, report: Dict[str, Any], findings: List[Dict[str, Any]]) -> bytes:
        """Export report to PDF bytes"""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50
        )

        story = []

        # Title
        story.append(Paragraph("Mobile Security Analysis Report", self.styles['ReportTitle']))
        story.append(Spacer(1, 20))

        # App Info Section
        story.extend(self._build_app_info_section(report))

        # Risk Score Section
        story.extend(self._build_risk_score_section(report))

        # Findings Summary
        story.extend(self._build_findings_summary(report))

        # Manifest Analysis
        if report.get("manifest_analysis"):
            story.extend(self._build_manifest_section(report["manifest_analysis"]))

        # Certificate Analysis
        if report.get("certificate_analysis"):
            story.extend(self._build_certificate_section(report["certificate_analysis"]))

        # Binary Analysis
        if report.get("binary_analysis"):
            story.extend(self._build_binary_section(report["binary_analysis"]))

        # Detailed Findings
        if findings:
            story.extend(self._build_findings_section(findings))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

    def _build_app_info_section(self, report: Dict) -> List:
        """Build app information section"""
        elements = []
        elements.append(Paragraph("Application Information", self.styles['SectionTitle']))

        data = [
            ["App Name", report.get("app_name", "N/A")],
            ["Package Name", report.get("package_name", "N/A")],
            ["Version", f"{report.get('version_name', 'N/A')} ({report.get('version_code', 'N/A')})"],
            ["Platform", report.get("platform", "android").upper()],
            ["File Name", report.get("file_name", "N/A")],
            ["File Size", self._format_size(report.get("file_size", 0))],
            ["MD5", report.get("md5_hash", "N/A")],
            ["SHA-256", report.get("sha256_hash", "N/A")[:32] + "..."],
            ["Analysis Date", report.get("created_at", "N/A")],
            ["Status", report.get("status", "N/A").upper()],
        ]

        table = Table(data, colWidths=[120, 350])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), self.COLORS["row_alt"]),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 20))
        return elements

    def _build_risk_score_section(self, report: Dict) -> List:
        """Build risk score visualization"""
        elements = []
        elements.append(Paragraph("Risk Assessment", self.styles['SectionTitle']))

        risk_score = report.get("risk_score", 0)
        risk_level = "Low" if risk_score < 30 else "Medium" if risk_score < 60 else "High" if risk_score < 80 else "Critical"

        color = self.COLORS["low"] if risk_score < 30 else \
            self.COLORS["medium"] if risk_score < 60 else \
            self.COLORS["high"] if risk_score < 80 else \
            self.COLORS["critical"]

        risk_text = f'<font size="18" color="{color.hexval()}">{risk_score}/100</font> - {risk_level} Risk'
        elements.append(Paragraph(risk_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 20))

        return elements

    def _build_findings_summary(self, report: Dict) -> List:
        """Build findings summary table"""
        elements = []
        elements.append(Paragraph("Findings Summary", self.styles['SectionTitle']))

        summary = report.get("findings_summary", {})
        if isinstance(summary, str):
            try:
                summary = json.loads(summary)
            except:
                summary = {}

        data = [
            ["Severity", "Count"],
            ["Critical", str(summary.get("critical", 0))],
            ["High", str(summary.get("high", 0))],
            ["Medium", str(summary.get("medium", 0))],
            ["Low", str(summary.get("low", 0))],
            ["Info", str(summary.get("info", 0))],
            ["Total", str(summary.get("total", 0))],
        ]

        table = Table(data, colWidths=[150, 100])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS["header_bg"]),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 1), (0, 1), self.COLORS["critical"]),
            ('BACKGROUND', (0, 2), (0, 2), self.COLORS["high"]),
            ('BACKGROUND', (0, 3), (0, 3), self.COLORS["medium"]),
            ('BACKGROUND', (0, 4), (0, 4), self.COLORS["low"]),
            ('BACKGROUND', (0, 5), (0, 5), self.COLORS["info"]),
            ('TEXTCOLOR', (0, 1), (0, 5), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(table)
        elements.append(Spacer(1, 20))
        return elements

    def _build_manifest_section(self, manifest: Dict) -> List:
        """Build manifest analysis section"""
        elements = []
        elements.append(Paragraph("Manifest Analysis", self.styles['SectionTitle']))

        # Security flags
        flags_data = [
            ["Security Flag", "Status"],
            ["Debuggable", "YES (Risk!)" if manifest.get("is_debuggable") else "No"],
            ["Allows Backup", "YES (Risk!)" if manifest.get("allows_backup") else "No"],
            ["Cleartext Traffic", "YES (Risk!)" if manifest.get("uses_cleartext_traffic") else "No"],
        ]

        table = Table(flags_data, colWidths=[150, 150])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS["header_bg"]),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 15))

        # Permissions
        permissions = manifest.get("permissions", [])
        if permissions:
            elements.append(Paragraph("Permissions", self.styles['SubSection']))
            dangerous = [p for p in permissions if isinstance(p, dict) and p.get("is_dangerous")]
            if dangerous:
                elements.append(Paragraph(f"<b>Dangerous Permissions ({len(dangerous)}):</b>", self.styles['CustomBody']))
                for perm in dangerous[:10]:  # Limit to 10
                    name = perm.get("name", "").split(".")[-1]
                    elements.append(Paragraph(f"• {name}", self.styles['CustomBody']))

        elements.append(Spacer(1, 15))
        return elements

    def _build_certificate_section(self, cert: Dict) -> List:
        """Build certificate analysis section"""
        elements = []
        elements.append(Paragraph("Certificate Analysis", self.styles['SectionTitle']))

        issues = []
        if cert.get("is_debug_signed"):
            issues.append("Debug certificate detected")
        if cert.get("is_expired"):
            issues.append("Certificate expired")
        if cert.get("is_self_signed"):
            issues.append("Self-signed certificate")

        if issues:
            elements.append(Paragraph("<b>Certificate Issues:</b>", self.styles['CustomBody']))
            for issue in issues:
                elements.append(Paragraph(f"• {issue}", self.styles['CustomBody']))
        else:
            elements.append(Paragraph("No certificate issues detected.", self.styles['CustomBody']))

        elements.append(Spacer(1, 15))
        return elements

    def _build_binary_section(self, binary: Dict) -> List:
        """Build binary analysis section"""
        elements = []
        elements.append(Paragraph("Binary Analysis", self.styles['SectionTitle']))

        info_data = [
            ["Property", "Value"],
            ["APK Size", self._format_size(binary.get("apk_size", 0))],
            ["DEX Files", str(binary.get("dex_count", 0))],
            ["Architectures", ", ".join(binary.get("architectures", []))],
            ["Native Libraries", str(len(binary.get("native_libraries", [])))],
        ]

        table = Table(info_data, colWidths=[150, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS["header_bg"]),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 15))
        return elements

    def _build_findings_section(self, findings: List[Dict]) -> List:
        """Build detailed findings section"""
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Findings", self.styles['SectionTitle']))

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev not in grouped:
                grouped[sev] = []
            grouped[sev].append(f)

        for severity in severity_order:
            if severity not in grouped:
                continue

            color = self.COLORS.get(severity, self.COLORS["info"])
            elements.append(Paragraph(
                f'<font color="{color.hexval()}">{severity.upper()} ({len(grouped[severity])})</font>',
                self.styles['SubSection']
            ))

            for i, finding in enumerate(grouped[severity][:20], 1):  # Limit per severity
                elements.append(Paragraph(f"<b>{i}. {finding.get('title', 'N/A')}</b>", self.styles['CustomBody']))
                elements.append(Paragraph(finding.get("description", "")[:500], self.styles['CustomBody']))

                if finding.get("file_path"):
                    elements.append(Paragraph(
                        f"<i>Location: {finding['file_path']}:{finding.get('line_number', '')}</i>",
                        self.styles['CustomBody']
                    ))

                if finding.get("recommendation"):
                    elements.append(Paragraph(
                        f"<b>Recommendation:</b> {finding['recommendation'][:300]}",
                        self.styles['CustomBody']
                    ))

                if finding.get("cwe_id"):
                    elements.append(Paragraph(f"CWE: {finding['cwe_id']}", self.styles['CustomBody']))

                elements.append(Spacer(1, 10))

        return elements

    def _format_size(self, size: int) -> str:
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"


class CSVExporter:
    """Export findings to CSV format"""

    def export_findings(self, findings: List[Dict[str, Any]]) -> bytes:
        """Export findings to CSV bytes"""
        buffer = io.StringIO()
        writer = csv.writer(buffer)

        # Header
        headers = [
            "ID", "Type", "Severity", "Title", "Description",
            "File Path", "Line Number", "Code Snippet",
            "Recommendation", "CWE ID", "OWASP Category"
        ]
        writer.writerow(headers)

        # Data
        for finding in findings:
            writer.writerow([
                finding.get("id", ""),
                finding.get("type", ""),
                finding.get("severity", ""),
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("file_path", ""),
                finding.get("line_number", ""),
                finding.get("code_snippet", "")[:500] if finding.get("code_snippet") else "",
                finding.get("recommendation", ""),
                finding.get("cwe_id", ""),
                finding.get("owasp_category", "")
            ])

        return buffer.getvalue().encode('utf-8')

    def export_report_summary(self, report: Dict[str, Any]) -> bytes:
        """Export report summary to CSV"""
        buffer = io.StringIO()
        writer = csv.writer(buffer)

        # Key-value pairs
        writer.writerow(["Property", "Value"])
        writer.writerow(["App Name", report.get("app_name", "")])
        writer.writerow(["Package Name", report.get("package_name", "")])
        writer.writerow(["Version", report.get("version_name", "")])
        writer.writerow(["Platform", report.get("platform", "")])
        writer.writerow(["Risk Score", report.get("risk_score", 0)])
        writer.writerow(["Status", report.get("status", "")])
        writer.writerow(["MD5", report.get("md5_hash", "")])
        writer.writerow(["SHA-256", report.get("sha256_hash", "")])
        writer.writerow(["Analysis Date", report.get("created_at", "")])

        # Findings summary
        summary = report.get("findings_summary", {})
        if isinstance(summary, str):
            try:
                summary = json.loads(summary)
            except:
                summary = {}

        writer.writerow([])
        writer.writerow(["Findings Summary", ""])
        writer.writerow(["Critical", summary.get("critical", 0)])
        writer.writerow(["High", summary.get("high", 0)])
        writer.writerow(["Medium", summary.get("medium", 0)])
        writer.writerow(["Low", summary.get("low", 0)])
        writer.writerow(["Info", summary.get("info", 0)])
        writer.writerow(["Total", summary.get("total", 0)])

        return buffer.getvalue().encode('utf-8')


class JSONExporter:
    """Export reports to JSON format"""

    def export(self, report: Dict[str, Any], findings: List[Dict[str, Any]]) -> bytes:
        """Export full report to JSON"""
        export_data = {
            "export_date": datetime.utcnow().isoformat(),
            "report": {
                "id": report.get("id"),
                "app_name": report.get("app_name"),
                "package_name": report.get("package_name"),
                "version_name": report.get("version_name"),
                "version_code": report.get("version_code"),
                "platform": report.get("platform"),
                "file_name": report.get("file_name"),
                "file_size": report.get("file_size"),
                "hashes": {
                    "md5": report.get("md5_hash"),
                    "sha1": report.get("sha1_hash"),
                    "sha256": report.get("sha256_hash")
                },
                "risk_score": report.get("risk_score"),
                "status": report.get("status"),
                "created_at": report.get("created_at"),
                "completed_at": report.get("completed_at"),
            },
            "analysis": {
                "manifest": report.get("manifest_analysis"),
                "certificate": report.get("certificate_analysis"),
                "binary": report.get("binary_analysis"),
                "code": report.get("code_analysis"),
            },
            "findings_summary": report.get("findings_summary"),
            "findings": findings
        }

        return json.dumps(export_data, indent=2, default=str).encode('utf-8')


# Export service instance
pdf_exporter = PDFExporter()
csv_exporter = CSVExporter()
json_exporter = JSONExporter()
