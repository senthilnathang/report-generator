from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak,
)


class PdfReporter:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: list, name: str = "vulnerability_report") -> str:
        out_path = self.output_dir / f"{name}.pdf"
        doc = SimpleDocTemplate(
            str(out_path),
            pagesize=landscape(A4),
            rightMargin=20*mm, leftMargin=20*mm,
            topMargin=20*mm, bottomMargin=20*mm,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ReportTitle", parent=styles["Title"], fontSize=20, spaceAfter=20,
        )

        elements = []
        elements.append(Paragraph(f"Vulnerability Scan Report", title_style))
        elements.append(Spacer(1, 10*mm))

        summary_data = [["Repository", "Scanner", "Crit", "High", "Med", "Low", "Total"]]
        for r in results:
            s = r.summary
            summary_data.append([
                r.repo, r.scanner,
                s["CRITICAL"], s["HIGH"], s["MEDIUM"], s["LOW"],
                len(r.vulnerabilities),
            ])

        summary_table = Table(summary_data, colWidths=[80, 50, 30, 30, 30, 30, 40])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2F5496")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (2, 0), (-1, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 10*mm))

        elements.append(Paragraph("Detailed Findings", styles["Heading2"]))
        elements.append(Spacer(1, 5*mm))

        detail_data = [["Repo", "Scanner", "CVE", "Package", "Installed", "Fixed", "Sev", "Type"]]
        for r in results:
            for v in r.vulnerabilities:
                detail_data.append([
                    r.repo, r.scanner, v.id, v.package,
                    v.installed_version, v.fixed_version or "N/A",
                    v.severity.upper(), v.type,
                ])

        detail_table = Table(detail_data, colWidths=[55, 35, 55, 50, 35, 35, 25, 40])
        detail_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2F5496")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 6),
            ("ALIGN", (6, 0), (6, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
        ]))
        elements.append(detail_table)

        doc.build(elements)
        return str(out_path)
