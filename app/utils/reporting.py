from __future__ import annotations

from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from app.config import get_settings
from app.models import Assessment, Evidence, Finding, Mitigation
from app.utils.jsonx import from_json


EXPORT_DIR = get_settings().runtime_dir / "exports"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)


def _kpi_rows(evidences: list[Evidence], findings: list[Finding], mitigations: list[Mitigation]) -> list[list[str]]:
    pivot_count = len([f for f in findings if f.type == "pivot"])
    high_findings = len([f for f in findings if f.severity >= 4])
    return [
        ["KPI", "Value"],
        ["Evidence Collected", str(len(evidences))],
        ["Findings", str(len(findings))],
        ["High Severity (4-5)", str(high_findings)],
        ["Risk to Clients via Impersonation", str(pivot_count)],
        ["Risk Reduction Actions", str(len(mitigations))],
    ]


def render_assessment_pdf(
    assessment: Assessment,
    evidences: list[Evidence],
    findings: list[Finding],
    mitigations: list[Mitigation],
) -> Path:
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    pdf_path = EXPORT_DIR / f"assessment_{assessment.id}_{stamp}.pdf"

    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4, leftMargin=28, rightMargin=28, topMargin=24)
    styles = getSampleStyleSheet()

    story = []
    story.append(Paragraph(f"ExposureMapper TI Report - {assessment.company_name}", styles["Title"]))
    story.append(Paragraph(f"Domain: {assessment.domain} | Sector: {assessment.sector}", styles["Normal"]))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()} UTC", styles["Normal"]))
    story.append(Spacer(1, 10))

    kpi_table = Table(_kpi_rows(evidences, findings, mitigations), hAlign="LEFT")
    kpi_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
            ]
        )
    )
    story.append(kpi_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Top 5 Findings", styles["Heading2"]))
    for f in sorted(findings, key=lambda x: x.severity, reverse=True)[:5]:
        story.append(
            Paragraph(
                f"[S{f.severity}] {f.title} - {f.description}",
                styles["BodyText"],
            )
        )

    story.append(Spacer(1, 8))
    story.append(Paragraph("Top 5 Risk Reduction Actions", styles["Heading2"]))
    for m in sorted(mitigations, key=lambda x: x.priority)[:5]:
        story.append(
            Paragraph(
                f"[P{m.priority}/{m.effort}] {m.owner}: {m.description}",
                styles["BodyText"],
            )
        )

    pivots = [f for f in findings if f.type == "pivot"]
    story.append(Spacer(1, 8))
    story.append(Paragraph("Risk to Clients via Impersonation Highlight", styles["Heading2"]))
    if pivots:
        for p in pivots[:3]:
            story.append(Paragraph(f"- {p.title} (confidence {p.confidence}%)", styles["BodyText"]))
    else:
        story.append(Paragraph("No direct client impersonation-risk signal above threshold.", styles["BodyText"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Annex: Evidence (max 20)", styles["Heading2"]))
    for ev in evidences[:20]:
        story.append(
            Paragraph(
                f"[{ev.connector}] {ev.title} | confidence {ev.confidence}% | {ev.source_url}",
                styles["BodyText"],
            )
        )

    assumptions = from_json(assessment.assumptions_json, [])
    story.append(Spacer(1, 10))
    story.append(Paragraph("Assumptions", styles["Heading2"]))
    for item in assumptions:
        story.append(Paragraph(f"- {item}", styles["BodyText"]))

    doc.build(story)
    return pdf_path
