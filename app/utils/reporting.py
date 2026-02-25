from __future__ import annotations

from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

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


def _normalize_refs(raw_json: str) -> list[int]:
    refs: list[int] = []
    for item in from_json(raw_json, []):
        if str(item).isdigit():
            refs.append(int(item))
            continue
        if isinstance(item, dict):
            cand = item.get("evidence_id") or item.get("id")
            if str(cand).isdigit():
                refs.append(int(cand))
    seen: set[int] = set()
    ordered: list[int] = []
    for value in refs:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _chain_template(finding_type: str) -> dict[str, str]:
    key = (finding_type or "").strip().lower()
    if key == "exposure":
        return {
            "inference": "Public organizational cues can be assembled into targeted reconnaissance.",
            "risk": "Higher success probability for social-engineering pretexts.",
            "boundary": "Exposure conditions observed; no active exploitation confirmed above threshold.",
        }
    if key == "mention":
        return {
            "inference": "Narrative alignment allows attackers to mimic trusted language and timing.",
            "risk": "Increased credibility of malicious outreach.",
            "boundary": "Narrative pressure detected; no coordinated campaign attribution performed.",
        }
    if key == "touchpoint":
        return {
            "inference": "Multiple contact paths create official-channel ambiguity.",
            "risk": "Conversation insertion into support, billing, or onboarding workflows.",
            "boundary": "Trust-friction weakness observed; no direct compromise telemetry in scope.",
        }
    if key == "pivot":
        return {
            "inference": "Trust in brand/channel can be leveraged to target third parties.",
            "risk": "Client/partner impersonation with potential downstream process abuse.",
            "boundary": "Assessment identifies preconditions and blast radius, not victim confirmation.",
        }
    return {
        "inference": "Independent signals converge on a plausible abuse pattern.",
        "risk": "Trust-heavy workflows may be exploitable without added controls.",
        "boundary": "Open-source signal assessment only; internal telemetry not included.",
    }


def _is_web_url(value: str | None) -> bool:
    if not value:
        return False
    try:
        parsed = urlparse(value)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


def _compact(text: str, limit: int = 120) -> str:
    raw = " ".join((text or "").strip().split())
    if len(raw) <= limit:
        return raw
    return f"{raw[: max(0, limit - 3)]}..."


def _what_we_saw_line(finding: Finding, evidence_rows: list[Evidence]) -> str:
    count = len(evidence_rows)
    if not evidence_rows:
        return f"{finding.title}: no linked evidence rows were attached to this finding."
    connectors = sorted({str(e.connector or "").strip() for e in evidence_rows if str(e.connector or "").strip()})
    connector_label = ", ".join(connectors[:3]) if connectors else "mixed connectors"
    snippets = [_compact(e.snippet or e.title, 90) for e in evidence_rows[:2] if (e.snippet or e.title)]
    if snippets:
        sample = " | ".join(snippets)
        return f"{count} linked evidence items from {connector_label}. Sample signals: {sample}"
    return f"{count} linked evidence items from {connector_label}."


def _severity_why_line(finding: Finding, evidence_count: int) -> str:
    sev = max(1, min(5, int(finding.severity or 3)))
    conf = max(1, min(100, int(finding.confidence or 0)))
    if sev >= 4:
        impact = "material operational/trust impact if exploited"
    elif sev == 3:
        impact = "meaningful but bounded business impact"
    else:
        impact = "contained impact unless combined with additional signals"
    if conf >= 75:
        likelihood = "high"
    elif conf >= 50:
        likelihood = "medium"
    else:
        likelihood = "low-to-medium"
    return (
        f"S{sev}: likelihood {likelihood} ({conf}% confidence, {evidence_count} corroborating references) + {impact}."
    )


def _effort_window(effort: str) -> str:
    key = (effort or "").strip().upper()
    if key == "S":
        return "execution target: 1-2 weeks"
    if key == "M":
        return "execution target: 2-6 weeks"
    if key == "L":
        return "execution target: 6+ weeks"
    return "execution target: planned sprint cadence"


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

    evidence_map = {e.id: e for e in evidences}
    sorted_findings = sorted(findings, key=lambda x: (x.severity, x.confidence), reverse=True)[:5]

    story.append(Paragraph("Top Findings (Evidence -> Inference -> Risk)", styles["Heading2"]))
    for f in sorted_findings:
        refs = _normalize_refs(f.evidence_refs_json)
        linked_evidence = [evidence_map[ev_id] for ev_id in refs if ev_id in evidence_map][:8]
        chain = _chain_template(f.type)

        story.append(Paragraph(f"[S{f.severity}] {f.title} (confidence {f.confidence}%)", styles["Heading3"]))
        story.append(Paragraph(f"<b>What we saw:</b> {_what_we_saw_line(f, linked_evidence)}", styles["BodyText"]))
        story.append(Paragraph(f"<b>Why it matters:</b> {chain['risk']}", styles["BodyText"]))
        story.append(Paragraph(f"<b>Why S{f.severity}:</b> {_severity_why_line(f, len(refs))}", styles["BodyText"]))
        story.append(Paragraph(f"<b>Scope boundary:</b> {chain['boundary']}", styles["BodyText"]))

        table = Table(
            [
                ["Evidence", "Inference", "Risk conclusion"],
                [
                    _what_we_saw_line(f, linked_evidence),
                    chain["inference"],
                    f.title,
                ],
            ],
            hAlign="LEFT",
            colWidths=[165, 165, 165],
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)

        citations = []
        for ev in linked_evidence[:3]:
            source = ev.source_url if _is_web_url(ev.source_url) else ""
            if not source:
                continue
            citations.append(f"{ev.title} ({source})")
        if citations:
            story.append(Paragraph(f"<b>Linked sources:</b> {'; '.join(citations)}", styles["BodyText"]))
        story.append(Spacer(1, 8))

    story.append(Spacer(1, 4))
    story.append(Paragraph("Risk Reduction Actions (Top 5)", styles["Heading2"]))
    finding_map = {f.id: f for f in findings}
    for m in sorted(mitigations, key=lambda x: x.priority)[:5]:
        linked_ids = [x for x in from_json(m.linked_findings_json, []) if str(x).isdigit()]
        linked_titles = [finding_map[int(fid)].title for fid in linked_ids if int(fid) in finding_map]
        story.append(
            Paragraph(
                f"[P{m.priority}/{m.effort}] {m.owner}: {m.description}",
                styles["BodyText"],
            )
        )
        if linked_titles:
            story.append(Paragraph(f"Linked findings: {', '.join(linked_titles[:3])}", styles["BodyText"]))
        story.append(Paragraph(_effort_window(m.effort), styles["BodyText"]))
        story.append(Spacer(1, 4))

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

    story.append(Spacer(1, 8))
    story.append(Paragraph("Assessment Boundaries", styles["Heading2"]))
    story.append(
        Paragraph(
            "- This report describes exposure and abuse preconditions from public evidence, not confirmed incidents.",
            styles["BodyText"],
        )
    )
    story.append(
        Paragraph(
            "- Internal controls, ticketing data, and SOC telemetry are outside current collection scope unless provided.",
            styles["BodyText"],
        )
    )

    doc.build(story)
    return pdf_path
