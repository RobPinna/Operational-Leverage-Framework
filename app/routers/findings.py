from urllib.parse import urlparse
import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Assessment, Evidence, Finding
from app.utils.jsonx import from_json

router = APIRouter(tags=["findings"])


def _assessment_context(assessment: Assessment) -> dict:
    return {
        "id": assessment.id,
        "company_name": assessment.company_name,
    }


def _latest_assessment_id(db: Session) -> int | None:
    latest = db.execute(select(Assessment.id).order_by(Assessment.updated_at.desc()).limit(1)).scalar_one_or_none()
    return int(latest) if latest is not None else None


def _is_web_url(value: str | None) -> bool:
    blocked_hosts = {"localhost", "example.com", "example.org", "example.net", "demo.invalid"}
    if not value:
        return False
    try:
        parsed = urlparse(value)
        host = parsed.netloc.lower().split(":")[0]
        if parsed.scheme not in {"http", "https"} or not host:
            return False
        if host in blocked_hosts:
            return False
        if host.endswith(".example") or host.endswith(".local") or host.endswith(".invalid"):
            return False
        return True
    except Exception:
        return False


def _severity_label(severity: int) -> str:
    if severity >= 4:
        return "high"
    if severity == 3:
        return "med"
    return "low"


def _confidence_label(confidence: int) -> str:
    if confidence >= 75:
        return "high"
    if confidence >= 50:
        return "med"
    return "low"


def _finding_bullets(row: Finding) -> dict[str, str]:
    enables_map = {
        "exposure": "Publicly observable channels, pages, or metadata expose reusable organizational signals.",
        "mention": "External narratives reference internal operations or trusted communication patterns.",
        "touchpoint": "Support, billing, onboarding, or customer-contact channels are externally discoverable.",
        "pivot": "Client-facing trust channels can be imitated to reach customers or partners.",
    }
    impacted_map = {
        "exposure": "Security, communications, and frontline teams validating inbound requests.",
        "mention": "Brand, legal, and operations teams managing public trust and escalation.",
        "touchpoint": "Support, finance, account-management, onboarding, and external contact stakeholders.",
        "pivot": "Customers, partners, beneficiaries, and shared-service helpdesks.",
    }
    why_map = {
        "exposure": "Signals can be combined into likely fraud scenarios and trust abuse patterns.",
        "mention": "Consistent public narratives can make fraudulent outreach look legitimate.",
        "touchpoint": "Known workflows can be abused to trigger unauthorized process actions.",
        "pivot": "Third-party trust in your brand can shift the blast radius beyond your perimeter.",
    }
    key = (row.type or "").strip().lower()
    return {
        "enables": enables_map.get(key, "Observed public evidence may support likely fraud scenarios."),
        "impacted": impacted_map.get(key, "Internal teams and external contacts relying on trust signals."),
        "matters": why_map.get(key, "Risk increases when evidence is consistent across multiple public sources."),
    }


def _defensive_actions_for_type(finding_type: str) -> list[str]:
    key = (finding_type or "").strip().lower()
    if key == "touchpoint":
        return [
            "Enforce callback verification for support and billing changes.",
            "Publish a single, signed list of official contact channels.",
            "Train frontline teams to reject urgent requests without secondary validation.",
        ]
    if key == "pivot":
        return [
            "Notify customers of approved domains and escalation paths.",
            "Add anti-impersonation checks to partner communication workflows.",
            "Create a public abuse-report channel with fast response SLAs.",
        ]
    if key == "mention":
        return [
            "Monitor repeated narratives and correct inaccurate public references.",
            "Standardize external statements for high-risk business processes.",
            "Escalate suspicious mentions to security and communications jointly.",
        ]
    return [
        "Reduce publicly exposed operational detail where not required.",
        "Harden verification for high-impact requests across teams.",
        "Document trusted channels and communicate them consistently.",
    ]


def _extract_reasoning_block(
    *,
    description: str,
    severity: int,
    confidence: int,
    evidence_count: int,
    bullets: dict[str, str],
) -> dict[str, str]:
    text = " ".join(str(description or "").split()).strip()
    lowered = text.lower()

    def _segment(start_label: str, end_label: str = "") -> str:
        start = lowered.find(start_label.lower())
        if start < 0:
            return ""
        start += len(start_label)
        if end_label:
            end = lowered.find(end_label.lower(), start)
            if end > start:
                return text[start:end].strip(" .")
        return text[start:].strip(" .")

    what_we_saw = _segment("What we saw:", "Why it matters:")
    why_it_matters = _segment("Why it matters:", "Why S")
    why_severity = ""
    m = re.search(r"(?i)(Why S\d:\s*)(.*?)(Scope boundary:|$)", text)
    if m:
        why_severity = str(m.group(2) or "").strip(" .")
    scope_boundary = _segment("Scope boundary:")

    if not what_we_saw:
        what_we_saw = f"{max(0, int(evidence_count or 0))} linked evidence items support this finding."
    if not why_it_matters:
        why_it_matters = bullets.get("matters", "")
    if not why_severity:
        why_severity = (
            f"S{int(severity or 3)} derived from evidence strength and impact estimate "
            f"(confidence {int(confidence or 0)}%)."
        )
    if not scope_boundary:
        scope_boundary = "This finding reflects exposure conditions from public evidence, not confirmed compromise."

    return {
        "what_we_saw": what_we_saw,
        "why_it_matters": why_it_matters,
        "why_severity": why_severity,
        "scope_boundary": scope_boundary,
    }


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


@router.get("/findings")
def findings_legacy_redirect(
    assessment_id: int | None = Query(default=None),
    tab: str = Query(default="all"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    target_id = assessment_id or _latest_assessment_id(db)
    if not target_id:
        return RedirectResponse(url="/assessments", status_code=302)
    return RedirectResponse(url=f"/assessments/{target_id}/findings?tab={tab}", status_code=302)


@router.get("/assessments/{assessment_id}/findings")
def findings_page(
    request: Request,
    assessment_id: int,
    tab: str = Query(default="all"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    rows = (
        db.execute(
            select(Finding)
            .where(Finding.assessment_id == assessment_id)
            .order_by(Finding.severity.desc(), Finding.confidence.desc())
        )
        .scalars()
        .all()
    )

    valid_tabs = ["all", "exposure", "mention", "touchpoint", "pivot"]
    selected_tab = tab if tab in valid_tabs else "all"
    filtered_rows = [row for row in rows if selected_tab == "all" or row.type == selected_tab]

    evidence_ids: set[int] = set()
    refs_by_finding: dict[int, list[int]] = {}
    for row in filtered_rows:
        refs = _normalize_refs(row.evidence_refs_json)
        refs_by_finding[row.id] = refs
        evidence_ids.update(refs)

    evidence_rows = (
        db.execute(select(Evidence).where(Evidence.id.in_(list(evidence_ids)))).scalars().all() if evidence_ids else []
    )
    evidence_map = {e.id: e for e in evidence_rows}

    cards: list[dict] = []
    for row in filtered_rows:
        refs = refs_by_finding.get(row.id, [])
        evidence_items = []
        web_count = 0
        for ev_id in refs:
            ev = evidence_map.get(ev_id)
            if not ev:
                continue
            is_web = _is_web_url(ev.source_url)
            if is_web:
                web_count += 1
            evidence_items.append(
                {
                    "id": ev.id,
                    "title": ev.title,
                    "snippet": (ev.snippet or "").strip(),
                    "connector": ev.connector,
                    "category": ev.category,
                    "confidence": ev.confidence,
                    "source_url": ev.source_url if is_web else "",
                    "source_ref": ev.source_url,
                }
            )

        assumptions = [
            "Evidence is limited to currently visible public artifacts.",
            "Observed channels may change without immediate public notice.",
        ]
        if row.confidence < 60:
            assumptions.append("Confidence is moderate/low and requires additional validation.")

        gaps = []
        if len(evidence_items) < 2:
            gaps.append("Insufficient corroborating evidence from independent sources.")
        if web_count == 0 and evidence_items:
            gaps.append("No direct verified web links available for attached evidence.")
        if not gaps:
            gaps.append("No critical evidence gaps detected for this finding.")

        bullets = _finding_bullets(row)
        reasoning = _extract_reasoning_block(
            description=(row.description or "").strip(),
            severity=row.severity,
            confidence=row.confidence,
            evidence_count=len(evidence_items),
            bullets=bullets,
        )
        cards.append(
            {
                "id": row.id,
                "type": row.type,
                "title": row.title,
                "description": (row.description or "").strip(),
                "severity": row.severity,
                "severity_label": _severity_label(row.severity),
                "confidence": row.confidence,
                "confidence_label": _confidence_label(row.confidence),
                "bullets": bullets,
                "reasoning": reasoning,
                "evidence": evidence_items,
                "assumptions": assumptions,
                "gaps": gaps,
                "defensive_actions": _defensive_actions_for_type(row.type),
            }
        )

    type_counts = {
        "exposure": len([x for x in rows if x.type == "exposure"]),
        "mention": len([x for x in rows if x.type == "mention"]),
        "touchpoint": len([x for x in rows if x.type == "touchpoint"]),
        "pivot": len([x for x in rows if x.type == "pivot"]),
    }

    return request.app.state.templates.TemplateResponse(
        "findings.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_findings",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment),
            "section_title": "Findings",
            "section_subtitle": "Prioritized evidence-first findings grouped by public information exposure, mentions, external contact channels, and risk to clients via impersonation.",
            "tab": selected_tab,
            "cards": cards,
            "type_counts": type_counts,
        },
    )


@router.get("/api/findings/{finding_id}/citations")
def finding_citations_api(
    finding_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    refs = _normalize_refs(finding.evidence_refs_json)
    evidence_rows = db.execute(select(Evidence).where(Evidence.id.in_(refs))).scalars().all() if refs else []
    evidence_map = {e.id: e for e in evidence_rows}

    ordered = []
    for ev_id in refs:
        ev = evidence_map.get(ev_id)
        if not ev:
            continue
        source_url = ev.source_url if _is_web_url(ev.source_url) else ""
        ordered.append(
            {
                "id": ev.id,
                "connector": ev.connector,
                "category": ev.category,
                "title": ev.title,
                "snippet": ev.snippet,
                "source_url": source_url,
                "source_ref": ev.source_url,
                "confidence": ev.confidence,
            }
        )

    return {
        "finding": {
            "id": finding.id,
            "title": finding.title,
            "type": finding.type,
            "severity": finding.severity,
            "confidence": finding.confidence,
        },
        "citations": ordered,
        "real_link_count": len([c for c in ordered if c.get("source_url")]),
        "total_count": len(ordered),
    }
