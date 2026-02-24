from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Assessment, CrossSignalCorrelation, Evidence
from app.utils.jsonx import from_json

router = APIRouter(tags=["correlations"])


def _assessment_context(assessment: Assessment) -> dict:
    return {
        "id": assessment.id,
        "company_name": assessment.company_name,
    }


def _latest_assessment_id(db: Session) -> int | None:
    latest = db.execute(select(Assessment.id).order_by(Assessment.updated_at.desc()).limit(1)).scalar_one_or_none()
    return int(latest) if latest is not None else None


def _risk_label(risk_level: int) -> str:
    if risk_level >= 5:
        return "critical"
    if risk_level >= 4:
        return "high"
    if risk_level == 3:
        return "med"
    return "low"


@router.get("/correlations")
def correlations_legacy_redirect(
    assessment_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    target_id = assessment_id or _latest_assessment_id(db)
    if not target_id:
        return RedirectResponse(url="/assessments", status_code=302)
    return RedirectResponse(url=f"/assessments/{target_id}/correlations", status_code=302)


@router.get("/assessments/{assessment_id}/correlations")
def correlations_page(
    request: Request,
    assessment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    rows = (
        db.execute(
            select(CrossSignalCorrelation)
            .where(CrossSignalCorrelation.assessment_id == assessment_id)
            .order_by(CrossSignalCorrelation.risk_level.desc(), CrossSignalCorrelation.created_at.desc())
        )
        .scalars()
        .all()
    )

    evidence_ids: set[int] = set()
    refs_by_corr: dict[int, list[int]] = {}
    for row in rows:
        refs = [int(x) for x in from_json(row.evidence_refs_json, []) if str(x).isdigit()]
        refs_by_corr[row.id] = refs
        evidence_ids.update(refs)

    evidence_map = {}
    if evidence_ids:
        ev_rows = db.execute(select(Evidence).where(Evidence.id.in_(list(evidence_ids)))).scalars().all()
        evidence_map = {e.id: e for e in ev_rows}

    cards: list[dict] = []
    for row in rows:
        evidence_items: list[dict] = []
        for ev_id in refs_by_corr.get(row.id, []):
            ev = evidence_map.get(ev_id)
            if not ev:
                continue
            evidence_items.append(
                {
                    "id": ev.id,
                    "title": ev.title,
                    "snippet": ev.snippet,
                    "source_url": ev.source_url,
                    "connector": ev.connector,
                    "confidence": ev.confidence,
                }
            )
        cards.append(
            {
                "id": row.id,
                "title": row.title,
                "summary": row.summary,
                "risk_level": row.risk_level,
                "risk_label": _risk_label(row.risk_level),
                "signals": [x for x in from_json(row.signals_json, []) if str(x).strip()],
                "evidence": evidence_items,
            }
        )

    return request.app.state.templates.TemplateResponse(
        "correlations.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_correlations",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment),
            "section_title": "Cross-Signal Correlation",
            "section_subtitle": "Synthesized risk correlations across job postings, DNS/subdomains, web vendors, media trend, and procurement documents.",
            "cards": cards,
        },
    )
