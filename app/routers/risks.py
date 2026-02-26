from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Assessment
from app.services.risk_story import build_risk_detail_viewmodel, get_risks_by_status

router = APIRouter(tags=["risks"])


def _assessment_context(assessment: Assessment) -> dict:
    return {"id": assessment.id, "company_name": assessment.company_name}


def _latest_assessment_id(db: Session) -> int | None:
    latest = db.execute(select(Assessment.id).order_by(Assessment.updated_at.desc()).limit(1)).scalar_one_or_none()
    return int(latest) if latest is not None else None


@router.get("/risks")
def risks_root(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    latest = _latest_assessment_id(db)
    if not latest:
        return RedirectResponse(url="/assessments", status_code=302)
    return RedirectResponse(url=f"/assessments/{latest}/risks", status_code=302)


@router.get("/assessments/{assessment_id}/risks")
def list_risks(
    request: Request,
    assessment_id: int,
    status: str = Query(default="ELEVATED"),
    tab: str = Query(default=""),
    risk_type: str = Query(default=""),
    impact: str = Query(default=""),
    q: str = Query(default=""),
    include_baseline: bool = Query(default=False),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    tab_key = str(tab or "").strip().lower()
    if tab_key in {"watchlist", "baseline", "elevated"}:
        status = tab_key.upper()

    ranked = get_risks_by_status(
        db,
        assessment,
        status=status,
        include_baseline=bool(include_baseline),
        risk_type=risk_type,
        impact=impact,
        q=q,
    )
    status_tab = str(ranked.get("status_tab") or "ELEVATED")
    status_counts = dict(ranked.get("status_counts") or {})
    risk_types = list(ranked.get("risk_types") or [])
    rows = list(ranked.get("items") or [])

    cards = []
    for r in rows:
        cards.append(
            {
                "id": int(r.get("id") or 0),
                "risk_type": str(r.get("risk_type", "other")),
                "primary_risk_type": str(r.get("primary_risk_type", "") or "").strip(),
                "risk_vector_summary": str(r.get("risk_vector_summary", "") or "").strip(),
                "title": str(r.get("title", "") or "Risk"),
                "why": str(r.get("why_matters", "") or "Open for evidence and defensive controls.")[:180],
                "impact_band": str(r.get("impact_band", "MED")),
                "likelihood": str(r.get("likelihood", "med")),
                "evidence_strength": str(r.get("evidence_strength", "WEAK")),
                "evidence_strength_score": int(r.get("confidence", 0) or 0),
                "signal_coverage": int(r.get("signal_coverage", 0) or 0),
                "evidence_count": int(r.get("evidence_refs_count", 0) or 0),
                "status": str(r.get("status", "WATCHLIST")),
                "missing_gate_reasons": list(r.get("missing_gate_reasons") or []),
                "needs_review": bool(r.get("needs_review", False)),
                "plausibility_score": int(r.get("plausibility_score", 0) or 0),
                "potential_impact_score": int(r.get("potential_impact_score", 0) or 0),
                "watchlist_label": (
                    "Low plausibility / Needs validation"
                    if int(r.get("plausibility_score", 0) or 0) < 55
                    else "Needs validation"
                ),
                "reasoning": dict(r.get("reasoning") or {}),
                "url": str(r.get("scenario_url", f"/assessments/{assessment_id}/risks/{int(r.get('id') or 0)}")),
            }
        )

    return request.app.state.templates.TemplateResponse(
        "risks.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_risks",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment),
            "section_title": "Risks",
            "cards": cards,
            "risk_types": risk_types,
            "risk_type": risk_type,
            "impact": impact,
            "q": q,
            "status_tab": status_tab,
            "status_counts": status_counts,
            "include_baseline": bool(include_baseline),
        },
    )


@router.get("/assessments/{assessment_id}/risks/{risk_id}")
def risk_detail(
    request: Request,
    assessment_id: int,
    risk_id: int,
    tab: str = Query(default="brief"),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    vm = build_risk_detail_viewmodel(db, assessment, int(risk_id))
    if not vm.get("risk"):
        return RedirectResponse(url=f"/assessments/{assessment_id}/risks", status_code=302)

    tab_key = (tab or "brief").strip().lower()
    if tab_key not in {"brief"}:
        tab_key = "brief"

    return request.app.state.templates.TemplateResponse(
        "risk_detail.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_risks",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment),
            "section_title": str(vm["risk"].get("title") or "Risk"),
            "vm": vm,
            "tab": tab_key,
        },
    )
