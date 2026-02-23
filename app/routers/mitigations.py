from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Assessment, Mitigation
from app.utils.jsonx import from_json

router = APIRouter(tags=["mitigations"])


def _assessment_context(assessment: Assessment) -> dict:
    return {
        "id": assessment.id,
        "company_name": assessment.company_name,
    }


def _latest_assessment_id(db: Session) -> int | None:
    latest = db.execute(select(Assessment.id).order_by(Assessment.updated_at.desc()).limit(1)).scalar_one_or_none()
    return int(latest) if latest is not None else None


def _priority_label(priority: int) -> str:
    if priority <= 2:
        return "high"
    if priority == 3:
        return "med"
    return "low"


@router.get("/mitigations")
def mitigations_legacy_redirect(
    assessment_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    target_id = assessment_id or _latest_assessment_id(db)
    if not target_id:
        return RedirectResponse(url="/assessments", status_code=302)
    return RedirectResponse(url=f"/assessments/{target_id}/mitigations", status_code=302)


@router.get("/assessments/{assessment_id}/mitigations")
def mitigations_page(
    request: Request,
    assessment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    mitigations = db.execute(
        select(Mitigation).where(Mitigation.assessment_id == assessment_id).order_by(Mitigation.priority.asc())
    ).scalars().all()

    cards = []
    for item in mitigations:
        linked = [x for x in from_json(item.linked_findings_json, []) if str(x).strip()]
        cards.append(
            {
                "id": item.id,
                "priority": item.priority,
                "priority_label": _priority_label(item.priority),
                "effort": item.effort,
                "owner": item.owner,
                "description": item.description,
                "linked": linked,
            }
        )

    return request.app.state.templates.TemplateResponse(
        "mitigations.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_mitigations",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment),
            "section_title": "Risk Reduction Actions",
            "section_subtitle": "Prioritized backlog with owner and effort guidance for defensive risk reduction.",
            "cards": cards,
        },
    )
