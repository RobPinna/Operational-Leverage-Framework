from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Assessment, Hypothesis, SocialTrustNode
from app.services.assessment_service import get_rag_advanced_state
from app.services.trust_workflows import (
    generate_trust_workflow_map,
    list_trust_workflow_nodes,
    trust_workflow_summary,
)
from app.utils.jsonx import from_json


router = APIRouter(tags=["trust_workflows"])


def _assessment_context(assessment: Assessment) -> dict:
    return {"id": assessment.id, "company_name": assessment.company_name}


def _band(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 60:
        return "med"
    return "low"


@router.get("/assessments/{assessment_id}/trust-workflows")
def trust_workflow_page(
    request: Request,
    assessment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    # Deprecated as a standalone entry point: workflow is a lens under Risks.
    return RedirectResponse(url=f"/assessments/{assessment_id}/risks?view=workflow", status_code=302)


@router.post("/assessments/{assessment_id}/trust-workflows/generate")
def trust_workflow_generate(
    assessment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    rag_cfg = get_rag_advanced_state(db)
    generate_trust_workflow_map(
        db,
        assessment_id,
        top_k=int(rag_cfg.get("top_k", 4)),
        min_ratio=float(rag_cfg.get("min_ratio", 0.70)),
    )
    return RedirectResponse(url=f"/assessments/{assessment_id}/risks?view=workflow", status_code=302)
