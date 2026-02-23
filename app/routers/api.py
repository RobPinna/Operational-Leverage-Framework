from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.dependencies import get_current_user, get_db
from app.models import Assessment
from app.services.risk_story import build_overview_viewmodel, get_risks_by_status

router = APIRouter(prefix="/api", tags=["api"])


@router.get("/assessments/{assessment_id}/overview")
def api_assessment_overview(
    assessment_id: int,
    include_weak: bool = Query(default=False),
    include_baseline: bool = Query(default=False),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    vm = build_overview_viewmodel(
        db,
        assessment,
        include_weak=bool(include_weak),
        include_baseline=bool(include_baseline),
        generate_brief=False,
    )
    return {
        **vm,
        "topRisk": vm.get("topRiskVerdict"),
        "statusCounts": vm.get("status_counts", {}),
        "watchlist_total_count": int(vm.get("watchlist_total_count", 0) or 0),
        "watchlist_preview_limit": int(vm.get("watchlist_preview_limit", 3) or 3),
        "watchlist_preview": list(vm.get("watchlist_preview") or vm.get("watchlistPreview") or []),
        "watchlistPreview": vm.get("watchlistPreview", []),
    }


@router.get("/assessments/{assessment_id}/risks")
def api_assessment_risks(
    assessment_id: int,
    status: str = Query(default="ELEVATED"),
    risk_type: str = Query(default=""),
    impact: str = Query(default=""),
    q: str = Query(default=""),
    include_baseline: bool = Query(default=False),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return JSONResponse(status_code=404, content={"error": "not_found"})
    ranked = get_risks_by_status(
        db,
        assessment,
        status=status,
        include_baseline=bool(include_baseline),
        risk_type=risk_type,
        impact=impact,
        q=q,
    )
    return {
        "assessment_id": assessment_id,
        "status": str(ranked.get("status_tab") or "ELEVATED"),
        "statusCounts": dict(ranked.get("status_counts") or {}),
        "items": list(ranked.get("items") or []),
    }
