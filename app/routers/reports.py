from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Assessment, Report

router = APIRouter(tags=["reports"])


def _assessment_context(assessment: Assessment) -> dict:
    return {
        "id": assessment.id,
        "company_name": assessment.company_name,
    }


def _latest_assessment_id(db: Session) -> int | None:
    latest = db.execute(select(Assessment.id).order_by(Assessment.updated_at.desc()).limit(1)).scalar_one_or_none()
    return int(latest) if latest is not None else None


@router.get("/reports")
def reports_legacy_redirect(
    assessment_id: int | None = Query(default=None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    target_id = assessment_id or _latest_assessment_id(db)
    if not target_id:
        return RedirectResponse(url="/assessments", status_code=302)
    return RedirectResponse(url=f"/assessments/{target_id}/report", status_code=302)


@router.get("/assessments/{assessment_id}/report")
def reports_page(
    request: Request,
    assessment_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    reports = (
        db.execute(select(Report).where(Report.assessment_id == assessment_id).order_by(Report.created_at.desc()))
        .scalars()
        .all()
    )

    return request.app.state.templates.TemplateResponse(
        "reports.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_report",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment),
            "section_title": "Report",
            "section_subtitle": "Export history for PDF and JSON packages generated for this assessment.",
            "reports": reports,
        },
    )


@router.get("/reports/download/pdf/{report_id}")
def download_report_pdf(
    report_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    path = Path(report.pdf_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="PDF file not found")
    return FileResponse(path, media_type="application/pdf", filename=path.name)


@router.get("/reports/download/json/{report_id}")
def download_report_json(
    report_id: int,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    path = Path(report.json_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="JSON file not found")
    return FileResponse(path, media_type="application/json", filename=path.name)
