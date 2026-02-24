from collections import Counter
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Assessment, Evidence, Finding, Mitigation, Node
from app.utils.jsonx import from_json
from app.utils.graphing import findings_by_type

router = APIRouter(tags=["dashboard"])


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


@router.get("/")
def root():
    return RedirectResponse(url="/assessments", status_code=302)


@router.get("/dashboard")
def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    return RedirectResponse(url="/assessments", status_code=302)

    # Legacy dashboard implementation kept below for backward compatibility with
    # internal imports; route now redirects to assessments list by product choice.
    latest = db.execute(select(Assessment).order_by(Assessment.updated_at.desc()).limit(1)).scalar_one_or_none()
    evidence_count = db.execute(select(func.count(Evidence.id))).scalar() or 0
    finding_count = db.execute(select(func.count(Finding.id))).scalar() or 0
    mitigation_count = db.execute(select(func.count(Mitigation.id))).scalar() or 0
    assessment_count = db.execute(select(func.count(Assessment.id))).scalar() or 0

    finding_rows = db.execute(select(Finding).order_by(Finding.severity.desc()).limit(12)).scalars().all()
    grouped = findings_by_type(finding_rows)
    top_findings = finding_rows[:5]

    evidence_ids: set[int] = set()
    refs_by_finding: dict[int, list[int]] = {}
    for finding in top_findings:
        refs = [int(x) for x in from_json(finding.evidence_refs_json, []) if str(x).isdigit()]
        refs_by_finding[finding.id] = refs
        evidence_ids.update(refs)

    evidence_rows = (
        db.execute(select(Evidence).where(Evidence.id.in_(list(evidence_ids)))).scalars().all() if evidence_ids else []
    )
    evidence_map = {e.id: e for e in evidence_rows}
    finding_previews: dict[int, dict] = {}
    for finding in top_findings:
        preview_web = None
        preview_any = None
        for ev_id in refs_by_finding.get(finding.id, []):
            ev = evidence_map.get(ev_id)
            if ev:
                if preview_any is None:
                    preview_any = ev
                if _is_web_url(ev.source_url):
                    preview_web = ev
                    break
        preview = preview_web or preview_any
        if preview and _is_web_url(preview.source_url):
            finding_previews[finding.id] = {
                "primary_url": preview.source_url,
                "primary_title": preview.title,
                "ref_count": len(refs_by_finding.get(finding.id, [])),
            }
        else:
            finding_previews[finding.id] = {"primary_url": "", "primary_title": "", "ref_count": 0}

    map_points = []
    if latest:
        nodes = (
            db.execute(
                select(Node).where(Node.assessment_id == latest.id, Node.type.in_(["mention", "touchpoint", "pivot"]))
            )
            .scalars()
            .all()
        )
        base_coords = [(24.7136, 46.6753), (25.2048, 55.2708), (30.0444, 31.2357), (51.5072, -0.1276)]
        for idx, node in enumerate(nodes[:15]):
            lat, lon = base_coords[idx % len(base_coords)]
            map_points.append({"label": node.label, "lat": lat + (idx * 0.08), "lon": lon + (idx * 0.05)})

    chart_counts = dict(Counter([f.type for f in finding_rows]))
    severities = dict(Counter([f.severity for f in finding_rows]))

    return request.app.state.templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "active": "dashboard",
            "latest": latest,
            "kpis": {
                "assessments": assessment_count,
                "evidence": evidence_count,
                "findings": finding_count,
                "mitigations": mitigation_count,
            },
            "top_findings": top_findings,
            "finding_previews": finding_previews,
            "chart_counts": chart_counts,
            "severity_counts": severities,
            "map_points": map_points,
            "grouped_findings": grouped,
        },
    )


@router.get("/demo")
def demo_redirect():
    return RedirectResponse(url="/assessments", status_code=302)
