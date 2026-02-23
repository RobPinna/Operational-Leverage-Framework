from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.dependencies import get_current_user
from app.models import Assessment, Document, Hypothesis
from app.services.signal_model import (
    SIGNAL_ICONS,
    SIGNAL_LABELS,
    compute_hypothesis_confidence,
    coverage_label_from_signals,
    infer_signal_type,
    signal_counts,
    timeline_for_risk,
)
from app.utils.jsonx import from_json
from src.rag.index import run_query_plan
from src.reasoner.hypotheses import generate_hypotheses

router = APIRouter(tags=["hypotheses"])


def _assessment_context(assessment: Assessment) -> dict:
    return {
        "id": assessment.id,
        "company_name": assessment.company_name,
    }


def _latest_assessment_id(db: Session) -> int | None:
    latest = db.execute(select(Assessment.id).order_by(Assessment.updated_at.desc()).limit(1)).scalar_one_or_none()
    return int(latest) if latest is not None else None


def _safe_json(value: str, fallback):
    try:
        return from_json(value, fallback)
    except Exception:
        return fallback


def _severity_label(severity: int) -> str:
    if severity >= 4:
        return "high"
    if severity == 3:
        return "med"
    return "low"


def _confidence_label(conf: int) -> str:
    if conf >= 75:
        return "high"
    if conf >= 50:
        return "med"
    return "low"


def _impact_points(value: str) -> list[str]:
    raw = str(value or "")
    if not raw:
        return ["Operations"]
    if "/" in raw:
        parts = [p.strip().capitalize() for p in raw.split("/") if p.strip()]
    elif "," in raw:
        parts = [p.strip().capitalize() for p in raw.split(",") if p.strip()]
    else:
        parts = [raw.strip().capitalize()]
    return parts[:3] if parts else ["Operations"]

def _short_risk_title(*, assessment: Assessment, row: Hypothesis) -> str:
    sector = (assessment.sector or "").strip().lower()
    rt = (row.risk_type or "").strip().lower()
    qid = (row.query_id or "").strip().upper()

    # If the generator already produced a specialized stakeholder title, keep it.
    existing = " ".join((row.title or "").split()).strip()
    existing_low = existing.lower()
    if existing_low in {
        "credential and account handling via external channels",
        "booking and payment workflow exposure",
    }:
        return existing
    if any(x in existing_low for x in ("workflow exposure", "account handling", "credential and account")):
        # Keep concise titles that are already "risk itself", not a long explanation.
        if len(existing) <= 64:
            return existing

    is_hospitality = any(k in sector for k in ("hospital", "hotel", "hospitality", "resort", "travel"))
    is_ngo = any(k in sector for k in ("ngo", "non-profit", "nonprofit", "aid", "charity", "humanitarian"))

    if qid == "Q6":
        if is_hospitality:
            return "Guest data risk"
        if is_ngo:
            return "Beneficiary data risk"
        return "Customer data risk"

    if rt in {"downstream_pivot"}:
        return "Client impersonation risk" if not is_hospitality else "Guest impersonation risk"

    if rt in {"social_trust_surface_exposure"}:
        return "Social channel trust risk"

    if rt in {"impersonation", "brand_abuse"}:
        return "Brand impersonation risk"

    if rt in {"credential_theft_risk"}:
        return "Account takeover risk"

    if rt in {"fraud_process"}:
        return "Process fraud risk"

    if qid == "Q1":
        return "External channel risk"
    if qid == "Q2":
        return "Vendor exposure risk"
    if qid == "Q3":
        return "Operational leakage risk"
    if qid == "Q4":
        return "Official channel confusion risk"
    if qid == "Q5":
        return "Client trust risk"

    return "Public-facing risk"


def _sentence_case(value: str) -> str:
    s = " ".join(str(value or "").split()).strip()
    if not s:
        return s
    return s[:1].upper() + s[1:].lower()


def _evidence_quality_label(meta: dict) -> str:
    try:
        weighted = int(meta.get("weighted_evidence_count", 0) or 0)
        distinct = int(meta.get("distinct_url_count", 0) or 0)
        diversity = int(meta.get("signal_diversity_count", 0) or 0)
    except Exception:
        return "WEAK"
    if weighted >= 4 and distinct >= 2 and diversity >= 3:
        return "STRONG"
    if weighted >= 3 and distinct >= 2 and diversity >= 2:
        return "OK"
    return "WEAK"


def _confirm_deny_points(*, meta: dict, process_flags: dict | None) -> tuple[list[str], list[str]]:
    counts = meta.get("signal_counts") if isinstance(meta.get("signal_counts"), dict) else {}
    confirm: list[str] = []
    deny: list[str] = []

    trust_friction = bool((process_flags or {}).get("trust_friction", False))
    sens_kinds = process_flags.get("data_sens_kinds", []) if isinstance(process_flags, dict) else []
    has_cred = any(str(x).upper() == "CREDENTIALS" for x in (sens_kinds or []))
    has_booking = any(str(x).upper() == "BOOKING_PAYMENT" for x in (sens_kinds or []))
    has_social = int((counts or {}).get("SOCIAL_TRUST_NODE", 0) or 0) > 0

    social_contact_in_bio = bool((process_flags or {}).get("social_contact_in_bio", False))
    social_dm_workflow = bool((process_flags or {}).get("social_dm_workflow", False))
    social_to_booking = bool((process_flags or {}).get("social_to_booking", False))
    social_verified = bool((process_flags or {}).get("social_verified", False))

    if int((counts or {}).get("CONTACT_CHANNEL", 0) or 0) >= 2:
        confirm.append("Multiple external contact channels are visible in the indexed corpus.")
    if int((counts or {}).get("VENDOR_CUE", 0) or 0) > 0:
        confirm.append("Public artifacts contain third-party vendor/tooling cues tied to external workflows.")
    if int((counts or {}).get("PROCESS_CUE", 0) or 0) > 0 and int((counts or {}).get("CONTACT_CHANNEL", 0) or 0) > 0:
        confirm.append("Workflow language and external channels co-occur (higher chance of trust-channel confusion).")
    if has_social and social_contact_in_bio:
        confirm.append("Contact details are exposed on official social profile(s) (email/phone in bio).")
    if has_social and social_dm_workflow:
        confirm.append("The official social profile advertises DM-based contact handling.")
    if has_social and social_to_booking:
        confirm.append("Social profiles link into booking/payment flows, increasing reliance on clear channel verification.")
    if has_cred:
        confirm.append("Credential/account handling is referenced alongside externally accessible support channels.")
    if has_booking:
        confirm.append("Booking/billing/payment workflow references appear alongside externally accessible channels.")
    if trust_friction:
        confirm.append("No clear public official-channel verification or anti-phishing guidance was found in the indexed corpus.")

    # What would deny (conditions that, if present, would reduce or negate this scenario)
    deny.append("A centralized, signed registry of official contact channels is published and consistently referenced.")
    deny.append("A clear statement exists and is visible: the organization will never request passwords or login details.")
    if has_social and (social_dm_workflow or social_to_booking):
        deny.append("Clear guidance exists: sensitive actions are never handled via DM; booking/payment changes require verified channels.")
    if has_social and social_verified:
        deny.append("Verified social accounts are used as trust anchors and consistently linked from official pages.")
    if has_booking or int((counts or {}).get("PROCESS_CUE", 0) or 0) > 0:
        deny.append("Sensitive booking/payment/billing changes require out-of-band verification and approvals.")
    if has_cred:
        deny.append("Credential and account recovery actions are restricted to secure portals (not email/chat).")

    # Compact: max 4 each; only include confirm points that are actually relevant.
    confirm = [x for x in confirm if x][:4]
    deny = [x for x in deny if x][:4]
    return confirm, deny


@router.get("/hypotheses")
def hypotheses_legacy_redirect(
    assessment_id: int | None = Query(default=None),
    risk_type: str = Query(default=""),
    severity: str = Query(default=""),
    impact: str = Query(default=""),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    target_id = assessment_id or _latest_assessment_id(db)
    if not target_id:
        return RedirectResponse(url="/assessments", status_code=302)
    query_bits: list[str] = []
    if risk_type:
        query_bits.append(f"risk_type={risk_type}")
    # Prefer impact band filter; keep backward-compat severity numeric.
    if impact:
        query_bits.append(f"impact={impact}")
    elif severity:
        query_bits.append(f"severity={severity}")
    suffix = f"?{'&'.join(query_bits)}" if query_bits else ""
    return RedirectResponse(url=f"/assessments/{target_id}/risks{suffix}", status_code=302)


@router.get("/assessments/{assessment_id}/hypotheses")
def hypotheses_page(
    request: Request,
    assessment_id: int,
    risk_type: str = Query(default=""),
    severity: str = Query(default=""),
    impact: str = Query(default=""),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    query_bits: list[str] = []
    if risk_type:
        query_bits.append(f"risk_type={risk_type}")
    if impact:
        query_bits.append(f"impact={impact}")
    elif severity:
        query_bits.append(f"severity={severity}")
    suffix = f"?{'&'.join(query_bits)}" if query_bits else ""
    return RedirectResponse(url=f"/assessments/{assessment_id}/risks{suffix}", status_code=302)

    rows = []
    risk_types: list[str] = []
    severity_value: int | None = int(severity) if str(severity).isdigit() else None
    impact_band = str(impact or "").strip().lower()

    stmt = select(Hypothesis).where(Hypothesis.assessment_id == assessment_id)
    if risk_type.strip():
        stmt = stmt.where(Hypothesis.risk_type == risk_type.strip())
    if impact_band in {"high", "med", "low"}:
        if impact_band == "high":
            stmt = stmt.where(Hypothesis.severity >= 4)
        elif impact_band == "med":
            stmt = stmt.where(Hypothesis.severity == 3)
        else:
            stmt = stmt.where(Hypothesis.severity <= 2)
    elif severity_value is not None:
        # Backward compatibility.
        stmt = stmt.where(Hypothesis.severity == severity_value)
    stmt = stmt.order_by(Hypothesis.severity.desc(), Hypothesis.created_at.desc())
    rows = db.execute(stmt).scalars().all()
    risk_types = [
        x[0]
        for x in db.execute(
            select(Hypothesis.risk_type)
            .where(Hypothesis.assessment_id == assessment_id)
            .distinct()
            .order_by(Hypothesis.risk_type.asc())
        ).all()
        if x and x[0]
    ]

    cards = []
    doc_ids: set[int] = set()
    doc_urls: set[str] = set()
    for row in rows:
        for ref in from_json(row.evidence_refs_json, []):
            if isinstance(ref, dict):
                doc_id_raw = ref.get("doc_id")
                if str(doc_id_raw).isdigit():
                    doc_ids.add(int(doc_id_raw))
                url = str(ref.get("url", "")).strip()
                if url:
                    doc_urls.add(url)

    docs_by_id: dict[int, Document] = {}
    docs_by_url: dict[str, Document] = {}
    if doc_ids:
        for item in db.execute(select(Document).where(Document.id.in_(list(doc_ids)))).scalars().all():
            docs_by_id[item.id] = item
    if doc_urls:
        for item in db.execute(
            select(Document).where(Document.assessment_id == assessment_id, Document.url.in_(list(doc_urls)))
        ).scalars().all():
            docs_by_url[item.url] = item

    for row in rows:
        evidence_refs = from_json(row.evidence_refs_json, [])
        for ev in evidence_refs:
            if not isinstance(ev, dict):
                continue
            doc = None
            doc_id = ev.get("doc_id")
            if str(doc_id).isdigit():
                doc = docs_by_id.get(int(doc_id))
            if not doc:
                doc = docs_by_url.get(str(ev.get("url", "")).strip())
            if doc:
                ev["doc_id"] = doc.id
                ev["doc_link"] = f"/documents/{doc.id}"
                ev["doc_title"] = doc.title
            else:
                ev["doc_link"] = str(ev.get("url", "")).strip()
                ev["doc_title"] = ""
            st = str(ev.get("signal_type", "")).strip().upper()
            if not st:
                st = infer_signal_type(str(ev.get("url", "")), str(ev.get("snippet", "")), query_id=str(row.query_id))
            ev["signal_type"] = st
            ev["signal_label"] = SIGNAL_LABELS.get(st, st.replace("_", " ").title())
            ev["signal_icon"] = SIGNAL_ICONS.get(st, "activity")

        base_avg = 0
        if evidence_refs:
            base_avg = int(sum(int(x.get("confidence", 50)) for x in evidence_refs if isinstance(x, dict)) / len(evidence_refs))

        # Prefer stored confidence from generation, otherwise compute with signal model.
        conf = int(row.confidence or 0)
        meta_counts_raw = _safe_json(row.signal_counts_json or "{}", {})
        merged_from = 1
        merged_query_ids = []
        debug_blob = None
        baseline_exposure = False
        tags = []
        process_flags = None
        if isinstance(meta_counts_raw, dict):
            merged_from = int(meta_counts_raw.pop("__merged_from__", 1) or 1)
            merged_query_ids = meta_counts_raw.pop("__merged_query_ids__", []) if isinstance(meta_counts_raw.get("__merged_query_ids__", []), list) else []
            debug_blob = meta_counts_raw.pop("__debug__", None)
            baseline_exposure = bool(meta_counts_raw.pop("__baseline_exposure__", False))
            tags = meta_counts_raw.pop("__tags__", []) if isinstance(meta_counts_raw.get("__tags__", []), list) else []
            process_flags = meta_counts_raw.pop("__process_flags__", None)

        # Compute evidence quality meta from evidence refs (boilerplate-aware).
        ev_items = [
            {
                "url": str(x.get("url", "")),
                "snippet": str(x.get("snippet", "")),
                "confidence": int(x.get("confidence", 50) or 50),
                "signal_type": str(x.get("signal_type", "")),
                "query_id": str(row.query_id),
                "is_boilerplate": bool(x.get("is_boilerplate", False)),
                "weight": float(x.get("weight", 1.0) or 1.0),
            }
            for x in evidence_refs
            if isinstance(x, dict)
        ]
        calc_conf, meta = compute_hypothesis_confidence(
            ev_items,
            base_avg=base_avg,
            sector=(assessment.sector or ""),
            risk_type=(row.risk_type or ""),
        )
        if conf <= 0:
            conf = int(calc_conf)

        counts = meta.get("signal_counts") if isinstance(meta.get("signal_counts"), dict) else signal_counts(evidence_refs)
        diversity = int(meta.get("signal_diversity_count") or len([k for k, v in (counts or {}).items() if int(v or 0) > 0]))
        meta["signal_counts"] = counts or {}
        meta["signal_diversity_count"] = diversity
        meta["has_critical_signal"] = any(int((counts or {}).get(k, 0) or 0) > 0 for k in ("PROCESS_CUE", "VENDOR_CUE", "ORG_CUE"))
        cov = coverage_label_from_signals(meta)
        if baseline_exposure:
            cov = "WEAK"

        pills = []
        for key in ("CONTACT_CHANNEL", "SOCIAL_TRUST_NODE", "PROCESS_CUE", "VENDOR_CUE", "ORG_CUE", "EXTERNAL_ATTENTION", "INFRA_CUE"):
            count = int((counts or {}).get(key, 0) or 0)
            active = count > 0
            pills.append(
                {
                    "key": key,
                    "label": SIGNAL_LABELS.get(key, key),
                    "icon": SIGNAL_ICONS.get(key, "activity"),
                    "active": active,
                    "count": count,
                    "tooltip": (
                        "Distinct signal types improve confidence. Repetition alone does not."
                        if active
                        else "No evidence of this signal type in the current corpus."
                    ),
                }
            )

        missing_signals = _safe_json(row.missing_signals_json or "[]", [])
        if not isinstance(missing_signals, list):
            missing_signals = []
        timeline = _safe_json(row.timeline_json or "[]", [])
        if not isinstance(timeline, list) or not timeline:
            meta["risk_hint"] = row.title
            timeline = timeline_for_risk(row.risk_type, meta)

        # Replace verbose titles with a short "risk itself" title (sentence case).
        original_title = " ".join((row.title or "").split()).strip()
        short_title = _sentence_case(_short_risk_title(assessment=assessment, row=row))
        impact_rationale = " ".join((row.impact_rationale or "").split()).strip()
        if original_title:
            impact_rationale = f"{original_title}. {impact_rationale}".strip().strip(".") + "."

        eq_label = _evidence_quality_label(meta)
        confirm_points, deny_points = _confirm_deny_points(meta=meta, process_flags=process_flags if isinstance(process_flags, dict) else None)

        card = {
            "id": row.id,
            "query_id": row.query_id,
            "risk_type": row.risk_type,
            "severity": row.severity,
            "severity_label": _severity_label(row.severity),
            "title": short_title if short_title else row.title,
            "description": row.description,
            "likelihood": row.likelihood,
            "likelihood_rationale": row.likelihood_rationale,
            "impact": row.impact,
            "impact_rationale": impact_rationale,
            "evidence_refs": evidence_refs,
            "assumptions": from_json(row.assumptions_json, []),
            "gaps_to_verify": from_json(row.gaps_to_verify_json, []),
            "defensive_actions": from_json(row.defensive_actions_json, []),
            "confidence": int(conf),
            "confidence_label": _confidence_label(int(conf)),
            "signal_pills": pills,
            "signal_diversity_count": diversity,
            "signal_coverage_label": cov,
            "missing_signals": missing_signals,
            "timeline": timeline,
            "merged_from": int(merged_from or 1),
            "merged_query_ids": merged_query_ids,
            "debug": debug_blob if show_debug else None,
            "baseline_exposure": bool(baseline_exposure),
            "tags": tags,
            "process_flags": process_flags if isinstance(process_flags, dict) else None,
            "evidence_quality": eq_label,
            "confirm_points": confirm_points,
            "deny_points": deny_points,
        }
        cards.append(card)

    return request.app.state.templates.TemplateResponse(
        "hypotheses.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_hypotheses",
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment),
            "section_title": "Risk Scenarios",
            "risk_type": risk_type,
            "impact": impact_band,
            "risk_types": risk_types,
            "cards": cards,
            "show_debug": show_debug,
        },
    )


@router.post("/hypotheses/generate")
def hypotheses_generate_legacy(
    assessment_id: int = Form(...),
    top_k: int | None = Form(default=None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    from app.services.assessment_service import get_rag_advanced_state
    rag_cfg = get_rag_advanced_state(db)
    chosen_top_k = int(top_k) if isinstance(top_k, int) else int(rag_cfg.get("top_k", 4))
    chosen_ratio = float(rag_cfg.get("min_ratio", 0.70))
    plan = run_query_plan(assessment_id, top_k=max(1, min(30, int(chosen_top_k))), min_ratio=chosen_ratio)
    generate_hypotheses(assessment_id, plan)
    try:
        from app.services.trust_workflows import generate_trust_workflow_map
        generate_trust_workflow_map(db, assessment_id, top_k=int(chosen_top_k), min_ratio=float(chosen_ratio))
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Trust workflow map generation failed for assessment %s", assessment_id)
    return RedirectResponse(url=f"/assessments/{assessment_id}/risks", status_code=302)


@router.post("/assessments/{assessment_id}/hypotheses/generate")
def hypotheses_generate_context(
    assessment_id: int,
    top_k: int | None = Form(default=None),
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return RedirectResponse(url="/assessments", status_code=302)

    from app.services.assessment_service import get_rag_advanced_state
    rag_cfg = get_rag_advanced_state(db)
    chosen_top_k = int(top_k) if isinstance(top_k, int) else int(rag_cfg.get("top_k", 4))
    chosen_ratio = float(rag_cfg.get("min_ratio", 0.70))
    plan = run_query_plan(assessment_id, top_k=max(1, min(30, int(chosen_top_k))), min_ratio=chosen_ratio)
    generate_hypotheses(assessment_id, plan)
    try:
        from app.services.trust_workflows import generate_trust_workflow_map
        generate_trust_workflow_map(db, assessment_id, top_k=int(chosen_top_k), min_ratio=float(chosen_ratio))
    except Exception:
        import logging
        logging.getLogger(__name__).exception("Trust workflow map generation failed for assessment %s", assessment_id)
    return RedirectResponse(url=f"/assessments/{assessment_id}/risks", status_code=302)


@router.get("/documents/{doc_id}")
def document_detail(
    doc_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    row = db.get(Document, doc_id)
    if not row:
        raise HTTPException(status_code=404, detail="Document not found")
    assessment = db.get(Assessment, row.assessment_id)
    return request.app.state.templates.TemplateResponse(
        "document_detail.html",
        {
            "request": request,
            "user": user,
            "active": "assessment_hypotheses",
            "document": row,
            "assessment": assessment,
            "assessment_context": _assessment_context(assessment) if assessment else None,
            "section_title": "Document Detail",
            "section_subtitle": "Normalized document content referenced by risk scenario evidence.",
        },
    )
