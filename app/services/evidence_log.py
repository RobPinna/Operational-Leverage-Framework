from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Assessment, Hypothesis, WorkflowNode
from app.services.risk_story import _canonical_url, _parse_signal_counts_blob, _risk_outcome_label, _sentence_case, build_overview_viewmodel
from app.utils.jsonx import from_json


def build_evidence_log_viewmodel(
    db: Session,
    assessment: Assessment,
    *,
    q: str = "",
    signal_type: str = "",
    risk_id: int | None = None,
) -> dict[str, Any]:
    """
    Evidence Log is risk-first: it lists the evidence items actually used by risk objects/workflow lens.
    This is distinct from the low-level fetch/parse examination log (collector telemetry).
    """
    assessment_id = int(assessment.id)

    # Use the risk story builder as the source of normalized/deduped evidence refs.
    ov = build_overview_viewmodel(db, assessment, include_weak=True, generate_brief=False)
    evidence_sets = ov.get("evidenceSets") or {}

    risks = (
        db.execute(select(Hypothesis).where(Hypothesis.assessment_id == assessment_id).order_by(Hypothesis.severity.desc()))
        .scalars()
        .all()
    )
    risk_titles: dict[int, str] = {}
    for r in risks:
        prt = str(getattr(r, "primary_risk_type", "") or "").strip()
        if prt:
            risk_titles[int(r.id)] = _sentence_case(prt) or f"Risk {int(r.id)}"
        else:
            parsed = _parse_signal_counts_blob(r.signal_counts_json or "{}")
            outcome = _risk_outcome_label(
                str(r.risk_type or ""),
                sector=str(assessment.sector or ""),
                process_flags=parsed.process_flags if isinstance(parsed.process_flags, dict) else None,
            )
            risk_titles[int(r.id)] = _sentence_case(outcome) or f"Risk {int(r.id)}"

    workflow_nodes = (
        db.execute(
            select(WorkflowNode)
            .where(WorkflowNode.assessment_id == assessment_id)
            .order_by(WorkflowNode.trust_friction_score.desc(), WorkflowNode.id.desc())
        )
        .scalars()
        .all()
    )
    workflow_titles = {int(n.id): (" ".join((n.title or "").split()).strip() or f"Workflow {int(n.id)}") for n in workflow_nodes}

    # Accumulate evidence items and link them back to risks and workflow nodes.
    ev_map: dict[str, dict[str, Any]] = {}

    def _key(ev: dict[str, Any]) -> str:
        u = str(ev.get("canonical_url") or ev.get("url") or "").strip()
        u = _canonical_url(u)
        st = str(ev.get("signal_type") or "OTHER").strip().upper()
        sn = " ".join(str(ev.get("snippet") or "").split()).strip()[:220]
        return f"{u}|{st}|{sn}"

    # Evidence referenced by risks.
    for r in risks:
        rid = int(r.id)
        if risk_id is not None and rid != int(risk_id):
            continue
        items = list(evidence_sets.get(f"risk:{rid}", []) or [])
        for ev in items:
            if not isinstance(ev, dict):
                continue
            k = _key(ev)
            cur = ev_map.get(k)
            if not cur:
                ev_map[k] = {
                    "canonical_url": str(ev.get("canonical_url") or _canonical_url(str(ev.get("url", "")))),
                    "url": str(ev.get("url", "")),
                    "domain": str(ev.get("domain", "")),
                    "snippet": str(ev.get("snippet", "")),
                    "signal_type": str(ev.get("signal_type", "OTHER")),
                    "confidence": int(ev.get("confidence", 50) or 50),
                    "doc_id": ev.get("doc_id"),
                    "weight": float(ev.get("weight", 1.0) or 1.0),
                    "occurrences": int(ev.get("occurrences", 1) or 1),
                    "linked_risks": set([rid]),
                    "linked_workflows": set(),
                }
            else:
                cur["linked_risks"].add(rid)
                cur["occurrences"] = int(cur.get("occurrences", 1) or 1) + int(ev.get("occurrences", 1) or 1)

    # Evidence referenced by workflow nodes (lens).
    for n in workflow_nodes:
        nid = int(n.id)
        evs = from_json(n.evidence_refs_json or "[]", [])
        if not isinstance(evs, list):
            continue
        for ev in evs:
            if not isinstance(ev, dict):
                continue
            u = str(ev.get("url", "")).strip()
            if not u:
                continue
            # Attach workflow linkage to any already-known evidence (by canonical url), otherwise keep as standalone evidence.
            cu = _canonical_url(u)
            # Create a minimal record so workflow-only evidence can still appear.
            tmp = {
                "canonical_url": cu,
                "url": u,
                "domain": "",
                "snippet": str(ev.get("snippet", "")),
                "signal_type": str(ev.get("signal_type", "")) or "OTHER",
                "confidence": int(ev.get("confidence", 50) or 50),
                "doc_id": ev.get("doc_id"),
                "weight": float(ev.get("weight", 1.0) or 1.0),
                "occurrences": 1,
            }
            k = _key(tmp)
            cur = ev_map.get(k)
            if not cur:
                ev_map[k] = {
                    **tmp,
                    "linked_risks": set(),
                    "linked_workflows": set([nid]),
                }
            else:
                cur["linked_workflows"].add(nid)

    rows = list(ev_map.values())

    # Filtering
    if signal_type:
        st = signal_type.strip().upper()
        rows = [r for r in rows if str(r.get("signal_type", "")).strip().upper() == st]
    if q:
        qq = q.strip().lower()
        rows = [
            r
            for r in rows
            if qq in str(r.get("canonical_url", "")).lower()
            or qq in str(r.get("snippet", "")).lower()
            or qq in str(r.get("signal_type", "")).lower()
        ]

    # Sort: prefer evidence linked to more risks, then by confidence.
    rows.sort(
        key=lambda r: (
            len(r.get("linked_risks") or []),
            int(r.get("confidence", 0) or 0),
            int(r.get("occurrences", 0) or 0),
        ),
        reverse=True,
    )

    # Prepare chips and URLs.
    out_rows = []
    for r in rows[:1200]:
        lr = sorted(list(r.get("linked_risks") or []))
        lw = sorted(list(r.get("linked_workflows") or []))
        best_risk = lr[0] if lr else None
        out_rows.append(
            {
                "canonical_url": str(r.get("canonical_url", "")),
                "url": str(r.get("url", "")),
                "snippet": str(r.get("snippet", "")),
                "signal_type": str(r.get("signal_type", "OTHER")),
                "confidence": int(r.get("confidence", 50) or 50),
                "doc_id": r.get("doc_id"),
                "weight": float(r.get("weight", 1.0) or 1.0),
                "occurrences": int(r.get("occurrences", 1) or 1),
                "linked_risks": [{"id": int(x), "title": risk_titles.get(int(x), f"Risk {int(x)}")} for x in lr[:6]],
                "linked_workflows": [{"id": int(x), "title": workflow_titles.get(int(x), f"Workflow {int(x)}")} for x in lw[:4]],
                "open_risk_url": (
                    f"/assessments/{assessment_id}/risks/{int(best_risk)}#evidence" if best_risk is not None else ""
                ),
                "open_risk_workflow_url": (
                    f"/assessments/{assessment_id}/risks/{int(best_risk)}?tab=workflow" if best_risk is not None else ""
                ),
            }
        )

    signal_values = sorted({str(r.get("signal_type") or "OTHER").strip().upper() for r in out_rows})

    return {
        "assessment_id": assessment_id,
        "rows": out_rows,
        "signal_values": signal_values,
        "q": q,
        "signal_type": signal_type,
        "risk_id": int(risk_id) if risk_id is not None else None,
    }
