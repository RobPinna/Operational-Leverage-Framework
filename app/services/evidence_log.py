from __future__ import annotations
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Assessment, Hypothesis, WorkflowNode
from app.services.risk_story import (
    EMAIL_PATTERN,
    PHONE_PATTERN,
    ROLE_HINTS,
    _canonical_url,
    _evidence_identity_key,
    _parse_signal_counts_blob,
    _risk_outcome_label,
    _sentence_case,
    build_assessment_evidence_code_map,
    get_ranked_risks,
)
from app.utils.jsonx import from_json


def _merge_hints(dst: list[str], src: list[str]) -> list[str]:
    out = list(dst or [])
    for raw in src or []:
        line = " ".join(str(raw or "").split()).strip()
        if line and line not in out:
            out.append(line)
            if len(out) >= 24:
                break
    return out


def _extract_artifacts(ev: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def _push(value: str) -> None:
        clean = " ".join(str(value or "").split()).strip()
        if not clean:
            return
        key = clean.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(clean)

    hints = ev.get("indicator_hints")
    hint_lines = [str(x or "") for x in hints] if isinstance(hints, list) else []
    for line in hint_lines:
        clean = " ".join(str(line or "").split()).strip()
        if not clean:
            continue
        low = clean.lower()
        if low.startswith("found public email:"):
            _push(clean.split(":", 1)[1].strip())
            continue
        if low.startswith("found public phone/contact number:"):
            _push(clean.split(":", 1)[1].strip())
            continue
        if low.startswith("found publicly targetable role cue:"):
            role = clean.split(":", 1)[1].strip()
            _push(f"role: {role}")
            continue
        email_match = EMAIL_PATTERN.search(clean)
        if email_match:
            _push(email_match.group(0))
            continue
        phone_match = PHONE_PATTERN.search(clean)
        if phone_match:
            _push(" ".join(str(phone_match.group(0)).split()))
            continue
        for role in ROLE_HINTS:
            if role in low:
                _push(f"role: {role}")
                break

    blob = " ".join(
        [
            str(ev.get("title", "") or ""),
            str(ev.get("snippet", "") or ""),
            str(ev.get("url", "") or ""),
            " ".join(hint_lines),
        ]
    )
    for em in EMAIL_PATTERN.findall(blob):
        _push(em.lower())
    for ph in PHONE_PATTERN.findall(blob):
        _push(" ".join(str(ph).split()))
    low_blob = blob.lower()
    for role in ROLE_HINTS:
        if role in low_blob:
            _push(f"role: {role}")

    url = str(ev.get("url", "") or "").strip()
    if url:
        try:
            parsed = urlparse(url)
            host = (parsed.netloc or "").lower().split(":")[0]
            path = (parsed.path or "").strip()
            if host and any(tok in path.lower() for tok in ("/contact", "/support", "/help", "/privacy", "/legal", "/jobs")):
                _push(f"{host}{path[:80]}")
        except Exception:
            pass

    return out[:8]


def _artifact_types_from_values(values: list[str]) -> list[str]:
    out: list[str] = []
    for raw in values or []:
        clean = " ".join(str(raw or "").split()).strip()
        if not clean:
            continue
        low = clean.lower()
        if EMAIL_PATTERN.search(clean):
            if "EMAIL" not in out:
                out.append("EMAIL")
        if PHONE_PATTERN.search(clean):
            if "PHONE" not in out:
                out.append("PHONE")
        if low.startswith("role:") or any(role in low for role in ROLE_HINTS):
            if "ORG_CUE" not in out:
                out.append("ORG_CUE")
        if any(tok in low for tok in ("/contact", "/support", "/help", "/privacy", "/legal", "/jobs")):
            if "CONTACT_CHANNEL" not in out:
                out.append("CONTACT_CHANNEL")
    return out[:6]


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

    ranked = get_ranked_risks(db, assessment, include_baseline=True)
    evidence_sets = ranked.get("evidence_sets") or {}
    shared_code_map = build_assessment_evidence_code_map(db, assessment, ranked_snapshot=ranked)

    risks = (
        db.execute(
            select(Hypothesis).where(Hypothesis.assessment_id == assessment_id).order_by(Hypothesis.severity.desc())
        )
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
    workflow_titles = {
        int(n.id): (" ".join((n.title or "").split()).strip() or f"Workflow {int(n.id)}") for n in workflow_nodes
    }

    # Accumulate evidence items and link them back to risks and workflow nodes.
    ev_map: dict[str, dict[str, Any]] = {}

    # Evidence referenced by risks.
    for r in risks:
        rid = int(r.id)
        if risk_id is not None and rid != int(risk_id):
            continue
        items = list(evidence_sets.get(f"risk:{rid}", []) or [])
        for ev in items:
            if not isinstance(ev, dict):
                continue
            k = _evidence_identity_key(ev)
            cur = ev_map.get(k)
            if not cur:
                ev_map[k] = {
                    "canonical_url": str(ev.get("canonical_url") or _canonical_url(str(ev.get("url", "")))),
                    "url": str(ev.get("url", "")),
                    "domain": str(ev.get("domain", "")),
                    "title": str(ev.get("title", "")),
                    "snippet": str(ev.get("snippet", "")),
                    "signal_type": str(ev.get("signal_type", "OTHER")),
                    "confidence": int(ev.get("confidence", 50) or 50),
                    "doc_id": ev.get("doc_id"),
                    "weight": float(ev.get("weight", 1.0) or 1.0),
                    "occurrences": int(ev.get("occurrences", 1) or 1),
                    "indicator_hints": list(ev.get("indicator_hints") or [])
                    if isinstance(ev.get("indicator_hints"), list)
                    else [],
                    "linked_risks": set([rid]),
                    "linked_workflows": set(),
                }
            else:
                cur["linked_risks"].add(rid)
                cur["occurrences"] = int(cur.get("occurrences", 1) or 1) + int(ev.get("occurrences", 1) or 1)
                cur["indicator_hints"] = _merge_hints(
                    list(cur.get("indicator_hints") or []),
                    list(ev.get("indicator_hints") or []) if isinstance(ev.get("indicator_hints"), list) else [],
                )

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
                "title": str(ev.get("title", "")),
                "snippet": str(ev.get("snippet", "")),
                "signal_type": str(ev.get("signal_type", "")) or "OTHER",
                "confidence": int(ev.get("confidence", 50) or 50),
                "doc_id": ev.get("doc_id"),
                "weight": float(ev.get("weight", 1.0) or 1.0),
                "occurrences": 1,
                "indicator_hints": [],
            }
            k = _evidence_identity_key(tmp)
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
    enriched_rows: list[dict[str, Any]] = []
    for row in rows:
        artifacts = _extract_artifacts(row)
        enriched = dict(row)
        enriched["evidence_code"] = str(shared_code_map.get(_evidence_identity_key(row), "")).strip()
        enriched["artifacts"] = artifacts
        enriched_rows.append(enriched)

    # Filtering
    if signal_type:
        st = signal_type.strip().upper()
        enriched_rows = [r for r in enriched_rows if str(r.get("signal_type", "")).strip().upper() == st]
    if q:
        qq = q.strip().lower()
        enriched_rows = [
            r
            for r in enriched_rows
            if qq in str(r.get("canonical_url", "")).lower()
            or qq in str(r.get("snippet", "")).lower()
            or qq in str(r.get("signal_type", "")).lower()
            or qq in str(r.get("evidence_code", "")).lower()
            or qq in " ".join(str(x or "") for x in (r.get("artifacts") or [])).lower()
        ]

    # Aggregate signal types at document level so each evidence row can show
    # the full set of evidence types observed in the same document.
    doc_signal_types: dict[int, list[str]] = {}
    doc_artifact_types: dict[int, list[str]] = {}
    for r in enriched_rows:
        did = r.get("doc_id")
        if not str(did).isdigit():
            continue
        doc_id_int = int(did)
        st = " ".join(str(r.get("signal_type", "OTHER") or "OTHER").split()).strip().upper() or "OTHER"
        bucket = doc_signal_types.setdefault(doc_id_int, [])
        if st not in bucket:
            bucket.append(st)
        artifact_bucket = doc_artifact_types.setdefault(doc_id_int, [])
        for at in _artifact_types_from_values(list(r.get("artifacts") or [])):
            if at not in artifact_bucket:
                artifact_bucket.append(at)
    for _, values in doc_signal_types.items():
        if len(values) > 1 and "OTHER" in values:
            values[:] = [v for v in values if v != "OTHER"]
        values.sort(key=lambda x: (x == "OTHER", x))
    for _, values in doc_artifact_types.items():
        values.sort(key=lambda x: (x == "OTHER", x))

    # Sort: prefer evidence linked to more risks, then by confidence.
    enriched_rows.sort(
        key=lambda r: (
            len(r.get("linked_risks") or []),
            int(r.get("confidence", 0) or 0),
            int(r.get("occurrences", 0) or 0),
        ),
        reverse=True,
    )

    # Prepare chips and URLs.
    out_rows = []
    for r in enriched_rows[:1200]:
        lr = sorted(list(r.get("linked_risks") or []))
        lw = sorted(list(r.get("linked_workflows") or []))
        best_risk = lr[0] if lr else None
        signal_type = str(r.get("signal_type", "OTHER"))
        row_doc_id = r.get("doc_id")
        row_signal_types = [signal_type]
        if str(row_doc_id).isdigit():
            doc_id_int = int(row_doc_id)
            merged_types: list[str] = []
            for value in list(doc_signal_types.get(doc_id_int, [])) + list(doc_artifact_types.get(doc_id_int, [])):
                v = " ".join(str(value or "").split()).strip().upper()
                if v and v not in merged_types:
                    merged_types.append(v)
            if len(merged_types) > 1 and "OTHER" in merged_types:
                merged_types = [v for v in merged_types if v != "OTHER"]
            row_signal_types = merged_types or [signal_type]
        out_rows.append(
            {
                "evidence_code": str(r.get("evidence_code", "")),
                "canonical_url": str(r.get("canonical_url", "")),
                "url": str(r.get("url", "")),
                "snippet": str(r.get("snippet", "")),
                "signal_type": signal_type,
                "signal_types": row_signal_types[:8],
                "confidence": int(r.get("confidence", 50) or 50),
                "doc_id": r.get("doc_id"),
                "weight": float(r.get("weight", 1.0) or 1.0),
                "occurrences": int(r.get("occurrences", 1) or 1),
                "artifacts": list(r.get("artifacts") or [])[:8],
                "linked_risks": [{"id": int(x), "title": risk_titles.get(int(x), f"Risk {int(x)}")} for x in lr[:6]],
                "linked_workflows": [
                    {"id": int(x), "title": workflow_titles.get(int(x), f"Workflow {int(x)}")} for x in lw[:4]
                ],
                "open_risk_url": (
                    f"/assessments/{assessment_id}/risks/{int(best_risk)}#evidence" if best_risk is not None else ""
                ),
                "open_risk_workflow_url": (
                    f"/assessments/{assessment_id}/risks/{int(best_risk)}#evidence" if best_risk is not None else ""
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
