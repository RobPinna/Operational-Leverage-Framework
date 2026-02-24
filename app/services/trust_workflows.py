from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import re
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import Assessment, Document, Hypothesis, SocialTrustNode, WorkflowNode
from app.services.signal_model import infer_signal_type, signal_counts
from app.utils.jsonx import from_json, to_json
from src.rag.index import search


_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)

TRUST_GUIDANCE_PATTERNS = (
    "we will never ask for your password",
    "we will never request your password",
    "never ask for your password",
    "do not share your password",
    "official channels",
    "official email",
    "verified domains",
    "anti-phishing",
    "phishing",
    "non ti chiederemo mai la password",
    "non chiederemo mai la password",
    "non condividere la password",
    "canali ufficiali",
    "indirizzi ufficiali",
)

VERIFICATION_PATTERNS = (
    "verification",
    "verify",
    "confirmed by phone",
    "callback",
    "out-of-band",
    "secondary verification",
    "we may call you",
    "we will call you",
    "two-step",
    "two step",
    "verifica",
    "richiam",
    "conferma telefon",
)

SECURE_PORTAL_PATTERNS = (
    "portal",
    "secure portal",
    "account portal",
    "my account",
    "dashboard",
    "login",
    "sign in",
    "secure area",
    "area riservata",
    "accedi",
)

SOCIAL_BOOKING_URL_HINTS = (
    "booking",
    "reservation",
    "reserve",
    "payment",
    "invoice",
    "billing",
    "pay",
    "checkout",
    "loyalty",
)


def _normalize_host(raw: str) -> str:
    value = (raw or "").strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = f"https://{value}"
    try:
        host = (urlparse(value).netloc or "").split(":")[0].strip().lower().strip(".")
    except Exception:
        host = ""
    return host[4:] if host.startswith("www.") else host


def _is_internal_to_assessment(assessment: Assessment, url: str) -> bool:
    target = _normalize_host(assessment.domain or "")
    if not target:
        return False
    try:
        host = (urlparse(url).netloc or "").split(":")[0].strip().lower().strip(".")
    except Exception:
        return False
    host = host[4:] if host.startswith("www.") else host
    return host == target or host.endswith(f".{target}")


def _doc_for_url(db: Session, assessment_id: int, url: str) -> Document | None:
    u = (url or "").strip()
    if not u:
        return None
    variants = {u, u.rstrip("/"), u.rstrip("/") + "/"}
    return (
        db.execute(
            select(Document)
            .where(
                Document.assessment_id == assessment_id,
                Document.url.in_(list(variants)),
            )
            .order_by(Document.created_at.desc(), Document.id.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )


def _has_trust_guidance_text(text: str) -> bool:
    low = _norm(text)
    return any(_norm(p) in low for p in TRUST_GUIDANCE_PATTERNS)


def _social_trust_friction(
    *,
    base_score: int,
    global_flags: dict[str, Any],
    has_dm_workflow: bool,
    contact_in_bio: bool,
    booking_link: str,
    booking_link_needs_guidance: bool,
    verified: bool | None,
) -> int:
    score = int(base_score)
    if has_dm_workflow:
        score += 15
    if contact_in_bio:
        score += 10
    if booking_link and booking_link_needs_guidance:
        score += 15
    if bool(verified) is True and bool(global_flags.get("has_trust_guidance", False)):
        score -= 10
    return max(0, min(100, int(score)))


def _confirm_deny_for_social_node(
    *,
    has_dm_workflow: bool,
    contact_in_bio: bool,
    social_to_booking: bool,
    verified: bool | None,
    global_flags: dict[str, Any],
) -> tuple[list[str], list[str]]:
    confirm: list[str] = []
    deny: list[str] = []

    if has_dm_workflow:
        confirm.append("The official social profile advertises DM-based contact handling.")
    if contact_in_bio:
        confirm.append("Email/phone contact details are exposed in the social profile bio.")
    if social_to_booking:
        confirm.append(
            "The social profile links into booking/payment flows (higher reliance on clear verification controls)."
        )
    if not bool(global_flags.get("has_trust_guidance", False)):
        confirm.append(
            "No clear official-channel verification or anti-impersonation guidance was found in the indexed corpus."
        )

    deny.append("Verified social accounts are used and consistently linked from official web pages.")
    deny.append("A centralized list of official channels is published, including social handles and verified domains.")
    if has_dm_workflow or social_to_booking:
        deny.append(
            "Clear guidance exists: sensitive actions are never handled via DM; changes require verified channels and out-of-band checks."
        )

    return [x for x in confirm if x][:4], [x for x in deny if x][:4]


def _social_workflow_nodes(
    db: Session, assessment: Assessment, global_flags: dict[str, Any]
) -> tuple[list[WorkflowNode], dict[int, int]]:
    nodes: list[WorkflowNode] = []
    score_by_social_id: dict[int, int] = {}

    social_rows = (
        db.execute(
            select(SocialTrustNode)
            .where(SocialTrustNode.assessment_id == assessment.id)
            .order_by(SocialTrustNode.updated_at.desc())
        )
        .scalars()
        .all()
    )
    for s in social_rows:
        profile_url = str(s.profile_url or "").strip()
        if not profile_url:
            continue

        contact_in_bio = bool(s.has_email_in_bio or s.has_phone_in_bio)
        has_dm_workflow = bool(s.mentions_dm_contact)
        social_to_booking = bool(
            s.mentions_booking or any(k in (str(s.link_in_bio or "").lower()) for k in SOCIAL_BOOKING_URL_HINTS)
        )
        verified = s.verified_status if isinstance(s.verified_status, bool) else None

        booking_link = str(s.link_in_bio or "").strip()
        booking_link_needs_guidance = False
        if booking_link and social_to_booking and _is_internal_to_assessment(assessment, booking_link):
            landing_doc = _doc_for_url(db, assessment.id, booking_link)
            landing_text = str((landing_doc.extracted_text if landing_doc else "") or "")
            if not _has_trust_guidance_text(landing_text):
                booking_link_needs_guidance = True

        # Evidence refs: prefer stored evidence, but keep compact schema used by template.
        evs = from_json(s.evidence_refs_json or "[]", [])
        if not isinstance(evs, list):
            evs = []
        evidence = []
        for ev in evs[:6]:
            if not isinstance(ev, dict):
                continue
            evidence.append(
                {
                    "url": str(ev.get("url", "")).strip()[:1024],
                    "title": str(ev.get("title", "")).strip()[:255],
                    "snippet": str(ev.get("snippet", "")).strip()[:380],
                    "doc_id": ev.get("doc_id"),
                    "score": float(ev.get("score", 0.0) or 0.0),
                }
            )
        if not evidence:
            evidence = [
                {
                    "url": profile_url[:1024],
                    "title": f"{s.platform} @{s.handle}".strip()[:255],
                    "snippet": (s.bio_text or "")[:380],
                }
            ]

        # DM workflow node
        if has_dm_workflow:
            sensitivity = "HIGH" if social_to_booking else "MED"
            base = _trust_friction_score(sensitivity=sensitivity, channel_type="chat", flags=global_flags)
            score = _social_trust_friction(
                base_score=base,
                global_flags=global_flags,
                has_dm_workflow=True,
                contact_in_bio=contact_in_bio,
                booking_link=booking_link,
                booking_link_needs_guidance=booking_link_needs_guidance,
                verified=verified,
            )
            confirm, deny = _confirm_deny_for_social_node(
                has_dm_workflow=True,
                contact_in_bio=contact_in_bio,
                social_to_booking=social_to_booking,
                verified=verified,
                global_flags=global_flags,
            )
            flags = dict(global_flags)
            flags.update(
                {
                    "workflow_kind": "SOCIAL_DM_INTERACTION",
                    "social_node_id": int(s.id),
                    "platform": str(s.platform or ""),
                    "handle": str(s.handle or ""),
                    "verified": verified,
                    "contact_in_bio": bool(contact_in_bio),
                    "dm_workflow": True,
                    "social_to_booking": bool(social_to_booking),
                    "booking_link": booking_link,
                    "booking_link_needs_guidance": bool(booking_link_needs_guidance),
                }
            )
            nodes.append(
                WorkflowNode(
                    assessment_id=assessment.id,
                    workflow_kind="SOCIAL_DM_INTERACTION",
                    title="Social Direct Message Interaction",
                    sensitivity_level=sensitivity,
                    channel_type="social_dm",
                    requires_trust=True,
                    trust_friction_score=int(score),
                    evidence_refs_json=to_json(evidence[:6]),
                    confirm_json=to_json(confirm),
                    deny_json=to_json(deny),
                    flags_json=to_json(flags),
                    created_at=datetime.utcnow(),
                )
            )
            score_by_social_id[int(s.id)] = max(int(score_by_social_id.get(int(s.id), 0) or 0), int(score))

        # Social-to-booking transition node
        if social_to_booking and booking_link:
            sensitivity = "HIGH"
            base = _trust_friction_score(sensitivity=sensitivity, channel_type="unknown", flags=global_flags)
            score = _social_trust_friction(
                base_score=base,
                global_flags=global_flags,
                has_dm_workflow=has_dm_workflow,
                contact_in_bio=contact_in_bio,
                booking_link=booking_link,
                booking_link_needs_guidance=booking_link_needs_guidance,
                verified=verified,
            )
            confirm, deny = _confirm_deny_for_social_node(
                has_dm_workflow=has_dm_workflow,
                contact_in_bio=contact_in_bio,
                social_to_booking=True,
                verified=verified,
                global_flags=global_flags,
            )
            flags = dict(global_flags)
            flags.update(
                {
                    "workflow_kind": "SOCIAL_TO_BOOKING_TRANSITION",
                    "social_node_id": int(s.id),
                    "platform": str(s.platform or ""),
                    "handle": str(s.handle or ""),
                    "verified": verified,
                    "contact_in_bio": bool(contact_in_bio),
                    "dm_workflow": bool(has_dm_workflow),
                    "social_to_booking": True,
                    "booking_link": booking_link,
                    "booking_link_needs_guidance": bool(booking_link_needs_guidance),
                }
            )
            nodes.append(
                WorkflowNode(
                    assessment_id=assessment.id,
                    workflow_kind="SOCIAL_TO_BOOKING_TRANSITION",
                    title="Social-to-Booking Transition",
                    sensitivity_level=sensitivity,
                    channel_type="social_link",
                    requires_trust=True,
                    trust_friction_score=int(score),
                    evidence_refs_json=to_json(evidence[:6]),
                    confirm_json=to_json(confirm),
                    deny_json=to_json(deny),
                    flags_json=to_json(flags),
                    created_at=datetime.utcnow(),
                )
            )
            score_by_social_id[int(s.id)] = max(int(score_by_social_id.get(int(s.id), 0) or 0), int(score))

    return nodes, score_by_social_id


@dataclass(frozen=True, slots=True)
class WorkflowDefinition:
    kind: str
    title: str
    query: str
    sensitivity: str  # LOW/MED/HIGH
    anchors: tuple[str, ...]


WORKFLOWS: list[WorkflowDefinition] = [
    WorkflowDefinition(
        kind="ACCOUNT_CREATION",
        title="Account creation",
        query="create account sign up register guest account creation",
        sensitivity="MED",
        anchors=("create account", "sign up", "register", "account creation", "guest account"),
    ),
    WorkflowDefinition(
        kind="LOGIN_HANDLING",
        title="Login handling",
        query="login sign in access account portal",
        sensitivity="MED",
        anchors=("login", "sign in", "account access", "portal"),
    ),
    WorkflowDefinition(
        kind="PASSWORD_HANDLING",
        title="Password and account recovery",
        query="password reset forgot password account recovery",
        sensitivity="HIGH",
        anchors=("password", "reset password", "forgot password", "account recovery", "credentials"),
    ),
    WorkflowDefinition(
        kind="BOOKING_MODIFICATION",
        title="Booking modification",
        query="booking modification reservation change modify booking change reservation",
        sensitivity="HIGH",
        anchors=(
            "modify booking",
            "booking modification",
            "reservation change",
            "change reservation",
            "booking change",
        ),
    ),
    WorkflowDefinition(
        kind="PAYMENT_REQUEST",
        title="Payment and billing requests",
        query="payment request billing invoice refund payment details",
        sensitivity="HIGH",
        anchors=("payment", "billing", "invoice", "refund", "payment details", "invoice details"),
    ),
    WorkflowDefinition(
        kind="LOYALTY_PROGRAM",
        title="Loyalty program management",
        query="loyalty program points account management",
        sensitivity="HIGH",
        anchors=("loyalty", "points", "loyalty account", "account management"),
    ),
    WorkflowDefinition(
        kind="CHAT_ASSISTANCE",
        title="Chat-based assistance",
        query="live chat chat support assistance",
        sensitivity="MED",
        anchors=("live chat", "chat", "chat support"),
    ),
    WorkflowDefinition(
        kind="PRIVACY_DATA_REQUEST",
        title="Privacy and data requests",
        query="data subject request privacy rights request DPO GDPR contact privacy",
        sensitivity="MED",
        anchors=("data subject", "rights request", "privacy request", "dpo", "gdpr", "diritti", "richiesta"),
    ),
]


def _norm(value: str) -> str:
    return " ".join((value or "").split()).strip().lower()


def _is_policy_url(url: str) -> bool:
    u = (url or "").lower()
    return any(x in u for x in ("/privacy", "/terms", "/cookie", "/polic", "/gdpr"))


def _is_boilerplate(snippet: str, title: str = "") -> bool:
    t = _norm(f"{title} {snippet}")
    if any(x in t for x in ("meta:", "og:title", "og:description")):
        return True
    if "cookie" in t and any(x in t for x in ("preferences", "consent", "accept", "reject", "manage")):
        return True
    # Footer-like navigation list in short text
    if len(t) <= 260:
        nav_words = ("home", "about", "careers", "jobs", "contact", "support", "privacy", "terms", "cookies", "sitemap")
        if sum(1 for w in nav_words if w in t) >= 5:
            return True
    return False


def _channel_type_from_evidence(url: str, snippet: str, doc_type: str = "") -> str:
    u = (url or "").lower()
    s = _norm(snippet)
    if any(x in u for x in ("/login", "/signin", "/account", "/portal", "/dashboard")) or any(
        x in s for x in ("portal", "my account", "dashboard", "area riservata", "accedi")
    ):
        return "portal"
    if "chat" in s or any(x in u for x in ("/chat", "/livechat")):
        return "chat"
    if "form" in s or any(x in u for x in ("/contact", "/support", "/help")):
        return "form"
    if _EMAIL_RE.search(snippet or ""):
        return "email"
    if doc_type == "pdf":
        # PDFs often contain contact flows via email/phone; stay conservative.
        return "unknown"
    return "unknown"


def _trust_flags_for_assessment(db: Session, assessment_id: int) -> dict[str, bool]:
    rows = (
        db.execute(
            select(Document.extracted_text).where(
                Document.assessment_id == assessment_id,
                Document.extracted_text != "",
            )
        )
        .scalars()
        .all()
    )
    joined = "\n".join((rows or [])[:120])
    low = _norm(joined)
    has_trust_guidance = any(_norm(p) in low for p in TRUST_GUIDANCE_PATTERNS)
    has_verification = any(_norm(p) in low for p in VERIFICATION_PATTERNS)
    has_secure_portal = any(_norm(p) in low for p in SECURE_PORTAL_PATTERNS)
    has_never_ask_pw = any(
        _norm(p) in low
        for p in (
            "we will never ask for your password",
            "never ask for your password",
            "non ti chiederemo mai la password",
        )
    )
    return {
        "has_trust_guidance": bool(has_trust_guidance),
        "has_verification": bool(has_verification),
        "has_secure_portal": bool(has_secure_portal),
        "has_never_ask_password": bool(has_never_ask_pw),
    }


def _anchor_hits(snippet: str, title: str, anchors: tuple[str, ...]) -> int:
    t = _norm(f"{title} {snippet}")
    hits = 0
    for a in anchors:
        aa = _norm(a)
        if aa and aa in t:
            hits += 1
    return hits


def _evidence_for_workflow(
    assessment_id: int, wf: WorkflowDefinition, *, top_k: int = 6, min_ratio: float = 0.70
) -> list[dict[str, Any]]:
    # Pull a decent candidate set, then apply ratio threshold.
    candidates = search(assessment_id, wf.query, top_k=max(20, int(top_k) * 6))
    if not candidates:
        return []
    top1 = float(candidates[0].get("score", 0.0) or 0.0)
    threshold = top1 * float(min_ratio or 0.70)

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in candidates:
        score = float(row.get("score", 0.0) or 0.0)
        if score < threshold:
            continue
        url = str(row.get("url", "")).strip()
        title = str(row.get("title", "")).strip()
        snippet = str(row.get("snippet", "")).strip()
        if not url or not snippet:
            continue
        if _is_boilerplate(snippet, title=title):
            continue
        if _anchor_hits(snippet, title, wf.anchors) <= 0:
            continue
        key = f"{url.lower()}|{snippet[:120].lower()}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "doc_id": int(row.get("doc_id")) if str(row.get("doc_id", "")).isdigit() else None,
                "url": url[:1024],
                "title": title[:255],
                "snippet": " ".join(snippet.split())[:380],
                "score": round(score, 4),
            }
        )
        if len(out) >= max(1, int(top_k)):
            break
    return out


def _confirm_deny_for_node(
    *, wf: WorkflowDefinition, flags: dict[str, Any], channel_type: str, sensitivity: str
) -> tuple[list[str], list[str]]:
    confirm: list[str] = []
    deny: list[str] = []

    if sensitivity == "HIGH" and channel_type in {"email", "chat", "form", "unknown"}:
        confirm.append(
            "Sensitive workflow references appear tied to externally reachable channels (higher trust dependency)."
        )
    if not bool(flags.get("has_trust_guidance", False)):
        confirm.append("Official-channel verification guidance was not found in the indexed corpus.")
    if not bool(flags.get("has_never_ask_password", False)) and wf.kind in {"PASSWORD_HANDLING", "LOGIN_HANDLING"}:
        confirm.append("No explicit 'we never request passwords' guidance was found in the indexed corpus.")
    if bool(flags.get("has_verification", False)) is False and sensitivity in {"HIGH", "MED"}:
        confirm.append("Secondary verification language was not found near this workflow in the indexed corpus.")

    deny.append("A centralized, signed registry of official contact channels is published and consistently referenced.")
    if wf.kind in {"PASSWORD_HANDLING", "LOGIN_HANDLING"}:
        deny.append(
            "A clear statement exists and is visible: the organization will never request passwords or login details."
        )
        deny.append("Credential and account recovery actions are restricted to secure portals (not email/chat).")
    if wf.kind in {"BOOKING_MODIFICATION", "PAYMENT_REQUEST"}:
        deny.append("Sensitive booking/payment changes require out-of-band verification and approvals.")
        deny.append("A secure portal is used for sensitive requests, and external channels are informational only.")
    if wf.kind == "PRIVACY_DATA_REQUEST":
        deny.append("Data subject requests are routed via a dedicated secure process with verified contact points.")

    return confirm[:4], [x for x in deny if x][:4]


def _trust_friction_score(*, sensitivity: str, channel_type: str, flags: dict[str, Any]) -> int:
    score = 0
    if sensitivity == "HIGH":
        score += 40
    elif sensitivity == "MED":
        score += 25
    else:
        score += 10

    if channel_type in {"email", "chat"}:
        score += 20
    elif channel_type == "form":
        score += 12
    elif channel_type == "portal":
        score -= 10
    else:
        score += 10

    # Friction increases when guidance is absent
    if not bool(flags.get("has_trust_guidance", False)):
        score += 15
    else:
        score -= 10
    if not bool(flags.get("has_never_ask_password", False)):
        score += 10
    else:
        score -= 10
    if not bool(flags.get("has_verification", False)):
        score += 10
    else:
        score -= 10
    if bool(flags.get("has_secure_portal", False)) or channel_type == "portal":
        score -= 10

    return max(0, min(100, int(score)))


def generate_trust_workflow_map(
    db: Session,
    assessment_id: int,
    *,
    top_k: int = 4,
    min_ratio: float = 0.70,
    auto_generate_scenarios: bool = True,
) -> dict[str, Any]:
    """
    Phase 1: detect trust workflows from corpus and compute trust friction scores.
    Also optionally generates a linked scenario when trust_friction_score > 70.
    """
    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return {"assessment_id": assessment_id, "nodes": 0}

    # Clear existing nodes for idempotency.
    db.execute(delete(WorkflowNode).where(WorkflowNode.assessment_id == assessment_id))
    db.commit()

    global_flags = _trust_flags_for_assessment(db, assessment_id)

    nodes: list[WorkflowNode] = []
    for wf in WORKFLOWS:
        evs = _evidence_for_workflow(assessment_id, wf, top_k=max(2, int(top_k)), min_ratio=float(min_ratio))
        if not evs:
            continue

        # Channel type: derive from the strongest evidence item.
        best = evs[0]
        url = str(best.get("url", ""))
        snippet = str(best.get("snippet", ""))
        doc_type = "pdf" if str(url).lower().endswith(".pdf") else "html"
        channel_type = _channel_type_from_evidence(url, snippet, doc_type=doc_type)

        sensitivity = wf.sensitivity
        requires_trust = bool(sensitivity in {"HIGH", "MED"} and channel_type != "portal")

        flags = dict(global_flags)
        flags.update(
            {
                "workflow_kind": wf.kind,
                "policy_only": bool(evs) and all(_is_policy_url(str(x.get("url", ""))) for x in evs),
                "distinct_url_count": len(
                    {str(x.get("url", "")).strip().lower() for x in evs if str(x.get("url", "")).strip()}
                ),
            }
        )

        score = _trust_friction_score(sensitivity=sensitivity, channel_type=channel_type, flags=flags)
        confirm, deny = _confirm_deny_for_node(wf=wf, flags=flags, channel_type=channel_type, sensitivity=sensitivity)

        node = WorkflowNode(
            assessment_id=assessment_id,
            workflow_kind=wf.kind,
            title=wf.title,
            sensitivity_level=sensitivity,
            channel_type=channel_type,
            requires_trust=requires_trust,
            trust_friction_score=int(score),
            evidence_refs_json=to_json(evs[:6]),
            confirm_json=to_json(confirm),
            deny_json=to_json(deny),
            flags_json=to_json(flags),
            created_at=datetime.utcnow(),
        )
        nodes.append(node)

    social_nodes, social_scores = _social_workflow_nodes(db, assessment, global_flags)
    if social_nodes:
        nodes.extend(social_nodes)
    # Update stored social node trust friction scores for UI display (best-effort).
    if social_scores:
        for sid, score in social_scores.items():
            row = db.get(SocialTrustNode, int(sid))
            if not row:
                continue
            row.trust_friction_score = int(score or 0)
        db.commit()

    for n in nodes:
        db.add(n)
    db.commit()
    for n in nodes:
        db.refresh(n)

    # Auto-generate scenario(s) for high-friction nodes.
    created_scenarios = 0
    if auto_generate_scenarios:
        created_social: set[int] = set()
        for n in nodes:
            if int(n.trust_friction_score or 0) <= 70:
                continue

            flags = from_json(n.flags_json or "{}", {})
            if isinstance(flags, dict) and str(flags.get("workflow_kind", "")).startswith("SOCIAL_"):
                social_id = flags.get("social_node_id")
                social_id_int = int(social_id) if str(social_id).isdigit() else None
                if social_id_int is None or social_id_int in created_social:
                    continue
                created_social.add(social_id_int)

                s = db.get(SocialTrustNode, social_id_int)
                if not s:
                    continue

                # Idempotency: one scenario per social node id.
                # Historical DBs might already contain duplicates. We only need an existence check.
                exists = (
                    db.execute(
                        select(Hypothesis.id)
                        .where(
                            Hypothesis.assessment_id == assessment_id,
                            Hypothesis.risk_type == "social_trust_surface_exposure",
                            Hypothesis.signal_counts_json.ilike(f'%\\"__social_node_id__\\": {social_id_int}%'),
                        )
                        .limit(1)
                    )
                    .scalars()
                    .first()
                )
                if exists:
                    continue

                contact_in_bio = bool(s.has_email_in_bio or s.has_phone_in_bio)
                dm_workflow = bool(s.mentions_dm_contact)
                social_to_booking = bool(
                    s.mentions_booking or any(k in (str(s.link_in_bio or "").lower()) for k in SOCIAL_BOOKING_URL_HINTS)
                )
                verified = s.verified_status if isinstance(s.verified_status, bool) else None
                trust_friction = not bool(global_flags.get("has_trust_guidance", False))

                evidence_refs_raw = from_json(s.evidence_refs_json or "[]", [])
                if not isinstance(evidence_refs_raw, list):
                    evidence_refs_raw = []
                evidence_refs = []
                for ev in evidence_refs_raw[:6]:
                    if not isinstance(ev, dict):
                        continue
                    evidence_refs.append(
                        {
                            "url": str(ev.get("url", ""))[:1024],
                            "title": str(ev.get("title", ""))[:255],
                            "snippet": str(ev.get("snippet", ""))[:1200],
                            "doc_id": ev.get("doc_id"),
                            "confidence": int(ev.get("confidence", 60) or 60),
                            "signal_type": str(ev.get("signal_type", "SOCIAL_TRUST_NODE") or "SOCIAL_TRUST_NODE"),
                            "score": float(ev.get("score", 0.0) or 0.0),
                            "is_boilerplate": False,
                            "weight": 1.0,
                        }
                    )

                # Add landing page evidence when social bio points internally to booking/payment flows.
                booking_link = str(s.link_in_bio or "").strip()
                if booking_link and social_to_booking and _is_internal_to_assessment(assessment, booking_link):
                    landing_doc = _doc_for_url(db, assessment_id, booking_link)
                    if landing_doc and landing_doc.extracted_text:
                        snippet = " ".join(str(landing_doc.extracted_text or "").split())[:520]
                        evidence_refs.append(
                            {
                                "url": str(landing_doc.url or booking_link)[:1024],
                                "title": str(landing_doc.title or "Landing page")[:255],
                                "snippet": snippet,
                                "doc_id": int(landing_doc.id),
                                "confidence": 65,
                                "signal_type": "PROCESS_CUE",
                                "score": 0.0,
                                "is_boilerplate": False,
                                "weight": 1.0,
                            }
                        )

                # Social-specific scenario: board-friendly, defensive framing only.
                severity = 4 if social_to_booking else 3
                impact = "financial" if social_to_booking else "reputation"
                likelihood = "med"
                if social_to_booking and dm_workflow and trust_friction and bool(verified) is not True:
                    likelihood = "high"

                description = (
                    "Official social channels appear to be a trust anchor for external interactions. "
                    "Where bios advertise direct-message contact or link into booking/payment flows, ambiguity can increase "
                    "and recipients may be more vulnerable to channel confusion or impersonation attempts. "
                    "This does not confirm malicious activity; it highlights a control opportunity."
                )
                impact_rationale = (
                    "Social profiles can be used by stakeholders as a shortcut for legitimacy. "
                    "If sensitive requests transition from social to booking/payment channels without clear verification guidance, "
                    "the risk of confusion-driven fraud increases."
                )

                actions = [
                    "Publish and maintain a clear official-channel registry (website + social bios) including verified domains and handles.",
                    "Add visible guidance: sensitive actions (payments, credential resets) are never handled via DM.",
                    "Prefer secure portals for booking/payment changes; require out-of-band verification for high-impact requests.",
                    "Use verified social accounts where possible and link to the official registry from the bio/website.",
                ]

                process_flags = {
                    "trust_friction": bool(trust_friction),
                    "social_contact_in_bio": bool(contact_in_bio),
                    "social_dm_workflow": bool(dm_workflow),
                    "social_to_booking": bool(social_to_booking),
                    "social_verified": bool(verified) is True,
                    "data_sens_kinds": ["BOOKING_PAYMENT"] if social_to_booking else [],
                }
                signal_counts_json = {
                    "__social_node_id__": int(social_id_int),
                    "__process_flags__": process_flags,
                }

                row = Hypothesis(
                    assessment_id=assessment_id,
                    query_id="SOC",
                    risk_type="social_trust_surface_exposure",
                    primary_risk_type=("Booking fraud" if social_to_booking else "Social engineering"),
                    risk_vector_summary=(
                        "Top risk: Booking fraud enabled by official social channel touchpoints + booking transition cues + multi-channel trust ambiguity."
                        if social_to_booking
                        else "Top risk: Social engineering enabled by official social channel touchpoints + public contact cues + multi-channel trust ambiguity."
                    )[:280],
                    baseline_tag=False,
                    integrity_flags_json=json.dumps(
                        {"source": "trust_workflows", "social_to_booking": bool(social_to_booking)}, ensure_ascii=True
                    ),
                    severity=int(severity),
                    title="Social Channel Trust Surface Exposure",
                    description=description[:1400],
                    likelihood=str(likelihood),
                    likelihood_rationale="Derived from public social-channel workflows, booking/payment transitions, and presence/absence of verification guidance.",
                    impact=str(impact),
                    impact_rationale=impact_rationale[:1000],
                    evidence_refs_json=to_json(evidence_refs[:6]),
                    assumptions_json=to_json([]),
                    gaps_to_verify_json=to_json([]),
                    defensive_actions_json=to_json(actions),
                    confidence=0,
                    signal_diversity=0,
                    signal_counts_json=json.dumps(signal_counts_json, ensure_ascii=True),
                    missing_signals_json=json.dumps([], ensure_ascii=True),
                    timeline_json=json.dumps([], ensure_ascii=True),
                )
                db.add(row)
                db.commit()
                created_scenarios += 1
                continue

            # Avoid duplicates: one scenario per workflow_kind.
            # Historical DBs might already contain duplicates. We only need an existence check.
            exists = (
                db.execute(
                    select(Hypothesis.id)
                    .where(
                        Hypothesis.assessment_id == assessment_id,
                        Hypothesis.risk_type == "workflow_trust_exposure",
                        Hypothesis.title.ilike(f"%{n.title}%"),
                    )
                    .limit(1)
                )
                .scalars()
                .first()
            )
            if exists:
                continue

            evs = json.loads(n.evidence_refs_json or "[]")
            # Map evidence refs into Hypothesis evidence refs schema.
            evidence_refs = []
            for ev in evs[:6]:
                if not isinstance(ev, dict):
                    continue
                evidence_refs.append(
                    {
                        "url": str(ev.get("url", ""))[:1024],
                        "title": str(ev.get("title", ""))[:255],
                        "snippet": str(ev.get("snippet", ""))[:1200],
                        "doc_id": ev.get("doc_id"),
                        "confidence": 65,
                        "signal_type": infer_signal_type(str(ev.get("url", "")), str(ev.get("snippet", ""))),
                        "score": float(ev.get("score", 0.0) or 0.0),
                        "is_boilerplate": False,
                        "weight": 1.0,
                    }
                )

            counts = signal_counts(evidence_refs)
            signal_counts_json = dict(counts)
            signal_counts_json["__workflow_node_id__"] = int(n.id)
            signal_counts_json["__workflow_kind__"] = str(n.workflow_kind)
            signal_counts_json["__process_flags__"] = {
                "trust_friction_score": int(n.trust_friction_score or 0),
                "workflow_kind": str(n.workflow_kind),
                "channel_type": str(n.channel_type),
                "sensitivity_level": str(n.sensitivity_level),
            }

            # Keep high-level and defensive language only.
            severity = 4 if int(n.trust_friction_score or 0) >= 80 else 3
            description = (
                f"Workflow-level trust exposure is indicated for: {n.title}. "
                f"Evidence suggests a trust dependency on externally reachable channels with incomplete verification guidance. "
                f"This does not confirm malicious activity; it highlights an opportunity for confusion-driven fraud if controls are weak."
            )
            impact_rationale = (
                f"{n.title} appears to rely on externally reachable channels ({n.channel_type}) at sensitivity {n.sensitivity_level}. "
                "Where official channels and verification steps are not explicit, recipients may be more vulnerable to channel confusion."
            )
            actions = [
                "Publish a clear, centralized list of official contact channels and verified domains.",
                "Add a visible statement describing what your teams will never request (especially passwords).",
                "Require out-of-band verification and approvals for high-impact workflow changes (billing/booking/account).",
                "Prefer secure portals for sensitive requests; keep email/chat informational only where possible.",
            ]

            row = Hypothesis(
                assessment_id=assessment_id,
                query_id="WF",
                risk_type="workflow_trust_exposure",
                primary_risk_type=(
                    "Payment fraud"
                    if any(x in (n.title or "").lower() for x in ("payment", "billing", "invoice"))
                    else (
                        "Booking fraud"
                        if any(x in (n.title or "").lower() for x in ("booking", "reservation"))
                        else (
                            "Account takeover vector"
                            if any(x in (n.title or "").lower() for x in ("password", "login", "account"))
                            else "Channel ambiguity exploitation"
                        )
                    )
                ),
                risk_vector_summary=(
                    "Top risk: Payment fraud enabled by operational workflow cues + externally reachable channel dependency + missing verification guidance."
                    if any(x in (n.title or "").lower() for x in ("payment", "billing", "invoice"))
                    else (
                        "Top risk: Booking fraud enabled by operational workflow cues + externally reachable channel dependency + missing verification guidance."
                        if any(x in (n.title or "").lower() for x in ("booking", "reservation"))
                        else (
                            "Top risk: Account takeover vector enabled by operational workflow cues + externally reachable channel dependency + missing verification guidance."
                            if any(x in (n.title or "").lower() for x in ("password", "login", "account"))
                            else "Top risk: Channel ambiguity exploitation enabled by externally reachable channel dependency + missing verification guidance."
                        )
                    )
                )[:280],
                baseline_tag=False,
                integrity_flags_json=json.dumps(
                    {"source": "trust_workflows", "workflow_node_id": int(n.id)}, ensure_ascii=True
                ),
                severity=int(severity),
                title=f"Workflow-level trust exposure: {n.title}"[:255],
                description=description[:1400],
                likelihood="med",
                likelihood_rationale="Derived from workflow sensitivity, channel type, and presence/absence of public verification guidance.",
                impact="ops",
                impact_rationale=impact_rationale[:1000],
                evidence_refs_json=to_json(evidence_refs),
                assumptions_json=to_json([]),
                gaps_to_verify_json=to_json([]),
                defensive_actions_json=to_json(actions),
                confidence=70,
                signal_diversity=len([k for k, v in counts.items() if v > 0]),
                signal_counts_json=json.dumps(signal_counts_json, ensure_ascii=True),
                missing_signals_json=json.dumps([], ensure_ascii=True),
                timeline_json=json.dumps([], ensure_ascii=True),
            )
            db.add(row)
            db.commit()
            created_scenarios += 1

    return {
        "assessment_id": assessment_id,
        "nodes_created": len(nodes),
        "scenarios_created": created_scenarios,
    }


def list_trust_workflow_nodes(db: Session, assessment_id: int) -> list[WorkflowNode]:
    return (
        db.execute(
            select(WorkflowNode)
            .where(WorkflowNode.assessment_id == assessment_id)
            .order_by(WorkflowNode.trust_friction_score.desc(), WorkflowNode.created_at.desc())
        )
        .scalars()
        .all()
    )


def trust_workflow_summary(db: Session, assessment_id: int) -> dict[str, Any]:
    nodes = list_trust_workflow_nodes(db, assessment_id)
    high_nodes = [n for n in nodes if int(n.trust_friction_score or 0) > 70]
    cred_or_pay = 0
    for n in nodes:
        if str(n.sensitivity_level or "").upper() != "HIGH":
            continue
        if str(n.channel_type or "").lower() in {"email", "chat", "form", "unknown"}:
            if n.workflow_kind in {"PASSWORD_HANDLING", "PAYMENT_REQUEST", "BOOKING_MODIFICATION", "LOYALTY_PROGRAM"}:
                cred_or_pay += 1
    return {
        "total_nodes": len(nodes),
        "high_friction_nodes": len(high_nodes),
        "external_sensitive_nodes": int(cred_or_pay),
    }
