from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


SIGNAL_TYPES = (
    "CONTACT_CHANNEL",
    "SOCIAL_TRUST_NODE",
    "PROCESS_CUE",
    "VENDOR_CUE",
    "ORG_CUE",
    "EXTERNAL_ATTENTION",
    "INFRA_CUE",
    "EMAIL_SPOOFING_RISK",
    "DMARC_POLICY_WEAK",
    "DMARC_POLICY_STRONG",
    "MULTIPLE_MX_PROVIDER",
    "ROLE_TARGETABILITY_SIGNAL",
    "CHANNEL_AMBIGUITY_SIGNAL",
    "DIRECT_MESSAGE_WORKFLOW_SIGNAL",
)

SIGNAL_LABELS: dict[str, str] = {
    "CONTACT_CHANNEL": "Contact channel",
    "SOCIAL_TRUST_NODE": "Social channel",
    "PROCESS_CUE": "Process cue",
    "VENDOR_CUE": "Vendor cue",
    "ORG_CUE": "Org cue",
    "EXTERNAL_ATTENTION": "External attention",
    "INFRA_CUE": "Infra cue",
    "EMAIL_SPOOFING_RISK": "Email spoofing risk",
    "DMARC_POLICY_WEAK": "DMARC weak",
    "DMARC_POLICY_STRONG": "DMARC strong",
    "MULTIPLE_MX_PROVIDER": "Multiple MX providers",
    "ROLE_TARGETABILITY_SIGNAL": "Role targetability",
    "CHANNEL_AMBIGUITY_SIGNAL": "Channel ambiguity",
    "DIRECT_MESSAGE_WORKFLOW_SIGNAL": "Direct message workflow",
}

SIGNAL_ICONS: dict[str, str] = {
    "CONTACT_CHANNEL": "mail",
    "SOCIAL_TRUST_NODE": "at-sign",
    "PROCESS_CUE": "clipboard-list",
    "VENDOR_CUE": "plug",
    "ORG_CUE": "users",
    "EXTERNAL_ATTENTION": "newspaper",
    "INFRA_CUE": "server",
    "EMAIL_SPOOFING_RISK": "shield-alert",
    "DMARC_POLICY_WEAK": "mail",
    "DMARC_POLICY_STRONG": "shield-check",
    "MULTIPLE_MX_PROVIDER": "network",
    "ROLE_TARGETABILITY_SIGNAL": "users",
    "CHANNEL_AMBIGUITY_SIGNAL": "shuffle",
    "DIRECT_MESSAGE_WORKFLOW_SIGNAL": "message-circle",
}

EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)
PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")

VENDOR_KEYWORDS = (
    "zendesk",
    "intercom",
    "freshdesk",
    "salesforce",
    "hubspot",
    "stripe",
    "adyen",
    "checkout.com",
    "paypal",
    "cloudflare",
    "akamai",
    "google tag manager",
    "gtm.js",
    "recaptcha",
    "okta",
    "auth0",
    "microsoft 365",
)

PROCESS_KEYWORDS = (
    "invoice",
    "billing",
    "payment",
    "refund",
    "reservation",
    "booking",
    "procurement",
    "supplier",
    "purchase order",
    "po ",
    "onboarding",
    "support",
    "escalation",
    "tier",
    "callback",
    "verification",
    "account change",
    "account management",
)

ORG_KEYWORDS = (
    "org chart",
    "organization",
    "reporting to",
    "head of",
    "manager",
    "director",
    "supervisor",
    "press office",
    "communications",
    "safeguarding",
    "finance team",
)

ATTENTION_KEYWORDS = (
    "advisory",
    "warning",
    "press",
    "media",
    "trend",
    "spike",
    "campaign",
    "announcement",
    "reputational",
    "headline",
)

PROCESS_VERBS = (
    "request",
    "submit",
    "change",
    "update",
    "verify",
    "confirm",
    "approve",
    "escalat",
    "refund",
    "cancel",
    "pay",
    "invoice",
    "bill",
    "onboard",
    "renew",
    "callback",
)

CONTACT_FORM_HINTS = (
    "contact form",
    "submit a request",
    "submit request",
    "open a ticket",
    "submit a ticket",
    "ticket form",
    "web form",
)

SOCIAL_HOSTS = (
    "instagram.com",
    "facebook.com",
    "linkedin.com",
    "x.com",
    "twitter.com",
    "youtube.com",
    "tiktok.com",
)


def _norm_text(value: str) -> str:
    return " ".join((value or "").strip().split()).lower()


def _url_parts(url: str) -> tuple[str, str, str]:
    raw = (url or "").strip()
    if raw.startswith("dns://"):
        host = raw[len("dns://") :].split("/", 1)[0].lower()
        return host, "/", raw.lower()
    try:
        u = urlparse(raw)
        host = (u.netloc or "").lower().split(":")[0]
        path = (u.path or "/").lower()
        return host, path, raw.lower()
    except Exception:
        return "", "/", raw.lower()


def infer_signal_type(url: str, snippet: str, *, query_id: str = "") -> str:
    """
    Infer a high-level signal type from a citation.
    This is intentionally heuristic and conservative (no over-claiming).
    """
    host, path, url_lower = _url_parts(url)
    text = _norm_text(snippet)

    # Infra cues: only from explicit metadata sources (DNS/subdomain/VT/Shodan), not from regular website pages.
    if url_lower.startswith(("dns://", "subdomain://", "shodan://", "virustotal://")):
        return "INFRA_CUE"

    # Social trust nodes: only from known social platforms (treat separately from generic contact channels).
    host_norm = (host or "").lower()
    if host_norm.startswith("www."):
        host_norm = host_norm[4:]
    if host_norm and any(host_norm == dom or host_norm.endswith(f".{dom}") for dom in SOCIAL_HOSTS):
        return "SOCIAL_TRUST_NODE"

    # Email posture / channel extension signals (explicit connector narratives).
    if "no dmarc policy detected" in text or "email spoofing risk" in text:
        return "EMAIL_SPOOFING_RISK"
    if "dmarc policy is monitoring only" in text or "dmarc policy detected with p=none" in text:
        return "DMARC_POLICY_WEAK"
    if "dmarc enforcement policy detected" in text or "p=reject" in text or "p=quarantine" in text:
        return "DMARC_POLICY_STRONG"
    if "multiple mx providers detected" in text:
        return "MULTIPLE_MX_PROVIDER"
    if "role targetability signal" in text:
        return "ROLE_TARGETABILITY_SIGNAL"
    if "channel ambiguity signal" in text:
        return "CHANNEL_AMBIGUITY_SIGNAL"
    if "direct message workflow signal" in text or any(x in text for x in ("whatsapp", "telegram", "messenger", "via dm")):
        return "DIRECT_MESSAGE_WORKFLOW_SIGNAL"

    # Vendor cues: only when a known vendor/tool is actually present.
    if any(v in text for v in VENDOR_KEYWORDS) or any(v in url_lower for v in ("zendesk", "intercom", "greenhouse", "lever")):
        return "VENDOR_CUE"

    # External attention: only from press/news/media contexts; explicitly exclude policy pages.
    if any(token in path for token in ("/privacy", "/terms", "/polic")):
        pass
    else:
        if any(k in path for k in ("/press", "/news", "/media", "/blog")) or any(k in text for k in ATTENTION_KEYWORDS):
            if any(k in path for k in ("/press", "/news", "/media", "/blog")) or query_id.strip().upper() in {"Q5"}:
                return "EXTERNAL_ATTENTION"

    # Contact channels: require concrete contact tokens (email/phone/form) or a canonical contact path.
    if any(k in path for k in ("/contact", "/contacts")):
        return "CONTACT_CHANNEL"
    if EMAIL_RE.search(snippet or "") or PHONE_RE.search(snippet or ""):
        return "CONTACT_CHANNEL"
    if any(h in text for h in CONTACT_FORM_HINTS) and ("contact" in text or "request" in text):
        return "CONTACT_CHANNEL"

    # Org cues: role/team identifiers or org/about pages.
    if any(k in path for k in ("/team", "/leadership", "/people", "/about", "/org-chart", "/org")):
        if any(k in text for k in ORG_KEYWORDS) or any(x in text for x in ("director", "manager", "head of", "team", "department", "press office", "communications", "finance")):
            return "ORG_CUE"
        return "ORG_CUE"
    if any(k in text for k in ORG_KEYWORDS) or any(x in text for x in ("director", "manager", "head of", "press office", "communications", "finance team", "reservations team", "concierge", "dpo")):
        return "ORG_CUE"

    # Process cues: require at least one process verb + one business action term (avoid generic mentions).
    has_verb = any(v in text for v in PROCESS_VERBS)
    has_term = any(k in text for k in PROCESS_KEYWORDS) or any(k in path for k in ("/billing", "/refund", "/procurement", "/onboarding", "/support", "/help", "/booking", "/reservation"))
    strong_phrase = any(p in text for p in ("refund policy", "billing inquiries", "purchase order", "reservation change", "account change", "verification process"))
    if strong_phrase or (has_verb and has_term):
        return "PROCESS_CUE"

    # Conservative fallback: do not assume a signal type when ambiguous.
    return "UNCLASSIFIED"


def signal_counts(evidence_items: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ev in evidence_items or []:
        if bool(ev.get("is_boilerplate", False)):
            continue
        try:
            if float(ev.get("weight", 1.0) or 1.0) < 0.2:
                continue
        except Exception:
            pass
        qt = str(ev.get("quality_tier", "") or "").strip().upper()
        if qt == "BOILERPLATE":
            continue
        st = str(ev.get("signal_type") or "").strip().upper()
        if not st:
            st = infer_signal_type(str(ev.get("url", "")), str(ev.get("snippet", "")), query_id=str(ev.get("query_id", "")))
        if st not in SIGNAL_TYPES:
            continue
        counts[st] = counts.get(st, 0) + 1
    return counts


def signal_diversity_count(evidence_items: list[dict[str, Any]]) -> int:
    counts = signal_counts(evidence_items)
    return len([k for k, v in counts.items() if v > 0])


def repetition_ratio(evidence_items: list[dict[str, Any]]) -> float:
    counts = signal_counts(evidence_items)
    total = sum(counts.values()) or 0
    if total <= 0:
        return 0.0
    dom = max(counts.values()) if counts else 0
    return float(dom) / float(total)


def _domain_from_url(url: str) -> str:
    host, _path, _raw = _url_parts(url)
    return host or ""


def domain_repetition_ratio(evidence_items: list[dict[str, Any]]) -> float:
    total = 0
    counts: dict[str, int] = {}
    for ev in evidence_items or []:
        u = str(ev.get("url", "") or "")
        dom = _domain_from_url(u)
        if not dom:
            continue
        counts[dom] = counts.get(dom, 0) + 1
        total += 1
    if total <= 0:
        return 0.0
    dom_max = max(counts.values()) if counts else 0
    return float(dom_max) / float(total)


def missing_signals_for_confidence(counts: dict[str, int]) -> list[str]:
    present = {k for k, v in (counts or {}).items() if v > 0}
    missing = []
    for key in ("PROCESS_CUE", "VENDOR_CUE", "ORG_CUE"):
        if key not in present:
            missing.append(SIGNAL_LABELS.get(key, key))
    return missing


def compute_hypothesis_confidence(
    evidence_items: list[dict[str, Any]],
    *,
    base_avg: int,
    sector: str = "",
    risk_type: str = "",
) -> tuple[int, dict[str, Any]]:
    """
    Evidence-first confidence score (weighted) that separates repetition from convergence.
    Returns (confidence, meta).
    """
    def _valid(ev: dict[str, Any]) -> bool:
        try:
            if bool(ev.get("is_boilerplate", False)):
                return False
            if str(ev.get("quality_tier", "") or "").strip().upper() == "BOILERPLATE":
                return False
            w = float(ev.get("weight", 1.0) or 1.0)
            return w >= 0.5
        except Exception:
            return True

    valid_items = [ev for ev in (evidence_items or []) if isinstance(ev, dict) and _valid(ev)]

    counts = signal_counts(valid_items)
    diversity = len([k for k, v in counts.items() if v > 0])
    sig_dom_ratio = repetition_ratio(valid_items)
    dom_ratio = domain_repetition_ratio(valid_items)

    # Distinct URLs (boilerplate excluded by `valid_items`)
    def _url_key(u: str) -> str:
        host, path, _raw = _url_parts(str(u or ""))
        if not host:
            return ""
        return f"{host}{path}"

    distinct_urls = {k for k in (_url_key(ev.get("url", "")) for ev in valid_items) if k}
    distinct_url_count = len(distinct_urls)

    has_contact = counts.get("CONTACT_CHANNEL", 0) > 0
    has_social = counts.get("SOCIAL_TRUST_NODE", 0) > 0
    has_process = counts.get("PROCESS_CUE", 0) > 0
    has_vendor = counts.get("VENDOR_CUE", 0) > 0
    has_org = counts.get("ORG_CUE", 0) > 0
    has_critical = bool(has_process or has_vendor or has_org)
    attention_spike = counts.get("EXTERNAL_ATTENTION", 0) >= 2

    # Required signal type per scenario class (conservative): most elevated claims require at least one critical cue.
    rt = str(risk_type or "").strip().lower()
    requires_critical = rt in {
        "impersonation",
        "downstream_pivot",
        "fraud_process",
        "credential_theft_risk",
        "social_engineering_risk",
        "privacy_data_risk",
    }
    missing_required = bool(requires_critical and not has_critical)

    # Boilerplate/meta evidence should not inflate: start from a fixed baseline.
    confidence = 55
    confidence += 6 * max(0, diversity - 1)
    confidence += 5 * max(0, min(3, distinct_url_count - 1))

    repetition_penalty_applied = False
    if (sig_dom_ratio > 0.60) or (dom_ratio > 0.60):
        confidence -= 10
        repetition_penalty_applied = True

    if missing_required:
        confidence -= 8

    # Caps
    channel_only = bool((has_contact or has_social) and not (has_process or has_vendor or has_org) and sum(counts.values()) > 0)

    # Policy-only: all distinct urls are policies (best-effort).
    policy_only = False
    if distinct_urls:
        policy_only = all(any(x in u for x in ("/privacy", "/terms", "/cookie", "/polic", "/gdpr")) for u in distinct_urls)

    if channel_only:
        confidence = min(confidence, 65)
    if policy_only:
        confidence = min(confidence, 70)

    # >75 only if >=2 distinct URLs AND at least one critical cue.
    if confidence > 75 and not (distinct_url_count >= 2 and has_critical):
        confidence = 75

    confidence = max(1, min(100, int(confidence)))

    meta = {
        "signal_counts": counts,
        "signal_diversity_count": diversity,
        "weighted_evidence_count": len(valid_items),
        "distinct_url_count": distinct_url_count,
        "repetition_ratio": round(sig_dom_ratio, 3),
        "domain_repetition_ratio": round(dom_ratio, 3),
        "repetition_penalty_applied": bool(repetition_penalty_applied),
        "missing_required_signal": bool(missing_required),
        "has_critical_signal": bool(has_critical),
        "has_process_cue": bool(has_process),
        "attention_spike": bool(attention_spike),
        "contact_only": bool(channel_only),
        "mostly_contact_only": bool(channel_only),
        "policy_only": bool(policy_only),
        "missing_signals": missing_signals_for_confidence(counts) if diversity < 3 else [],
    }
    return confidence, meta


def coverage_label_from_signals(meta: dict[str, Any]) -> str:
    diversity = int(meta.get("signal_diversity_count", 0) or 0)
    total = sum((meta.get("signal_counts") or {}).values()) if isinstance(meta.get("signal_counts"), dict) else 0
    has_critical = bool(meta.get("has_critical_signal", False))
    if diversity >= 3 and total >= 4 and has_critical:
        return "STRONG"
    if diversity == 2 and total >= 3:
        return "OK"
    return "WEAK"


def timeline_for_risk(risk_type: str, meta: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Deterministic, non-offensive exploitation timeline for stakeholder communication.
    """
    rkey = (risk_type or "other").strip().lower()
    counts = meta.get("signal_counts") if isinstance(meta.get("signal_counts"), dict) else {}
    present = {k for k, v in (counts or {}).items() if int(v or 0) > 0}
    diversity = int(meta.get("signal_diversity_count", 0) or 0)

    has_contact = "CONTACT_CHANNEL" in present
    has_process = "PROCESS_CUE" in present
    has_org = "ORG_CUE" in present
    has_vendor = "VENDOR_CUE" in present
    has_attention = "EXTERNAL_ATTENTION" in present
    is_downstream = rkey in {"downstream_pivot"} or "client" in (meta.get("risk_hint", "") or "").lower()
    sens_kinds = meta.get("data_sens_kinds") if isinstance(meta.get("data_sens_kinds"), list) else []
    has_cred = any(str(x).upper() == "CREDENTIALS" for x in sens_kinds)
    has_booking = any(str(x).upper() == "BOOKING_PAYMENT" for x in sens_kinds)

    contact_only = diversity <= 1 and has_contact and not (has_process or has_org or has_vendor or has_attention)

    steps: list[dict[str, Any]] = []

    if has_attention:
        steps.append(
            {
                "step_index": 1,
                "title": "Timing with public updates",
                "brief": "Leverage periods of high visibility to blend in.",
                "tooltip": "Press coverage or public updates can increase inbound volume and urgency. This can raise the chance of confusion in external communications.",
                "control_point": False,
            }
        )

    steps.append(
        {
            "step_index": 2,
            "title": "Observe public signals",
            "brief": "Map official channels, roles, and workflow hints.",
            "tooltip": "Public pages, documents, and metadata can expose contact paths, role names, vendor tooling cues, and process language. This can be collected without privileged access.",
            "control_point": False,
        }
    )

    if has_cred:
        steps.append(
            {
                "step_index": 3,
                "title": "Account handling pressure",
                "brief": "Exploit confusion around login, reset, or account requests.",
                "tooltip": "Where public content references account access or password handling, there is a higher chance of confusion. Strong verification and clear 'never ask' guidance should reduce this risk.",
                "control_point": True,
            }
        )
    elif has_booking:
        steps.append(
            {
                "step_index": 3,
                "title": "Booking/payment context",
                "brief": "Align a request to booking, billing, or payment flows.",
                "tooltip": "When booking or payment workflows are publicly described, an adversary may align a request to those flows. Verification and approvals should interrupt sensitive changes.",
                "control_point": True,
            }
        )

    if has_org:
        steps.append(
            {
                "step_index": 4,
                "title": "Role-based selection",
                "brief": "Pick a scenario aligned to visible teams and duties.",
                "tooltip": "Role cues (finance, reservations, procurement, comms) can help an adversary choose a believable interaction type. Defensive controls should not treat role-based plausibility as verification.",
                "control_point": False,
            }
        )

    steps.append(
        {
            "step_index": 5,
            "title": "Select a likely scenario",
            "brief": "Choose a routine request tied to business context.",
            "tooltip": "Scenarios typically align to support updates, account changes, billing clarifications, service delivery confirmation, or policy-related requests. This remains an opportunity, not proof of malicious activity.",
            "control_point": False,
        }
    )

    if has_contact:
        steps.append(
            {
                "step_index": 6,
                "title": "Channel confusion",
                "brief": "Exploit ambiguity in official communication channels.",
                "tooltip": "If recipients do not have a single authoritative channel list, a confusing sender identity or alternative contact path can be mistaken as official. Verification and known-good callback channels should interrupt here.",
                "control_point": True,
            }
        )

    if has_vendor:
        steps.append(
            {
                "step_index": 7,
                "title": "Vendor cue plausibility",
                "brief": "Reference vendor/process cues to appear consistent.",
                "tooltip": "Mentions of known helpdesk/payment/booking tooling can make a request feel consistent. Treat vendor familiarity as untrusted; require verification for sensitive actions.",
                "control_point": True,
            }
        )

    if has_process:
        steps.append(
            {
                "step_index": 8,
                "title": "High-impact workflow",
                "brief": "Target an action where approvals are often weak.",
                "tooltip": "High-impact actions include billing changes, refunds, reservation changes, procurement updates, or urgent confirmations. Controls should interrupt with verification, approvals, and logging.",
                "control_point": True,
            }
        )
    elif contact_only:
        steps.append(
            {
                "step_index": 8,
                "title": "Verification gap",
                "brief": "Rely on missing out-of-band verification for requests.",
                "tooltip": "When only contact channels are visible (without process/vendor/org cues), abuse potential depends heavily on whether sensitive requests are verified via an independent channel.",
                "control_point": True,
            }
        )

    steps.append(
        {
            "step_index": 9,
            "title": "Impact and churn",
            "brief": "Cause trust damage or operational disruption.",
            "tooltip": "Even failed attempts can create workload and reputational impact. The likely outcome depends on the targeted workflow and verification controls.",
            "control_point": False,
        }
    )

    if is_downstream:
        steps.append(
            {
                "step_index": 10,
                "title": "Extend to clients/partners",
                "brief": "Reuse the same signals against external audiences.",
                "tooltip": "Where the organization serves clients/beneficiaries, public signals may be reused to target those audiences. Client safety controls should reduce trust in unverified channels.",
                "control_point": True,
            }
        )

    for idx, s in enumerate(steps, start=1):
        s["step_index"] = idx
    return steps[:8]


def safe_json_dumps(obj: Any, default: str) -> str:
    try:
        return json.dumps(obj, ensure_ascii=True)
    except Exception:
        return default
