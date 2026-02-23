from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse


EVIDENCE_KINDS = (
    "WORKFLOW_VENDOR",
    "GENERIC_WEB",
    "CONTENT_DOC",
    "CONTACT_CHANNEL",
    "SECURITY_POSTURE",
    "ORG_ROLE",
    "PROCUREMENT",
    "NEWS_MENTION",
    "UNKNOWN",
)

QUALITY_TIERS = ("HIGH", "MED", "LOW", "BOILERPLATE")

EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.IGNORECASE)
PHONE_RE = re.compile(r"\+?\d[\d\s().-]{7,}\d")

ANALYTICS_HOST_HINTS = (
    "googletagmanager.com",
    "google-analytics.com",
    "doubleclick.net",
    "hotjar.com",
    "clarity.ms",
    "segment.com",
    "amplitude.com",
    "mixpanel.com",
)
ANALYTICS_TEXT_HINTS = (
    "analytics",
    "tracking",
    "tag manager",
    "gtm.js",
    "pixel",
)

CMP_HINTS = (
    "cookie",
    "consent",
    "cmp",
    "onetrust",
    "cookiebot",
    "quantcast",
    "trustarc",
    "iubenda",
    "didomi",
)

CDN_HOST_HINTS = (
    "cdnjs.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "bootstrapcdn.com",
)
CDN_TEXT_HINTS = (
    "jquery",
    "bootstrap",
    "react",
    "vue",
    "cdn",
)

GENERIC_SECURITY_HINTS = (
    "email-decode.min.js",
    "email obfuscation",
    "cloudflare",
    "waf",
)

WORKFLOW_PATH_HINTS = (
    "/checkout",
    "/payment",
    "/donate",
    "/portal",
    "/account",
    "/login",
    "/reset",
    "/support",
    "/ticket",
    "/helpdesk",
    "/help",
    "/booking",
    "/reservation",
)
WORKFLOW_TEXT_HINTS = (
    "checkout",
    "payment",
    "billing",
    "invoice",
    "donate",
    "account",
    "login",
    "reset password",
    "support portal",
    "helpdesk",
    "ticket",
    "booking",
    "reservation",
)

VENDOR_PAYMENT_HINTS = (
    "stripe",
    "adyen",
    "checkout.com",
    "braintree",
    "cybersource",
    "worldpay",
    "ingenico",
    "payfort",
    "hyperpay",
    "tap.company",
    "paypal",
)
VENDOR_HELPDESK_HINTS = (
    "zendesk",
    "freshdesk",
    "intercom",
    "servicenow",
    "jira service management",
    "salesforce",
)
VENDOR_IDENTITY_HINTS = (
    "auth0",
    "okta",
    "azuread",
    "keycloak",
    "cognito",
)
VENDOR_FORMS_HINTS = (
    "hubspot",
    "mailchimp",
    "web-to-lead",
)
VENDOR_GENERIC_HINTS = VENDOR_PAYMENT_HINTS + VENDOR_HELPDESK_HINTS + VENDOR_IDENTITY_HINTS + VENDOR_FORMS_HINTS

NEWS_HINTS = ("news", "press", "media", "headline", "gdelt")
ROLE_HINTS = (
    "finance",
    "billing",
    "accounts payable",
    "procurement",
    "treasury",
    "it support",
    "system admin",
    "infrastructure",
    "security team",
    "helpdesk",
    "dpo",
    "data protection officer",
    "compliance",
    "privacy officer",
    "ceo",
    "director",
    "general manager",
    "managing director",
)
PROCUREMENT_HINTS = ("tender", "rfp", "procurement", "supplier", "vendor onboarding", "purchase order")


@dataclass(slots=True, frozen=True)
class EvidenceQuality:
    evidence_kind: str
    quality_tier: str
    quality_weight: float
    is_boilerplate: bool
    rationale: str


def _norm(value: str) -> str:
    return " ".join(str(value or "").split()).strip().lower()


def _url_parts(url: str) -> tuple[str, str]:
    raw = (url or "").strip()
    if not raw:
        return "", ""
    try:
        p = urlparse(raw)
        host = (p.netloc or "").lower().split(":")[0]
        path = (p.path or "/").lower()
        return host, path
    except Exception:
        return "", raw.lower()


def _contains_any(haystack: str, needles: tuple[str, ...]) -> bool:
    return any(n in haystack for n in needles if n)


def _is_generic_web(*, text: str, host: str, path: str) -> bool:
    if _contains_any(host, ANALYTICS_HOST_HINTS) or _contains_any(text, ANALYTICS_TEXT_HINTS):
        return True
    if _contains_any(text, CMP_HINTS):
        return True
    if _contains_any(host, CDN_HOST_HINTS) or _contains_any(text, CDN_TEXT_HINTS):
        return True
    if _contains_any(text, GENERIC_SECURITY_HINTS):
        return True
    # Generic reCAPTCHA mention is boilerplate unless tied to login/account flow.
    if "recaptcha" in text:
        workflow_context = _contains_any(path, WORKFLOW_PATH_HINTS) or _contains_any(text, WORKFLOW_TEXT_HINTS)
        return not workflow_context
    return False


def _workflow_vendor_class(*, text: str, host: str, path: str) -> tuple[bool, bool]:
    workflow_context = _contains_any(path, WORKFLOW_PATH_HINTS) or _contains_any(text, WORKFLOW_TEXT_HINTS)
    vendor_hint = _contains_any(text, VENDOR_GENERIC_HINTS) or _contains_any(host, VENDOR_GENERIC_HINTS)
    if not vendor_hint:
        return False, False
    high_impact = _contains_any(text, VENDOR_PAYMENT_HINTS + VENDOR_IDENTITY_HINTS) and (
        "payment" in text or "billing" in text or "account" in text or "login" in text or "reset" in text
    )
    if _contains_any(path, ("/payment", "/checkout", "/login", "/reset", "/account", "/donate")):
        high_impact = True
    return True, bool(high_impact or workflow_context)


def classify_evidence(
    *,
    url: str,
    title: str = "",
    snippet: str = "",
    source_type: str = "",
    connector: str = "",
    mime_type: str = "",
    raw: dict[str, Any] | None = None,
    anchor_text: str = "",
) -> EvidenceQuality:
    raw = raw or {}
    host, path = _url_parts(url or str(raw.get("script_src", "") or str(raw.get("url", ""))))
    text = _norm(
        " ".join(
            [
                title or "",
                snippet or "",
                anchor_text or "",
                str(raw.get("html_context", "") or ""),
                str(raw.get("script_src", "") or ""),
                str(raw.get("hostname", "") or ""),
                str(raw.get("path", "") or ""),
                str(connector or ""),
                str(source_type or ""),
            ]
        )
    )
    source = _norm(source_type)
    conn = _norm(connector)
    mime = _norm(mime_type)

    if _is_generic_web(text=text, host=host, path=path):
        weight = 0.05 if (_contains_any(host, ANALYTICS_HOST_HINTS) or _contains_any(text, ANALYTICS_TEXT_HINTS)) else 0.10
        return EvidenceQuality(
            evidence_kind="GENERIC_WEB",
            quality_tier="BOILERPLATE",
            quality_weight=weight,
            is_boilerplate=True,
            rationale="Generic web/analytics/CMP/CDN artifact (non workflow-specific)",
        )

    is_vendor, is_workflow_specific = _workflow_vendor_class(text=text, host=host, path=path)
    if is_vendor and is_workflow_specific:
        high_impact = _contains_any(text, VENDOR_PAYMENT_HINTS + VENDOR_IDENTITY_HINTS) or _contains_any(
            path, ("/payment", "/checkout", "/account", "/login", "/reset", "/donate")
        )
        return EvidenceQuality(
            evidence_kind="WORKFLOW_VENDOR",
            quality_tier="HIGH" if high_impact else "MED",
            quality_weight=0.95 if high_impact else 0.75,
            is_boilerplate=False,
            rationale="Workflow-specific vendor dependency detected",
        )
    if is_vendor:
        return EvidenceQuality(
            evidence_kind="WORKFLOW_VENDOR",
            quality_tier="MED",
            quality_weight=0.65,
            is_boilerplate=False,
            rationale="Vendor indicator present but workflow specificity is limited",
        )

    if conn in {"email_posture_analyzer", "dns_footprint"} or _contains_any(text, ("dmarc", "spf", "dkim", "mx record")):
        weight = 0.70 if _contains_any(text, ("p=reject", "p=quarantine", "email spoofing risk", "no dmarc")) else 0.55
        return EvidenceQuality(
            evidence_kind="SECURITY_POSTURE",
            quality_tier="MED",
            quality_weight=weight,
            is_boilerplate=False,
            rationale="Email/domain posture signal",
        )

    if EMAIL_RE.search(text) or PHONE_RE.search(text) or _contains_any(text, ("mailto:", "whatsapp", "telegram", "messenger", "contact form", "dm")):
        return EvidenceQuality(
            evidence_kind="CONTACT_CHANNEL",
            quality_tier="MED",
            quality_weight=0.55,
            is_boilerplate=False,
            rationale="Official contact channel",
        )

    is_doc = source == "pdf" or ".pdf" in path or "application/pdf" in mime or conn in {"public_docs_pdf", "procurement_documents"}
    if is_doc:
        process_text = _contains_any(text, ("submit request", "payment", "billing", "account recovery", "reservation", "booking", "procurement"))
        is_proc = _contains_any(text, PROCUREMENT_HINTS) or conn == "procurement_documents"
        if is_proc:
            return EvidenceQuality(
                evidence_kind="PROCUREMENT",
                quality_tier="MED",
                quality_weight=0.60,
                is_boilerplate=False,
                rationale="Procurement/supplier document signal",
            )
        return EvidenceQuality(
            evidence_kind="CONTENT_DOC",
            quality_tier="MED" if process_text else "LOW",
            quality_weight=0.60 if process_text else 0.35,
            is_boilerplate=False,
            rationale="Document evidence (policy/process context)",
        )

    if conn in {"gdelt_news", "media_trend"} or source == "news" or _contains_any(text, NEWS_HINTS):
        specific = _contains_any(text, ("staff", "role", "contact", "email", "finance", "it", "dpo", "booking", "payment"))
        return EvidenceQuality(
            evidence_kind="NEWS_MENTION",
            quality_tier="MED" if specific else "LOW",
            quality_weight=0.55 if specific else 0.30,
            is_boilerplate=False,
            rationale="Media/news mention signal",
        )

    if _contains_any(text, ROLE_HINTS) or conn == "public_role_extractor":
        return EvidenceQuality(
            evidence_kind="ORG_ROLE",
            quality_tier="MED",
            quality_weight=0.60,
            is_boilerplate=False,
            rationale="Public role/organization cue",
        )

    if source == "html":
        return EvidenceQuality(
            evidence_kind="GENERIC_WEB",
            quality_tier="LOW",
            quality_weight=0.30,
            is_boilerplate=False,
            rationale="Generic website context",
        )

    return EvidenceQuality(
        evidence_kind="UNKNOWN",
        quality_tier="LOW",
        quality_weight=0.50,
        is_boilerplate=False,
        rationale="Unclassified evidence pattern",
    )
