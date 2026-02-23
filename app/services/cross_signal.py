from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import Assessment, CrossSignalCorrelation, Evidence
from app.utils.jsonx import to_json

VENDOR_KEYWORDS: dict[str, tuple[str, ...]] = {
    "zendesk": ("zendesk",),
    "freshdesk": ("freshdesk", "freshworks"),
    "intercom": ("intercom",),
    "salesforce": ("salesforce",),
    "hubspot": ("hubspot",),
    "servicenow": ("servicenow",),
    "okta": ("okta",),
    "cloudflare": ("cloudflare",),
    "google": ("googletagmanager", "google-analytics", "recaptcha"),
}

CHANNEL_TERMS = ("support", "billing", "helpdesk", "refund", "onboarding", "portal", "customer", "partner")

SIGNAL_LABELS = {
    "job_posting": "Job postings",
    "dns_subdomain": "Subdomains/DNS",
    "vendor_js": "Website vendor scripts",
    "media": "Media trend",
    "procurement_doc": "Procurement documents",
}

HELPDESK_VENDORS = {"zendesk", "freshdesk", "intercom", "servicenow", "salesforce"}


def _signal_type(ev: Evidence) -> str:
    if ev.connector == "job_postings_live":
        return "job_posting"
    if ev.connector in {"dns_footprint", "subdomain_discovery", "shodan"} or (ev.source_url or "").startswith("dns://"):
        return "dns_subdomain"
    if ev.connector == "vendor_js_detection":
        return "vendor_js"
    if ev.connector == "procurement_documents":
        return "procurement_doc"
    if ev.connector in {"gdelt_news", "media_trend", "social_mock"} or ev.category == "mention":
        return "media"
    return "other"


def _evidence_text(ev: Evidence) -> str:
    return f"{ev.title} {ev.snippet} {ev.source_url}".lower()


def _extract_vendors(ev: Evidence) -> set[str]:
    low = _evidence_text(ev)
    hits: set[str] = set()
    for vendor, markers in VENDOR_KEYWORDS.items():
        if any(marker in low for marker in markers):
            hits.add(vendor)
    return hits


def _has_channel_terms(ev: Evidence) -> bool:
    low = _evidence_text(ev)
    return any(term in low for term in CHANNEL_TERMS)


def _host_from_url(value: str) -> str:
    try:
        host = urlparse(value or "").netloc.lower().split(":")[0]
        return host
    except Exception:
        return ""


def build_cross_signal_correlations(db: Session, assessment: Assessment) -> int:
    rows = db.execute(
        select(Evidence).where(Evidence.assessment_id == assessment.id).order_by(Evidence.confidence.desc(), Evidence.id.desc())
    ).scalars().all()

    db.execute(delete(CrossSignalCorrelation).where(CrossSignalCorrelation.assessment_id == assessment.id))
    db.commit()
    if not rows:
        return 0

    vendor_signal_refs: dict[str, dict[str, list[Evidence]]] = defaultdict(lambda: defaultdict(list))
    for ev in rows:
        sig = _signal_type(ev)
        if sig == "other":
            continue
        for vendor in _extract_vendors(ev):
            vendor_signal_refs[vendor][sig].append(ev)

    created = 0
    used_keys: set[str] = set()

    for vendor, by_signal in vendor_signal_refs.items():
        active_signals = [name for name, values in by_signal.items() if values]
        if len(active_signals) < 2:
            continue

        refs: list[int] = []
        signal_lines: list[str] = []
        has_client_channel = False
        for name in active_signals:
            ev = by_signal[name][0]
            signal_lines.append(f"{SIGNAL_LABELS.get(name, name)}: {ev.title}")
            has_client_channel = has_client_channel or _has_channel_terms(ev)
            refs.extend([x.id for x in by_signal[name][:3]])

        risk_level = min(5, 2 + len(active_signals) + (1 if has_client_channel else 0))
        key = f"vendor:{vendor}"
        if key in used_keys:
            continue
        used_keys.add(key)

        summary = (
            f"{vendor.title()} appears consistently across {len(active_signals)} independent signal families. "
            "This increases confidence that attackers can craft believable identity abuse narratives."
        )
        db.add(
            CrossSignalCorrelation(
                assessment_id=assessment.id,
                correlation_key=key,
                title=f"{vendor.title()} cross-signal correlation",
                summary=summary,
                risk_level=risk_level,
                signals_json=to_json(signal_lines[:8]),
                evidence_refs_json=to_json(sorted(set(refs))[:12]),
            )
        )
        created += 1

    # Pattern correlation requested: job posting + DNS/subdomain + website vendor JS.
    job_hits = [ev for ev in rows if _signal_type(ev) == "job_posting" and _has_channel_terms(ev)]
    dns_hits = [ev for ev in rows if _signal_type(ev) == "dns_subdomain" and _has_channel_terms(ev)]
    js_hits = [
        ev for ev in rows
        if _signal_type(ev) == "vendor_js" and (_extract_vendors(ev) & HELPDESK_VENDORS)
    ]
    if job_hits and dns_hits and js_hits and "pattern:support_impersonation" not in used_keys:
        refs = [job_hits[0].id, dns_hits[0].id, js_hits[0].id]
        dns_host = _host_from_url(dns_hits[0].source_url) or dns_hits[0].source_url
        db.add(
            CrossSignalCorrelation(
                assessment_id=assessment.id,
                correlation_key="pattern:support_impersonation",
                title="Support-channel impersonation correlation",
                summary=(
                    "Hiring language, DNS/subdomain exposure, and website support-vendor signals align on external support channels. "
                    "This pattern can increase risk to clients via impersonation."
                ),
                risk_level=5,
                signals_json=to_json(
                    [
                        f"Job postings: {job_hits[0].title}",
                        f"Subdomains/DNS: {dns_hits[0].title} ({dns_host})",
                        f"Website vendor scripts: {js_hits[0].title}",
                    ]
                ),
                evidence_refs_json=to_json(refs),
            )
        )
        created += 1

    # Procurement + media narrative pressure correlation.
    procurement_hits = [ev for ev in rows if _signal_type(ev) == "procurement_doc"]
    media_hits = [ev for ev in rows if _signal_type(ev) == "media"]
    if procurement_hits and media_hits and "pattern:procurement_media" not in used_keys:
        refs = [procurement_hits[0].id, media_hits[0].id]
        db.add(
            CrossSignalCorrelation(
                assessment_id=assessment.id,
                correlation_key="pattern:procurement_media",
                title="Procurement workflow and media-pressure correlation",
                summary=(
                    "Public procurement process details and active external narratives coexist, which may make fraudulent supplier-facing pretexts "
                    "more believable to third parties."
                ),
                risk_level=4,
                signals_json=to_json(
                    [
                        f"Procurement docs: {procurement_hits[0].title}",
                        f"Media trend: {media_hits[0].title}",
                    ]
                ),
                evidence_refs_json=to_json(refs),
            )
        )
        created += 1

    db.commit()
    return created

