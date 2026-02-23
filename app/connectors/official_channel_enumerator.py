from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import select

from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.connectors.utils import canonical_domain_for_api
from app.db import SessionLocal
from app.models import Document


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.IGNORECASE)
HTTP_URL_RE = re.compile(r"https?://[^\s<>'\"()]+", re.IGNORECASE)
MAILTO_RE = re.compile(r"mailto:([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)

SOCIAL_HOSTS = (
    "instagram.com",
    "facebook.com",
    "linkedin.com",
    "x.com",
    "twitter.com",
    "youtube.com",
    "tiktok.com",
)
DIRECT_MESSAGE_HOSTS = (
    "api.whatsapp.com",
    "wa.me",
    "whatsapp.com",
    "t.me",
    "telegram.me",
    "messenger.com",
    "m.me",
)


def _path(url: str) -> str:
    try:
        return (urlparse(url).path or "/").lower()
    except Exception:
        return "/"


def _host(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower().split(":")[0]
    except Exception:
        return ""


def _is_homepage(url: str, domain: str) -> bool:
    p = _path(url)
    h = _host(url)
    if h.startswith("www."):
        h = h[4:]
    return p in {"", "/"} and (not domain or h == domain or h.endswith(f".{domain}"))


class OfficialChannelEnumeratorConnector(ConnectorBase):
    name = "official_channel_enumerator"
    description = "Enumerates official public contact channels and flags channel ambiguity/direct-message workflows."

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        if not target.assessment_id:
            target.log_examination(
                url="connector://official_channel_enumerator",
                source_type="manual",
                status="skipped",
                discovered_from="connector-run",
                parse_summary="missing assessment_id for document lookup",
                fetched_at=datetime.utcnow(),
            )
            return []

        with SessionLocal() as db:
            docs = db.execute(
                select(Document).where(
                    Document.assessment_id == target.assessment_id,
                    Document.doc_type == "html",
                )
            ).scalars().all()

        if not docs:
            target.log_examination(
                url="connector://official_channel_enumerator",
                source_type="manual",
                status="skipped",
                discovered_from="collector_v2 output",
                parse_summary="no html documents available",
                fetched_at=datetime.utcnow(),
            )
            return []

        domain = canonical_domain_for_api(target.domain)
        homepage_docs = [d for d in docs if _is_homepage(d.url, domain)]
        homepage = homepage_docs[0] if homepage_docs else docs[0]
        home_text = f"{homepage.title} {homepage.extracted_text or ''}"

        # Enumerate public channels from homepage-like content.
        url_hits = HTTP_URL_RE.findall(home_text)
        social_links = sorted(
            {
                u
                for u in url_hits
                if any((_host(u) == h or _host(u).endswith(f".{h}")) for h in SOCIAL_HOSTS)
            }
        )
        dm_links = sorted(
            {
                u
                for u in url_hits
                if any((_host(u) == h or _host(u).endswith(f".{h}")) for h in DIRECT_MESSAGE_HOSTS)
            }
        )
        dm_links += [
            f"https://{_host(u)}"
            for u in url_hits
            if "whatsapp" in u.lower() or "telegram" in u.lower() or "messenger" in u.lower()
        ]
        dm_links = sorted({u for u in dm_links if u})

        emails_global = sorted(
            {
                e.lower()
                for d in docs
                for e in (EMAIL_RE.findall(d.extracted_text or "") + MAILTO_RE.findall(d.extracted_text or ""))
            }
        )

        keyed_emails: dict[str, set[str]] = {"privacy": set(), "support": set(), "info": set()}
        for d in docs:
            low = f"{d.url} {d.title} {d.extracted_text}".lower()
            emails = {
                e.lower()
                for e in (EMAIL_RE.findall(d.extracted_text or "") + MAILTO_RE.findall(d.extracted_text or ""))
            }
            if not emails:
                continue
            if any(k in low for k in ("privacy", "gdpr", "data protection")):
                keyed_emails["privacy"].update(emails)
            if any(k in low for k in ("support", "help", "helpdesk", "ticket")):
                keyed_emails["support"].update(emails)
            if any(k in low for k in ("contact", "info@", "about")):
                keyed_emails["info"].update(emails)

        evidences: list[EvidencePayload] = []

        if len(emails_global) > 1:
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="touchpoint",
                    title="Official channel ambiguity signal: multiple contact emails",
                    snippet=f"Multiple distinct public contact emails detected: {', '.join(emails_global[:5])}",
                    source_url=homepage.url,
                    confidence=67,
                    raw={
                        "signal_type": "CHANNEL_AMBIGUITY_SIGNAL",
                        "emails": emails_global[:20],
                        "source": "homepage+html",
                    },
                )
            )

        if dm_links:
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="touchpoint",
                    title="Direct message workflow signal: public DM channel detected",
                    snippet=f"Public direct-message channel detected ({_host(dm_links[0])}); verify official channel guidance.",
                    source_url=dm_links[0],
                    confidence=64,
                    raw={
                        "signal_type": "DIRECT_MESSAGE_WORKFLOW_SIGNAL",
                        "dm_links": dm_links[:20],
                        "social_links": social_links[:20],
                    },
                )
            )

        different_across_pages = False
        non_empty_sets = [v for v in keyed_emails.values() if v]
        if len(non_empty_sets) >= 2:
            union = set().union(*non_empty_sets)
            inter = set(non_empty_sets[0]).intersection(*non_empty_sets[1:])
            different_across_pages = len(union - inter) > 0

        if different_across_pages:
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="touchpoint",
                    title="Official channel ambiguity signal: contact emails differ by page context",
                    snippet="Public emails vary across privacy/support/info pages, increasing channel ambiguity.",
                    source_url=homepage.url,
                    confidence=69,
                    raw={
                        "signal_type": "CHANNEL_AMBIGUITY_SIGNAL",
                        "emails_by_context": {k: sorted(list(v))[:10] for k, v in keyed_emails.items()},
                    },
                )
            )

        target.log_examination(
            url="connector://official_channel_enumerator",
            source_type="html",
            status="parsed",
            discovered_from="homepage html parse",
            parse_summary=(
                f"html_docs={len(docs)} social_links={len(social_links)} dm_links={len(dm_links)} "
                f"emails={len(emails_global)} evidences={len(evidences)}"
            ),
            fetched_at=datetime.utcnow(),
        )
        return evidences
