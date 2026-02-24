import re
from datetime import datetime

from sqlalchemy import select

from app.db import SessionLocal
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.models import Document

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

PROVIDER_HINTS = {
    "googletagmanager": "Google Tag Manager",
    "google-analytics": "Google Analytics",
    "recaptcha": "Google reCAPTCHA",
    "zendesk": "Zendesk",
    "intercom": "Intercom",
    "hubspot": "HubSpot",
    "freshdesk": "Freshdesk",
}


class WebsiteAnalyzerConnector(ConnectorBase):
    name = "website_analyzer"
    description = "Builds website public information exposure indicators from collector_v2 normalized HTML documents"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        if not target.assessment_id:
            target.log_examination(
                url="connector://website_analyzer",
                source_type="manual",
                status="skipped",
                discovered_from="connector-run",
                parse_summary="missing assessment_id for document lookup",
                fetched_at=datetime.utcnow(),
            )
            return []

        with SessionLocal() as db:
            docs = (
                db.execute(
                    select(Document).where(
                        Document.assessment_id == target.assessment_id,
                        Document.doc_type == "html",
                    )
                )
                .scalars()
                .all()
            )

        if not docs:
            target.log_examination(
                url="connector://website_analyzer",
                source_type="manual",
                status="skipped",
                discovered_from="collector_v2 output",
                parse_summary="no html documents available",
                fetched_at=datetime.utcnow(),
            )
            return []

        evidences: list[EvidencePayload] = []
        seen_emails: set[str] = set()
        seen_providers: set[str] = set()
        seen_touchpoints: set[str] = set()

        for doc in docs:
            lower = (doc.extracted_text or "").lower()
            if not lower:
                continue

            for email in EMAIL_RE.findall(lower):
                if email in seen_emails:
                    continue
                seen_emails.add(email)
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title="Public contact email exposed in website content",
                        snippet=f"Found public email: {email}",
                        source_url=doc.url,
                        confidence=90,
                        raw={"email": email, "document_id": doc.id},
                    )
                )

            for marker, provider in PROVIDER_HINTS.items():
                if marker in lower and provider not in seen_providers:
                    seen_providers.add(provider)
                    evidences.append(
                        EvidencePayload(
                            connector=self.name,
                            category="touchpoint",
                            title=f"Third-party provider detected: {provider}",
                            snippet=f"Provider marker '{marker}' found in normalized document text.",
                            source_url=doc.url,
                            confidence=76,
                            raw={"provider": provider, "marker": marker, "document_id": doc.id},
                        )
                    )

            for keyword in ("support", "billing", "helpdesk", "contact", "careers"):
                if keyword in lower and keyword not in seen_touchpoints:
                    seen_touchpoints.add(keyword)
                    evidences.append(
                        EvidencePayload(
                            connector=self.name,
                            category="touchpoint",
                            title=f"Public external contact channel exposed: {keyword}",
                            snippet=f"'{keyword}' external contact channel appears in public website content.",
                            source_url=doc.url,
                            confidence=70,
                            raw={"keyword": keyword, "document_id": doc.id},
                        )
                    )

        target.log_examination(
            url="connector://website_analyzer",
            source_type="manual",
            status="parsed",
            discovered_from="collector_v2 output",
            parse_summary=f"documents={len(docs)} evidences={len(evidences)}",
            fetched_at=datetime.utcnow(),
        )

        return evidences[:80]
