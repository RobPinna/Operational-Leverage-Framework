import re
from datetime import datetime

from sqlalchemy import select

from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.db import SessionLocal
from app.models import Document

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class PublicDocsPdfConnector(ConnectorBase):
    name = "public_docs_pdf"
    description = "Builds IOC/external-contact-channel evidence from collector_v2 normalized PDF documents"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        if not target.assessment_id:
            target.log_examination(
                url="connector://public_docs_pdf",
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
                        Document.doc_type == "pdf",
                    )
                )
                .scalars()
                .all()
            )

        if not docs:
            target.log_examination(
                url="connector://public_docs_pdf",
                source_type="manual",
                status="skipped",
                discovered_from="collector_v2 output",
                parse_summary="no pdf documents available",
                fetched_at=datetime.utcnow(),
            )
            return []

        evidences: list[EvidencePayload] = []
        touchpoint_keywords = {
            "billing": "Billing external contact channel appears in public document text",
            "invoice": "Invoice processing external contact channel appears in public document text",
            "support": "Support process external contact channel appears in public document text",
            "helpdesk": "Helpdesk process external contact channel appears in public document text",
            "onboarding": "Onboarding process external contact channel appears in public document text",
            "vendor": "Vendor interaction external contact channel appears in public document text",
            "procurement": "Procurement external contact channel appears in public document text",
            "donation": "Donation channel external contact flow appears in public document text",
            "refund": "Refund process external contact channel appears in public document text",
            "beneficiary": "Beneficiary support external contact channel appears in public document text",
        }

        for doc in docs:
            text = (doc.extracted_text or "").strip()
            if not text:
                continue
            lower = text.lower()

            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="exposure",
                    title="Public PDF document parsed",
                    snippet=f"Normalized PDF document available: {doc.title or doc.url}",
                    source_url=doc.url,
                    confidence=70,
                    raw={"document_id": doc.id, "language": doc.language},
                )
            )

            emails = sorted(set(EMAIL_RE.findall(lower)))[:8]
            domains = [d for d in sorted(set(DOMAIN_RE.findall(lower))) if "." in d][:10]
            ips = sorted(set(IPV4_RE.findall(text)))[:10]

            if emails:
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title="IOC from PDF: public emails detected",
                        snippet=", ".join(emails[:5]),
                        source_url=doc.url,
                        confidence=86,
                        raw={"ioc_type": "email", "values": emails, "document_id": doc.id},
                    )
                )

            if domains:
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title="IOC from PDF: domains detected",
                        snippet=", ".join(domains[:6]),
                        source_url=doc.url,
                        confidence=84,
                        raw={"ioc_type": "domain", "values": domains, "document_id": doc.id},
                    )
                )

            if ips:
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title="IOC from PDF: IPv4 addresses detected",
                        snippet=", ".join(ips[:5]),
                        source_url=doc.url,
                        confidence=82,
                        raw={"ioc_type": "ipv4", "values": ips, "document_id": doc.id},
                    )
                )

            for keyword, message in touchpoint_keywords.items():
                if keyword in lower:
                    evidences.append(
                        EvidencePayload(
                            connector=self.name,
                            category="touchpoint",
                            title=f"Document external contact channel indicator: {keyword}",
                            snippet=message,
                            source_url=doc.url,
                            confidence=76,
                            raw={"keyword": keyword, "document_id": doc.id},
                        )
                    )

        target.log_examination(
            url="connector://public_docs_pdf",
            source_type="manual",
            status="parsed",
            discovered_from="collector_v2 output",
            parse_summary=f"documents={len(docs)} evidences={len(evidences)}",
            fetched_at=datetime.utcnow(),
        )

        return evidences[:120]
