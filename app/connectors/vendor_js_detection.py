from __future__ import annotations

from datetime import datetime
from collections import defaultdict

from sqlalchemy import select

from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.db import SessionLocal
from app.models import Document

VENDORS: dict[str, tuple[str, ...]] = {
    "Zendesk": ("zendesk",),
    "Freshdesk": ("freshdesk", "freshworks"),
    "Intercom": ("intercom",),
    "HubSpot": ("hubspot",),
    "Salesforce": ("salesforce",),
    "Google Analytics/Tag Manager": ("google-analytics", "googletagmanager", "gtm.js"),
    "Cloudflare": ("cloudflare",),
    "reCAPTCHA": ("recaptcha",),
    "Stripe": ("stripe",),
    "Segment": ("segment.com",),
}


class VendorJsDetectionConnector(ConnectorBase):
    name = "vendor_js_detection"
    description = "Detects third-party vendor JavaScript/provider footprints from collected website documents"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        if not target.assessment_id:
            target.log_examination(
                url="connector://vendor_js_detection",
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
                url="connector://vendor_js_detection",
                source_type="manual",
                status="skipped",
                discovered_from="collector_v2 output",
                parse_summary="no html documents available",
                fetched_at=datetime.utcnow(),
            )
            return []

        hits_by_vendor: dict[str, list[Document]] = defaultdict(list)
        for doc in docs:
            low = f"{doc.title} {doc.extracted_text}".lower()
            for vendor, markers in VENDORS.items():
                if any(marker in low for marker in markers):
                    hits_by_vendor[vendor].append(doc)

        evidences: list[EvidencePayload] = []
        for vendor, rows in hits_by_vendor.items():
            top = rows[0]
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="touchpoint",
                    title=f"Vendor JS/provider footprint: {vendor}",
                    snippet=f"{vendor} markers found across {len(rows)} collected pages.",
                    source_url=top.url,
                    confidence=79 if len(rows) > 1 else 72,
                    raw={"vendor": vendor, "doc_ids": [x.id for x in rows[:20]]},
                )
            )
            # Keep a direct per-page signal for provenance/correlation.
            for doc in rows[:3]:
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="touchpoint",
                        title=f"{vendor} marker in page",
                        snippet=f"Collected page includes {vendor} provider marker in visible/normalized content.",
                        source_url=doc.url,
                        confidence=70,
                        raw={"vendor": vendor, "doc_id": doc.id},
                    )
                )

        target.log_examination(
            url="connector://vendor_js_detection",
            source_type="manual",
            status="parsed",
            discovered_from="collector_v2 output",
            parse_summary=f"html_docs={len(docs)} vendor_hits={len(hits_by_vendor)} evidences={len(evidences)}",
            fetched_at=datetime.utcnow(),
        )

        return evidences[:80]
