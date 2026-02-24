from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.db import SessionLocal
from app.models import Document

PROCUREMENT_TERMS = (
    "procurement",
    "supplier",
    "vendor",
    "tender",
    "rfp",
    "purchase order",
    "invoice",
    "accounts payable",
    "payment instruction",
)

HIGH_RISK_TERMS = (
    "bank account change",
    "payment update",
    "wire",
    "urgent invoice",
    "shared mailbox",
    "email approval",
)


class ProcurementDocumentsConnector(ConnectorBase):
    name = "procurement_documents"
    description = "Extracts procurement-workflow exposure signals from collected HTML/PDF documents"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        if not target.assessment_id:
            target.log_examination(
                url="connector://procurement_documents",
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
                        Document.doc_type.in_(["html", "pdf"]),
                    )
                )
                .scalars()
                .all()
            )

        evidences: list[EvidencePayload] = []
        hit_docs = 0
        for doc in docs:
            low = f"{doc.url} {doc.title} {doc.extracted_text}".lower()
            if not any(term in low for term in PROCUREMENT_TERMS):
                continue
            hit_docs += 1
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="touchpoint",
                    title="Procurement workflow publicly discoverable",
                    snippet=f"Document references procurement/supplier flow: {doc.title or doc.url}",
                    source_url=doc.url,
                    confidence=76,
                    raw={"doc_id": doc.id, "doc_type": doc.doc_type},
                )
            )
            if any(term in low for term in HIGH_RISK_TERMS):
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="pivot",
                        title="Procurement communication abuse risk",
                        snippet=(
                            "Public workflow language includes payment/invoice cues that can be reused in impersonation attempts "
                            "toward suppliers or finance contacts."
                        ),
                        source_url=doc.url,
                        confidence=78,
                        raw={"doc_id": doc.id, "risk": "procurement_impersonation"},
                    )
                )

        target.log_examination(
            url="connector://procurement_documents",
            source_type="manual",
            status="parsed" if hit_docs else "skipped",
            discovered_from="collector_v2 output",
            parse_summary=f"documents={len(docs)} procurement_hits={hit_docs} evidences={len(evidences)}",
            fetched_at=datetime.utcnow(),
        )

        return evidences[:80]
