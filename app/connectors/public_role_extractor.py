from __future__ import annotations

import re
from datetime import datetime

from sqlalchemy import select

from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.db import SessionLocal
from app.models import Document, Evidence


ROLE_PATTERNS: dict[str, tuple[str, ...]] = {
    "finance": (
        "finance",
        "billing",
        "accounts payable",
        "procurement",
        "treasury",
    ),
    "it": (
        "it support",
        "system admin",
        "infrastructure",
        "security",
        "helpdesk",
    ),
    "privacy": (
        "dpo",
        "data protection officer",
        "compliance",
        "privacy officer",
    ),
    "executive": (
        "ceo",
        "director",
        "general manager",
        "managing director",
    ),
}


def _looks_like_job(url: str, title: str, text: str) -> bool:
    value = f"{url} {title} {text}".lower()
    return any(token in value for token in ("/careers", "/jobs", "job posting", "vacancy", "hiring"))


def _looks_like_news(url: str, connector: str) -> bool:
    value = (url or "").lower()
    return connector in {"gdelt_news", "media_trend"} or any(k in value for k in ("/news", "/press", "/media", "gdeltproject.org"))


class PublicRoleExtractorConnector(ConnectorBase):
    name = "public_role_extractor"
    description = "Extracts publicly visible role targetability cues from website/jobs/PDF/news content."

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        if not target.assessment_id:
            target.log_examination(
                url="connector://public_role_extractor",
                source_type="manual",
                status="skipped",
                discovered_from="connector-run",
                parse_summary="missing assessment_id for content lookup",
                fetched_at=datetime.utcnow(),
            )
            return []

        with SessionLocal() as db:
            docs = db.execute(
                select(Document).where(Document.assessment_id == target.assessment_id)
            ).scalars().all()
            news_rows = db.execute(
                select(Evidence).where(
                    Evidence.assessment_id == target.assessment_id,
                    Evidence.connector.in_(["gdelt_news", "media_trend"]),
                )
            ).scalars().all()
            job_rows = db.execute(
                select(Evidence).where(
                    Evidence.assessment_id == target.assessment_id,
                    Evidence.connector == "job_postings_live",
                )
            ).scalars().all()

        if not docs and not news_rows and not job_rows:
            target.log_examination(
                url="connector://public_role_extractor",
                source_type="manual",
                status="skipped",
                discovered_from="collector_v2 output",
                parse_summary="no source content available",
                fetched_at=datetime.utcnow(),
            )
            return []

        source_rows: list[dict[str, str | int]] = []
        for doc in docs:
            text = f"{doc.title} {doc.extracted_text}".strip()
            if not text:
                continue
            source = "website"
            if doc.doc_type == "pdf":
                source = "pdf"
            elif _looks_like_job(doc.url, doc.title, text):
                source = "job"
            elif _looks_like_news(doc.url, ""):
                source = "news"
            source_rows.append(
                {
                    "source": source,
                    "url": doc.url,
                    "title": doc.title or "Document",
                    "text": text[:10000],
                    "doc_id": int(doc.id),
                }
            )

        for ev in job_rows:
            source_rows.append(
                {
                    "source": "job",
                    "url": ev.source_url or "",
                    "title": ev.title or "Job posting",
                    "text": f"{ev.title} {ev.snippet}",
                    "doc_id": 0,
                }
            )

        for ev in news_rows:
            source_rows.append(
                {
                    "source": "news",
                    "url": ev.source_url or "",
                    "title": ev.title or "News",
                    "text": f"{ev.title} {ev.snippet}",
                    "doc_id": 0,
                }
            )

        evidences: list[EvidencePayload] = []
        seen: set[str] = set()
        hits = 0
        for row in source_rows:
            low = str(row.get("text", "")).lower()
            url = str(row.get("url", ""))
            source = str(row.get("source", "website"))
            title = str(row.get("title", "Source"))
            doc_id = int(row.get("doc_id", 0) or 0)
            for role_category, patterns in ROLE_PATTERNS.items():
                if not any(re.search(rf"\b{re.escape(p)}\b", low) for p in patterns):
                    continue
                key = f"{role_category}|{source}|{url}"
                if key in seen:
                    continue
                seen.add(key)
                hits += 1
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title=f"Public role targetability signal: {role_category}",
                        snippet=f"Detected {role_category} role cue in {source} content: {title[:120]}",
                        source_url=url,
                        confidence=68,
                        raw={
                            "signal_type": "ROLE_TARGETABILITY_SIGNAL",
                            "role_category": role_category,
                            "source": source,
                            "document_id": doc_id if doc_id > 0 else None,
                        },
                    )
                )
                if len(evidences) >= 120:
                    break
            if len(evidences) >= 120:
                break

        target.log_examination(
            url="connector://public_role_extractor",
            source_type="manual",
            status="parsed",
            discovered_from="collector_v2 documents + job/news evidence",
            parse_summary=f"sources={len(source_rows)} role_hits={hits} evidences={len(evidences)}",
            fetched_at=datetime.utcnow(),
        )
        return evidences
