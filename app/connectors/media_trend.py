from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from urllib.parse import urlparse

from sqlalchemy import select

from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.db import SessionLocal
from app.models import Evidence

NEGATIVE_MARKERS = (
    "fraud",
    "scam",
    "imperson",
    "fake",
    "abuse",
    "breach",
    "alert",
    "warning",
)


class MediaTrendConnector(ConnectorBase):
    name = "media_trend"
    description = "Builds media mention trend signals from collected news/social evidence"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        if not target.assessment_id:
            target.log_examination(
                url="connector://media_trend",
                source_type="manual",
                status="skipped",
                discovered_from="connector-run",
                parse_summary="missing assessment_id for evidence lookup",
                fetched_at=datetime.utcnow(),
            )
            return []

        with SessionLocal() as db:
            rows = (
                db.execute(
                    select(Evidence).where(
                        Evidence.assessment_id == target.assessment_id,
                        Evidence.connector.in_(["gdelt_news", "social_mock"]),
                    )
                )
                .scalars()
                .all()
            )

        if not rows:
            target.log_examination(
                url="connector://media_trend",
                source_type="news",
                status="skipped",
                discovered_from="existing evidence",
                parse_summary="no gdelt/social evidence available",
                fetched_at=datetime.utcnow(),
            )
            return []

        now = datetime.utcnow()
        recent_cut = now - timedelta(days=7)
        prev_cut = now - timedelta(days=14)
        recent = [x for x in rows if (x.observed_at or now) >= recent_cut]
        previous = [x for x in rows if prev_cut <= (x.observed_at or now) < recent_cut]
        recent_count = len(recent)
        previous_count = len(previous)

        if recent_count >= previous_count + 3:
            trend = "rising"
            conf = 76
        elif recent_count + 2 < previous_count:
            trend = "cooling"
            conf = 65
        else:
            trend = "stable"
            conf = 68

        negative_recent = [
            x for x in recent if any(marker in f"{x.title} {x.snippet}".lower() for marker in NEGATIVE_MARKERS)
        ]
        source_hosts = Counter(urlparse(x.source_url or "").netloc.lower() for x in rows if x.source_url)
        top_hosts = [h for h, _ in source_hosts.most_common(3) if h]

        evidences: list[EvidencePayload] = [
            EvidencePayload(
                connector=self.name,
                category="mention",
                title=f"Media trend is {trend}",
                snippet=(
                    f"Recent 7-day mentions={recent_count}, previous 7-day mentions={previous_count}. "
                    f"Negative-signal mentions in recent window={len(negative_recent)}."
                ),
                source_url=recent[0].source_url if recent else (rows[0].source_url or ""),
                confidence=conf,
                raw={
                    "trend": trend,
                    "recent_count": recent_count,
                    "previous_count": previous_count,
                    "negative_recent": len(negative_recent),
                },
            )
        ]

        if top_hosts:
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="mention",
                    title="Top media source concentration",
                    snippet=", ".join(top_hosts),
                    source_url=f"https://{top_hosts[0]}",
                    confidence=64,
                    raw={"top_hosts": top_hosts},
                )
            )

        if negative_recent and trend == "rising":
            ev = negative_recent[0]
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="pivot",
                    title="Rising adverse narratives can strengthen impersonation pretexts",
                    snippet="Recent media pressure may make fraudulent urgent outreach appear more plausible.",
                    source_url=ev.source_url,
                    confidence=72,
                    raw={"evidence_id": ev.id},
                )
            )

        target.log_examination(
            url="connector://media_trend",
            source_type="news",
            status="parsed",
            discovered_from="existing evidence",
            parse_summary=f"rows={len(rows)} trend={trend}",
            fetched_at=datetime.utcnow(),
        )
        return evidences
