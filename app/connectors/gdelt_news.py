from datetime import datetime
import hashlib

import requests

from app.config import get_settings
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload


class GDELTNewsConnector(ConnectorBase):
    name = "gdelt_news"
    description = "Fetches recent global news mentions from GDELT"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        settings = get_settings()
        query = target.company_name
        if target.regions:
            query = f"{query} {target.regions.split(',')[0].strip()}"

        params = {
            "query": query,
            "mode": "ArtList",
            "maxrecords": 20,
            "format": "json",
            "sort": "DateDesc",
        }

        api_url = "https://api.gdeltproject.org/api/v2/doc/doc"
        fetched_at = datetime.utcnow()
        try:
            res = requests.get(
                api_url,
                params=params,
                timeout=settings.request_timeout_seconds,
                headers={"User-Agent": settings.website_user_agent},
            )
            res.raise_for_status()
            payload = res.json()
            target.log_examination(
                url=res.url or api_url,
                source_type="news",
                status="fetched",
                discovered_from="gdelt api query",
                http_status=res.status_code,
                content_hash=hashlib.sha256(res.content).hexdigest()[:32] if res.content else "",
                bytes_size=len(res.content or b""),
                parse_summary=f"query={query}",
                fetched_at=fetched_at,
            )
        except Exception as exc:
            target.log_examination(
                url=api_url,
                source_type="news",
                status="failed",
                discovered_from="gdelt api query",
                error_message=exc.__class__.__name__,
                fetched_at=fetched_at,
            )
            if target.demo_mode:
                fallback_url = "https://example.local/news/demo-1"
                target.log_examination(
                    url=fallback_url,
                    source_type="news",
                    status="parsed",
                    discovered_from="gdelt fallback",
                    parse_summary="demo fallback article",
                    fetched_at=datetime.utcnow(),
                )
                return [
                    EvidencePayload(
                        connector=self.name,
                        category="mention",
                        title=f"Demo news pressure around {target.company_name}",
                        snippet="Local media discussed service disruption rumors impacting brand trust.",
                        source_url=fallback_url,
                        confidence=52,
                        raw={"demo": True},
                    )
                ]
            return []

        articles = payload.get("articles", []) if isinstance(payload, dict) else []
        evidences: list[EvidencePayload] = []

        for article in articles[:20]:
            title = article.get("title") or "Untitled article"
            url = article.get("url") or ""
            source = article.get("sourceCommonName") or article.get("domain") or "unknown source"
            seen = article.get("seendate") or ""
            snippet = f"{source} | seen {seen}"
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="mention",
                    title=title[:250],
                    snippet=snippet,
                    source_url=url,
                    confidence=65,
                    raw=article,
                )
            )
            target.log_examination(
                url=url or "gdelt://result",
                source_type="news",
                status="parsed",
                discovered_from="gdelt result",
                parse_summary=title[:200],
                fetched_at=datetime.utcnow(),
            )

        return evidences
