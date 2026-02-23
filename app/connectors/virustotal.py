from datetime import datetime

import requests

from app.config import get_settings
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.connectors.utils import canonical_domain_for_api


class VirusTotalConnector(ConnectorBase):
    name = "virustotal"
    requires_api_key = True
    description = "Optional domain metadata from VirusTotal"

    def ping(self, api_key: str | None = None) -> tuple[bool, str]:
        if not api_key:
            return False, "Missing API key"
        return True, "API key present"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        domain = canonical_domain_for_api(target.domain)
        if not domain:
            target.log_examination(
                url="virustotal://invalid-domain",
                source_type="news",
                status="failed",
                discovered_from="virustotal connector",
                error_message="invalid target domain",
                fetched_at=datetime.utcnow(),
            )
            return []
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        fetched_at = datetime.utcnow()
        if not api_key:
            target.log_examination(
                url=url,
                source_type="news",
                status="skipped",
                discovered_from="virustotal connector",
                parse_summary="missing api key",
                fetched_at=fetched_at,
            )
            return []

        settings = get_settings()
        headers = {"x-apikey": api_key, "User-Agent": settings.website_user_agent}

        try:
            res = requests.get(url, headers=headers, timeout=settings.request_timeout_seconds)
            res.raise_for_status()
            data = res.json()
            target.log_examination(
                url=url,
                source_type="news",
                status="parsed",
                discovered_from="virustotal api",
                http_status=res.status_code,
                bytes_size=len(res.content or b""),
                parse_summary="domain metadata fetched",
                fetched_at=fetched_at,
            )
        except Exception as exc:
            target.log_examination(
                url=url,
                source_type="news",
                status="failed",
                discovered_from="virustotal api",
                error_message=exc.__class__.__name__,
                fetched_at=fetched_at,
            )
            return []

        attrs = data.get("data", {}).get("attributes", {})
        harmless = attrs.get("last_analysis_stats", {}).get("harmless", 0)
        malicious = attrs.get("last_analysis_stats", {}).get("malicious", 0)

        return [
            EvidencePayload(
                connector=self.name,
                category="exposure",
                title="VirusTotal domain metadata",
                snippet=f"Harmless votes={harmless}; malicious votes={malicious}",
                source_url=f"https://www.virustotal.com/gui/domain/{domain}",
                confidence=70,
                raw={"stats": attrs.get("last_analysis_stats", {})},
            )
        ]
