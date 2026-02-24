from datetime import datetime

import requests

from app.config import get_settings
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.connectors.utils import canonical_domain_for_api


class ShodanConnector(ConnectorBase):
    name = "shodan"
    requires_api_key = True
    description = "Optional Shodan DNS metadata"

    def ping(self, api_key: str | None = None) -> tuple[bool, str]:
        if not api_key:
            return False, "Missing API key"
        return True, "API key present"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        settings = get_settings()
        domain = canonical_domain_for_api(target.domain)
        if not domain:
            target.log_examination(
                url="shodan://invalid-domain",
                source_type="news",
                status="failed",
                discovered_from="shodan connector",
                error_message="invalid target domain",
                fetched_at=datetime.utcnow(),
            )
            return []
        params = {"key": api_key} if api_key else {}
        url = f"https://api.shodan.io/dns/domain/{domain}"
        fetched_at = datetime.utcnow()

        if not api_key:
            target.log_examination(
                url=url,
                source_type="news",
                status="skipped",
                discovered_from="shodan connector",
                parse_summary="missing api key",
                fetched_at=fetched_at,
            )
            return []

        try:
            res = requests.get(url, params=params, timeout=settings.request_timeout_seconds)
            res.raise_for_status()
            data = res.json()
            target.log_examination(
                url=res.url or url,
                source_type="news",
                status="parsed",
                discovered_from="shodan api",
                http_status=res.status_code,
                bytes_size=len(res.content or b""),
                parse_summary="dns metadata fetched",
                fetched_at=fetched_at,
            )
        except Exception as exc:
            target.log_examination(
                url=url,
                source_type="news",
                status="failed",
                discovered_from="shodan api",
                error_message=exc.__class__.__name__,
                fetched_at=fetched_at,
            )
            return []

        subdomains = data.get("subdomains", []) if isinstance(data, dict) else []
        return [
            EvidencePayload(
                connector=self.name,
                category="exposure",
                title="Shodan DNS metadata",
                snippet=f"Observed subdomains: {len(subdomains)}",
                source_url=url,
                confidence=67,
                raw={"subdomains": subdomains[:50]},
            )
        ]
