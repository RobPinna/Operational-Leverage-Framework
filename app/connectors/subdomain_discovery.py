from __future__ import annotations

from datetime import datetime
import hashlib

import dns.resolver
import requests

from app.config import get_settings
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.connectors.utils import canonical_domain_for_api

COMMON_SUBDOMAINS = (
    "www",
    "support",
    "help",
    "billing",
    "portal",
    "status",
    "docs",
    "partners",
    "api",
    "jobs",
    "careers",
    "cdn",
    "mail",
    "m",
)


class SubdomainDiscoveryConnector(ConnectorBase):
    name = "subdomain_discovery"
    description = "Discovers subdomains via certificate transparency and DNS probing"

    def _resolve_name(self, host: str, rtype: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=4)
            return [str(a).strip() for a in answers][:8]
        except Exception:
            return []

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        settings = get_settings()
        domain = canonical_domain_for_api(target.domain)
        if not domain:
            target.log_examination(
                url="subdomain://invalid-domain",
                source_type="dns",
                status="failed",
                discovered_from="subdomain discovery",
                error_message="invalid target domain",
                fetched_at=datetime.utcnow(),
            )
            return []

        discovered: set[str] = set()

        # Certificate transparency discovery.
        crt_url = "https://crt.sh/"
        crt_params = {"q": f"%.{domain}", "output": "json"}
        fetched_at = datetime.utcnow()
        try:
            res = requests.get(
                crt_url,
                params=crt_params,
                timeout=max(8, settings.request_timeout_seconds),
                headers={"User-Agent": settings.website_user_agent},
            )
            if res.status_code < 400 and res.text.strip():
                payload = res.json()
                for row in payload[:1200]:
                    name_value = str((row or {}).get("name_value", "")).strip().lower()
                    for candidate in name_value.splitlines():
                        host = candidate.replace("*.", "").strip(".")
                        if host.endswith(domain):
                            discovered.add(host)
                target.log_examination(
                    url=res.url or crt_url,
                    source_type="dns",
                    status="parsed",
                    discovered_from="crt.sh",
                    http_status=res.status_code,
                    bytes_size=len(res.content or b""),
                    parse_summary=f"ct_subdomains={len(discovered)}",
                    fetched_at=fetched_at,
                )
            else:
                target.log_examination(
                    url=res.url or crt_url,
                    source_type="dns",
                    status="failed",
                    discovered_from="crt.sh",
                    http_status=res.status_code,
                    error_message=f"http_status={res.status_code}",
                    fetched_at=fetched_at,
                )
        except Exception as exc:
            target.log_examination(
                url=crt_url,
                source_type="dns",
                status="failed",
                discovered_from="crt.sh",
                error_message=exc.__class__.__name__,
                fetched_at=fetched_at,
            )

        # Common subdomain probing.
        for name in COMMON_SUBDOMAINS:
            host = f"{name}.{domain}"
            dns_url = f"dns://{host}/A"
            fetched_at = datetime.utcnow()
            values = self._resolve_name(host, "A") or self._resolve_name(host, "CNAME")
            if values:
                discovered.add(host)
                joined = ", ".join(values)
                target.log_examination(
                    url=dns_url,
                    source_type="dns",
                    status="parsed",
                    discovered_from="common subdomain probe",
                    content_hash=hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32],
                    bytes_size=len(joined.encode("utf-8")),
                    parse_summary=f"records={len(values)}",
                    fetched_at=fetched_at,
                )
            else:
                target.log_examination(
                    url=dns_url,
                    source_type="dns",
                    status="failed",
                    discovered_from="common subdomain probe",
                    error_message="no_dns_answer",
                    fetched_at=fetched_at,
                )

        if not discovered:
            return []

        rows = sorted(discovered)
        evidences: list[EvidencePayload] = [
            EvidencePayload(
                connector=self.name,
                category="exposure",
                title=f"Subdomain discovery identified {len(rows)} hosts",
                snippet=", ".join(rows[:12]),
                source_url=f"dns://{domain}/subdomains",
                confidence=74,
                raw={"subdomains": rows[:200]},
            )
        ]

        for host in rows[:18]:
            channel_conf = 80 if any(k in host for k in ["support", "billing", "help", "portal"]) else 68
            cat = "touchpoint" if channel_conf >= 80 else "exposure"
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category=cat,
                    title=f"Subdomain exposed: {host}",
                    snippet="Public DNS host may be referenced in external support or operational communications.",
                    source_url=f"https://{host}",
                    confidence=channel_conf,
                    raw={"host": host},
                )
            )

        return evidences[:40]

