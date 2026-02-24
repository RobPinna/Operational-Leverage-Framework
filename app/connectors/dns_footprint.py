from __future__ import annotations

import hashlib
from datetime import datetime

import dns.resolver

from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.connectors.utils import canonical_domain_for_api


class DNSFootprintConnector(ConnectorBase):
    name = "dns_footprint"
    description = "Collects DNS exposure indicators"

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        root_domain = canonical_domain_for_api(target.domain)
        if not root_domain:
            target.log_examination(
                url="dns://invalid-domain",
                source_type="dns",
                status="failed",
                discovered_from="dns footprint collector",
                error_message="invalid target domain",
                fetched_at=datetime.utcnow(),
            )
            return []
        domains = [root_domain, f"www.{root_domain}"]
        record_types = ["MX", "NS", "CNAME", "A", "AAAA"]
        evidences: list[EvidencePayload] = []

        for domain in domains:
            for rtype in record_types:
                dns_url = f"dns://{domain}/{rtype}"
                fetched_at = datetime.utcnow()
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=4)
                    values = [str(r).strip() for r in answers][:10]
                    joined = ", ".join(values)
                    c_hash = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:32] if joined else ""

                    if not values:
                        target.log_examination(
                            url=dns_url,
                            source_type="dns",
                            status="parsed",
                            discovered_from="dns footprint collector",
                            parse_summary="no values returned",
                            fetched_at=fetched_at,
                        )
                        continue

                    evidences.append(
                        EvidencePayload(
                            connector=self.name,
                            category="exposure",
                            title=f"DNS {rtype} records for {domain}",
                            snippet=joined,
                            source_url=dns_url,
                            confidence=85,
                            raw={"domain": domain, "type": rtype, "values": values},
                        )
                    )
                    target.log_examination(
                        url=dns_url,
                        source_type="dns",
                        status="parsed",
                        discovered_from="dns footprint collector",
                        content_hash=c_hash,
                        bytes_size=len(joined.encode("utf-8")),
                        parse_summary=f"records={len(values)}",
                        fetched_at=fetched_at,
                    )
                except Exception as exc:
                    target.log_examination(
                        url=dns_url,
                        source_type="dns",
                        status="failed",
                        discovered_from="dns footprint collector",
                        error_message=exc.__class__.__name__,
                        fetched_at=fetched_at,
                    )
                    continue

        return evidences
