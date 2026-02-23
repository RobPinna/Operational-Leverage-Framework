from __future__ import annotations

import re
from datetime import datetime

import dns.resolver
from sqlalchemy import select

from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.connectors.utils import canonical_domain_for_api
from app.db import SessionLocal
from app.models import Evidence
from app.utils.jsonx import from_json


DMARC_POLICY_RE = re.compile(r"\bp\s*=\s*([a-z]+)\b", re.IGNORECASE)


def _root_provider(host: str) -> str:
    value = (host or "").strip().strip(".").lower()
    if not value:
        return ""
    parts = [p for p in value.split(".") if p]
    if len(parts) <= 2:
        return value
    return ".".join(parts[-2:])


class EmailPostureAnalyzerConnector(ConnectorBase):
    name = "email_posture_analyzer"
    description = "Analyzes public email posture (SPF/DMARC/MX) and emits structured, defensive-only signals."

    def _load_dns_evidence(self, assessment_id: int | None) -> tuple[list[str], list[str]]:
        if not assessment_id:
            return [], []
        with SessionLocal() as db:
            rows = db.execute(
                select(Evidence).where(
                    Evidence.assessment_id == assessment_id,
                    Evidence.connector == "dns_footprint",
                )
            ).scalars().all()
        mx_values: list[str] = []
        txt_values: list[str] = []
        for ev in rows:
            raw = from_json(ev.raw_json or "{}", {})
            if not isinstance(raw, dict):
                continue
            rtype = str(raw.get("type", "")).strip().upper()
            vals = raw.get("values") if isinstance(raw.get("values"), list) else []
            text_vals = [str(v).strip().strip('"') for v in vals if str(v).strip()]
            if rtype == "MX":
                mx_values.extend(text_vals)
            elif rtype == "TXT":
                txt_values.extend(text_vals)
        return mx_values, txt_values

    def _resolve_mx(self, domain: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(domain, "MX", lifetime=5)
            return [str(r.exchange).strip().rstrip(".") for r in answers][:20]
        except Exception:
            return []

    def _resolve_txt(self, domain: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
            out: list[str] = []
            for r in answers:
                try:
                    if getattr(r, "strings", None):
                        value = "".join([x.decode("utf-8", errors="ignore") for x in r.strings])
                    else:
                        value = str(r)
                    value = value.strip().strip('"')
                    if value:
                        out.append(value)
                except Exception:
                    continue
            return out[:50]
        except Exception:
            return []

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        domain = canonical_domain_for_api(target.domain)
        if (not domain) or (" " in domain) or ("." not in domain):
            target.log_examination(
                url="dns://invalid-domain",
                source_type="dns",
                status="failed",
                discovered_from="email posture analyzer",
                error_message="invalid target domain",
                fetched_at=datetime.utcnow(),
            )
            return []

        mx_values, txt_values = self._load_dns_evidence(target.assessment_id)
        used_existing_dns = bool(mx_values or txt_values)

        if not mx_values:
            mx_values = self._resolve_mx(domain)
            target.log_examination(
                url=f"dns://{domain}/MX",
                source_type="dns",
                status="parsed" if mx_values else "failed",
                discovered_from="email posture analyzer (live lookup)",
                parse_summary=f"mx_records={len(mx_values)}",
                fetched_at=datetime.utcnow(),
            )
        else:
            target.log_examination(
                url=f"connector://{self.name}",
                source_type="dns",
                status="parsed",
                discovered_from="dns_footprint evidence",
                parse_summary=f"reused dns_footprint mx_records={len(mx_values)}",
                fetched_at=datetime.utcnow(),
            )

        # DMARC lives on _dmarc.<domain>; use explicit lookup even when dns_footprint exists,
        # because the dns connector may not have queried TXT.
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_txt = self._resolve_txt(dmarc_domain)
        target.log_examination(
            url=f"dns://{dmarc_domain}/TXT",
            source_type="dns",
            status="parsed" if dmarc_txt else "failed",
            discovered_from="email posture analyzer (dmarc lookup)",
            parse_summary=f"dmarc_txt_records={len(dmarc_txt)}",
            fetched_at=datetime.utcnow(),
        )

        if not txt_values:
            txt_values = self._resolve_txt(domain)
            target.log_examination(
                url=f"dns://{domain}/TXT",
                source_type="dns",
                status="parsed" if txt_values else "failed",
                discovered_from="email posture analyzer (spf/txt lookup)",
                parse_summary=f"txt_records={len(txt_values)}",
                fetched_at=datetime.utcnow(),
            )

        spf_records = [v for v in txt_values if "v=spf1" in v.lower()]
        dmarc_records = [v for v in dmarc_txt if "v=dmarc1" in v.lower()]

        evidences: list[EvidencePayload] = []
        if not dmarc_records:
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="exposure",
                    title="Email posture: no DMARC policy detected",
                    snippet="No DMARC policy detected for target domain.",
                    source_url=f"dns://{dmarc_domain}/TXT",
                    confidence=68,
                    raw={
                        "signal_type": "EMAIL_SPOOFING_RISK",
                        "domain": domain,
                        "dmarc_records": [],
                        "spf_records": spf_records[:5],
                        "used_existing_dns": used_existing_dns,
                    },
                )
            )
        else:
            # Use first DMARC record for conservative classification.
            rec = dmarc_records[0]
            pol_match = DMARC_POLICY_RE.search(rec)
            policy = pol_match.group(1).lower() if pol_match else ""
            if policy == "none":
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title="Email posture: DMARC policy is monitoring only (p=none)",
                        snippet=f"DMARC policy detected with p=none: {rec[:180]}",
                        source_url=f"dns://{dmarc_domain}/TXT",
                        confidence=66,
                        raw={
                            "signal_type": "DMARC_POLICY_WEAK",
                            "domain": domain,
                            "dmarc_policy": policy,
                            "dmarc_record": rec,
                            "spf_records": spf_records[:5],
                            "used_existing_dns": used_existing_dns,
                        },
                    )
                )
            elif policy in {"quarantine", "reject"}:
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title=f"Email posture: DMARC enforcement policy present (p={policy})",
                        snippet=f"DMARC enforcement policy detected: {rec[:180]}",
                        source_url=f"dns://{dmarc_domain}/TXT",
                        confidence=72,
                        raw={
                            "signal_type": "DMARC_POLICY_STRONG",
                            "domain": domain,
                            "dmarc_policy": policy,
                            "dmarc_record": rec,
                            "spf_records": spf_records[:5],
                            "used_existing_dns": used_existing_dns,
                        },
                    )
                )

        providers = sorted({_root_provider(v) for v in mx_values if _root_provider(v)})
        if len(providers) > 1:
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="exposure",
                    title="Email posture: multiple MX providers detected",
                    snippet=f"Multiple MX providers detected: {', '.join(providers[:5])}",
                    source_url=f"dns://{domain}/MX",
                    confidence=58,
                    raw={
                        "signal_type": "MULTIPLE_MX_PROVIDER",
                        "domain": domain,
                        "mx_hosts": mx_values[:20],
                        "providers": providers[:20],
                        "used_existing_dns": used_existing_dns,
                    },
                )
            )

        target.log_examination(
            url=f"connector://{self.name}",
            source_type="dns",
            status="parsed",
            discovered_from="connector-run",
            parse_summary=(
                f"domain={domain} dmarc={len(dmarc_records)} spf={len(spf_records)} "
                f"mx={len(mx_values)} evidences={len(evidences)}"
            ),
            fetched_at=datetime.utcnow(),
        )
        return evidences
