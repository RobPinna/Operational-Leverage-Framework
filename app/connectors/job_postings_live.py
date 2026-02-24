import json
import re
from datetime import datetime
from urllib.parse import urljoin
from xml.etree import ElementTree as ET

import requests
from sqlalchemy import select

from app.config import get_settings
from app.connectors.base import ConnectorBase, ConnectorTarget, EvidencePayload
from app.connectors.utils import canonical_domain_for_api
from app.db import SessionLocal
from app.models import Document

LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
GREENHOUSE_RE = re.compile(r"(?:boards|job-boards)\.greenhouse\.io/([a-zA-Z0-9_-]+)", re.IGNORECASE)
LEVER_RE = re.compile(r"jobs\.lever\.co/([a-zA-Z0-9_-]+)", re.IGNORECASE)
INDEED_RE = re.compile(r"indeed\.[a-z.]+/.+(job|viewjob|cmp)", re.IGNORECASE)


class JobPostingsLiveConnector(ConnectorBase):
    name = "job_postings_live"
    description = "Discovers public job postings from career pages, Indeed links, Greenhouse/Lever APIs, and RSS"

    def _fetch(self, url: str, timeout: int, headers: dict[str, str]) -> tuple[str, str, int | None, str]:
        try:
            res = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
            return res.url, (res.text[:250000] if res.text else ""), res.status_code, ""
        except Exception as exc:
            return "", "", None, exc.__class__.__name__

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        links = []
        for href in LINK_RE.findall(html):
            full = urljoin(base_url, href)
            if full.startswith("http://") or full.startswith("https://"):
                links.append(full)
        return list(dict.fromkeys(links))

    def _extract_jsonld_jobs(self, html: str) -> list[dict]:
        jobs: list[dict] = []
        for match in re.findall(
            r"<script[^>]+type=[\"']application/ld\+json[\"'][^>]*>(.*?)</script>",
            html,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            try:
                payload = json.loads(match.strip())
            except Exception:
                continue

            data = payload if isinstance(payload, list) else [payload]
            for item in data:
                if not isinstance(item, dict):
                    continue
                graph_items = item.get("@graph")
                if isinstance(graph_items, list):
                    for g in graph_items:
                        if isinstance(g, dict) and str(g.get("@type", "")).lower() == "jobposting":
                            jobs.append(g)

                if str(item.get("@type", "")).lower() == "jobposting":
                    jobs.append(item)
        return jobs

    def _fallback_from_documents(self, target: ConnectorTarget) -> list[EvidencePayload]:
        if not target.assessment_id:
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
        rows: list[EvidencePayload] = []
        seen: set[str] = set()
        for doc in docs:
            value = f"{doc.url} {doc.title} {(doc.extracted_text or '')[:3000]}".lower()
            if not any(token in value for token in ["/careers", "/jobs", "job posting", "job", "careers"]):
                continue
            key = (doc.url or "").strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            rows.append(
                EvidencePayload(
                    connector=self.name,
                    category="exposure",
                    title=f"Career signal from collected page: {doc.title or 'career page'}",
                    snippet="Collector-discovered document indicates externally visible hiring workflows.",
                    source_url=doc.url,
                    confidence=66,
                    raw={"source": "collector_document", "doc_id": doc.id},
                )
            )
            if len(rows) >= 10:
                break
        if rows:
            target.log_examination(
                url=f"connector://{self.name}/document-fallback",
                source_type="html",
                status="parsed",
                discovered_from="job posting connector fallback",
                parse_summary=f"document fallback evidences={len(rows)}",
                fetched_at=datetime.utcnow(),
            )
        return rows

    def run(self, target: ConnectorTarget, api_key: str | None = None) -> list[EvidencePayload]:
        settings = get_settings()
        timeout = settings.request_timeout_seconds
        headers = {"User-Agent": settings.website_user_agent}

        host = canonical_domain_for_api(target.domain)
        if not host:
            target.log_examination(
                url="job_postings://invalid-domain",
                source_type="html",
                status="failed",
                discovered_from="job posting connector",
                error_message="invalid target domain",
                fetched_at=datetime.utcnow(),
            )
            return self._fallback_from_documents(target)

        base = f"https://{host}"
        seed_paths = ["/careers", "/jobs", "/join-us", "/work-with-us", "/about/careers", "/"]
        candidate_pages = [urljoin(base, p) for p in seed_paths]

        visited: set[str] = set()
        jsonld_jobs: list[dict] = []
        greenhouse_tokens: set[str] = set()
        lever_companies: set[str] = set()
        indeed_links: set[str] = set()
        rss_links: set[str] = set()

        for url in candidate_pages:
            if url in visited:
                continue
            visited.add(url)
            fetched_at = datetime.utcnow()
            final_url, html, http_status, err = self._fetch(url, timeout, headers)
            if err:
                target.log_examination(
                    url=url,
                    source_type="html",
                    status="failed",
                    discovered_from="seed/careers paths",
                    error_message=err,
                    fetched_at=fetched_at,
                )
                continue

            target.log_examination(
                url=final_url or url,
                source_type="html",
                status="fetched" if (http_status and http_status < 400) else "failed",
                discovered_from="seed/careers paths",
                http_status=http_status,
                bytes_size=len((html or "").encode("utf-8")),
                parse_summary="career page fetched",
                error_message="" if (http_status and http_status < 400) else f"http_status={http_status}",
                fetched_at=fetched_at,
            )
            if not html:
                continue

            scan_url = final_url or url
            for gh_match in GREENHOUSE_RE.finditer(html):
                greenhouse_tokens.add(gh_match.group(1))
            for lv_match in LEVER_RE.finditer(html):
                lever_companies.add(lv_match.group(1))

            links = self._extract_links(html, scan_url)
            target.log_examination(
                url=scan_url,
                source_type="html",
                status="parsed",
                discovered_from="career page parse",
                parse_summary=f"outbound_links={len(links)}",
                fetched_at=datetime.utcnow(),
            )

            for link in links:
                if INDEED_RE.search(link):
                    indeed_links.add(link)
                if link.lower().endswith(".xml") or "rss" in link.lower():
                    rss_links.add(link)
                gh_match = GREENHOUSE_RE.search(link)
                if gh_match:
                    greenhouse_tokens.add(gh_match.group(1))
                lv_match = LEVER_RE.search(link)
                if lv_match:
                    lever_companies.add(lv_match.group(1))

            jsonld_jobs.extend(self._extract_jsonld_jobs(html))

        evidences: list[EvidencePayload] = []
        seen_titles: set[str] = set()

        for job in jsonld_jobs[:25]:
            title = str(job.get("title") or "Job posting")[:230]
            if title.lower() in seen_titles:
                continue
            seen_titles.add(title.lower())
            org = job.get("hiringOrganization", {}) if isinstance(job.get("hiringOrganization"), dict) else {}
            org_name = org.get("name") or target.company_name
            loc = job.get("jobLocation", {})
            loc_name = ""
            if isinstance(loc, dict):
                addr = loc.get("address", {})
                if isinstance(addr, dict):
                    loc_name = addr.get("addressLocality") or addr.get("addressRegion") or ""

            source_url = str(job.get("url") or base)
            snippet = f"Source=JSON-LD JobPosting; org={org_name}; location={loc_name or 'n/a'}"
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="exposure",
                    title=f"Public job posting discovered: {title}",
                    snippet=snippet,
                    source_url=source_url,
                    confidence=78,
                    raw={"job": job, "source": "jsonld"},
                )
            )
            target.log_examination(
                url=source_url,
                source_type="html",
                status="parsed",
                discovered_from="json-ld jobposting",
                parse_summary=title,
                fetched_at=datetime.utcnow(),
            )

        for token in list(greenhouse_tokens)[:6]:
            api_url = f"https://boards-api.greenhouse.io/v1/boards/{token}/jobs"
            fetched_at = datetime.utcnow()
            try:
                res = requests.get(api_url, timeout=timeout, headers=headers)
                res.raise_for_status()
                jobs = res.json().get("jobs", []) if isinstance(res.json(), dict) else []
                target.log_examination(
                    url=api_url,
                    source_type="news",
                    status="parsed",
                    discovered_from="greenhouse board api",
                    http_status=res.status_code,
                    bytes_size=len(res.content or b""),
                    parse_summary=f"jobs={len(jobs)}",
                    fetched_at=fetched_at,
                )
            except Exception as exc:
                target.log_examination(
                    url=api_url,
                    source_type="news",
                    status="failed",
                    discovered_from="greenhouse board api",
                    error_message=exc.__class__.__name__,
                    fetched_at=fetched_at,
                )
                continue

            for job in jobs[:20]:
                title = str(job.get("title") or "Greenhouse role")[:230]
                key = f"gh:{title.lower()}"
                if key in seen_titles:
                    continue
                seen_titles.add(key)
                loc = job.get("location", {}).get("name", "n/a") if isinstance(job.get("location"), dict) else "n/a"
                source_url = str(job.get("absolute_url") or f"https://boards.greenhouse.io/{token}")
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title=f"Greenhouse posting: {title}",
                        snippet=f"Board={token}; location={loc}",
                        source_url=source_url,
                        confidence=82,
                        raw={"job": job, "source": "greenhouse", "board": token},
                    )
                )

        for company in list(lever_companies)[:6]:
            api_url = f"https://api.lever.co/v0/postings/{company}?mode=json"
            fetched_at = datetime.utcnow()
            try:
                res = requests.get(
                    f"https://api.lever.co/v0/postings/{company}",
                    params={"mode": "json"},
                    timeout=timeout,
                    headers=headers,
                )
                res.raise_for_status()
                jobs = res.json() if isinstance(res.json(), list) else []
                target.log_examination(
                    url=res.url or api_url,
                    source_type="news",
                    status="parsed",
                    discovered_from="lever board api",
                    http_status=res.status_code,
                    bytes_size=len(res.content or b""),
                    parse_summary=f"jobs={len(jobs)}",
                    fetched_at=fetched_at,
                )
            except Exception as exc:
                target.log_examination(
                    url=api_url,
                    source_type="news",
                    status="failed",
                    discovered_from="lever board api",
                    error_message=exc.__class__.__name__,
                    fetched_at=fetched_at,
                )
                continue

            for job in jobs[:20]:
                title = str(job.get("text") or "Lever role")[:230]
                key = f"lv:{title.lower()}"
                if key in seen_titles:
                    continue
                seen_titles.add(key)
                cats = job.get("categories", {}) if isinstance(job.get("categories"), dict) else {}
                loc = cats.get("location") or "n/a"
                source_url = str(job.get("hostedUrl") or f"https://jobs.lever.co/{company}")
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title=f"Lever posting: {title}",
                        snippet=f"Company board={company}; location={loc}",
                        source_url=source_url,
                        confidence=82,
                        raw={"job": job, "source": "lever", "company": company},
                    )
                )

        for link in list(indeed_links)[:20]:
            target.log_examination(
                url=link,
                source_type="html",
                status="parsed",
                discovered_from="career page outbound link",
                parse_summary="indeed link discovered",
                fetched_at=datetime.utcnow(),
            )
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="exposure",
                    title="Indeed posting link discovered",
                    snippet="External Indeed job posting linked from public career surface.",
                    source_url=link,
                    confidence=74,
                    raw={"source": "indeed_link"},
                )
            )

        for rss_url in list(rss_links)[:6]:
            fetched_at = datetime.utcnow()
            try:
                res = requests.get(rss_url, timeout=timeout, headers=headers, allow_redirects=True)
                res.raise_for_status()
                root = ET.fromstring(res.content[:500000])
                target.log_examination(
                    url=res.url or rss_url,
                    source_type="rss",
                    status="parsed",
                    discovered_from="career page rss link",
                    http_status=res.status_code,
                    bytes_size=len(res.content or b""),
                    parse_summary="rss feed fetched",
                    fetched_at=fetched_at,
                )
            except Exception as exc:
                target.log_examination(
                    url=rss_url,
                    source_type="rss",
                    status="failed",
                    discovered_from="career page rss link",
                    error_message=exc.__class__.__name__,
                    fetched_at=fetched_at,
                )
                continue

            items = root.findall(".//item")[:20]
            for item in items:
                title = (item.findtext("title") or "RSS job item").strip()[:230]
                link = (item.findtext("link") or rss_url).strip()
                pub = (item.findtext("pubDate") or "").strip()
                evidences.append(
                    EvidencePayload(
                        connector=self.name,
                        category="exposure",
                        title=f"RSS job feed item: {title}",
                        snippet=f"Source feed={rss_url}; published={pub or 'n/a'}",
                        source_url=link,
                        confidence=76,
                        raw={"source": "rss", "feed": rss_url},
                    )
                )
                target.log_examination(
                    url=link,
                    source_type="rss",
                    status="parsed",
                    discovered_from="rss job item",
                    parse_summary=title,
                    fetched_at=datetime.utcnow(),
                )

        touchpoint_words = {
            "billing": "Billing process appears in public hiring language",
            "invoice": "Invoice operations mentioned in job descriptions",
            "support": "Support workflows are referenced in role descriptions",
            "onboarding": "Onboarding flows are publicly detailed in postings",
            "vendor": "Vendor interaction process appears in hiring content",
            "donation": "Donation operations are referenced in role content",
            "procurement": "Procurement external contact channels are visible in hiring data",
        }

        for ev in list(evidences)[:30]:
            raw_text = f"{ev.title} {ev.snippet}".lower()
            for keyword, message in touchpoint_words.items():
                if keyword in raw_text:
                    evidences.append(
                        EvidencePayload(
                            connector=self.name,
                            category="touchpoint",
                            title=f"Job posting external contact channel indicator: {keyword}",
                            snippet=message,
                            source_url=ev.source_url,
                            confidence=72,
                            raw={"keyword": keyword, "parent": ev.title},
                        )
                    )
                    break

        if not evidences:
            evidences.extend(self._fallback_from_documents(target))

        if not evidences and target.demo_mode:
            fallback_url = "https://jobs.example/demo"
            target.log_examination(
                url=fallback_url,
                source_type="manual",
                status="parsed",
                discovered_from="job connector demo fallback",
                parse_summary="no live job board matched",
                fetched_at=datetime.utcnow(),
            )
            evidences.append(
                EvidencePayload(
                    connector=self.name,
                    category="mention",
                    title=f"Demo fallback: job visibility signal for {target.company_name}",
                    snippet="No live job board matched; fallback indicates externally visible hiring contact-channel details.",
                    source_url=fallback_url,
                    confidence=52,
                    raw={"demo": True, "fallback": "job_postings_live"},
                )
            )
        elif not evidences:
            target.log_examination(
                url=f"connector://{self.name}",
                source_type="html",
                status="skipped",
                discovered_from="job posting connector",
                parse_summary="no live or fallback job posting evidence found",
                fetched_at=datetime.utcnow(),
            )

        return evidences[:60]
