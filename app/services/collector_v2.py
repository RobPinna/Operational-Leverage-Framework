from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import html
import io
import json
import logging
from pathlib import PurePosixPath
import re
import time
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser
import xml.etree.ElementTree as ET

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import SessionLocal
from app.models import Assessment, Document, ExaminationLog, SocialTrustNode

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover - runtime dependency guard
    PdfReader = None

try:
    from playwright.sync_api import sync_playwright
except Exception:  # pragma: no cover - optional runtime dependency
    sync_playwright = None


logger = logging.getLogger(__name__)

SEED_PATHS = (
    "/careers",
    "/jobs",
    "/support",
    "/help",
    "/docs",
    "/press",
    "/news",
    "/partners",
    "/downloads",
    "/policies",
    "/privacy",
    "/terms",
    "/contact",
    "/about",
    "/procurement",
    "/tenders",
    "/rfp",
    "/suppliers",
)
KEYWORD_WEIGHTS = {
    "careers": 3,
    "jobs": 3,
    "support": 3,
    "help": 3,
    "docs": 2,
    "pdf": 3,
    "policy": 2,
    "vendor": 3,
    "partner": 3,
    "news": 2,
    "press": 2,
    "download": 2,
    "privacy": 2,
    "terms": 2,
    "contact": 2,
    "about": 1,
    "procurement": 3,
    "supplier": 3,
    "rfp": 3,
    "tender": 3,
}
MAX_FETCH_BYTES = 15 * 1024 * 1024
MAX_DISCOVERY_SITEMAP_URLS = 500
MAX_SELECTED_HTML_URLS = 50
MAX_PDF_BYTES = 15 * 1024 * 1024
MAX_PDF_PER_RUN = 10
MAX_JS_RENDER_PAGES = 10
MAX_SOCIAL_FETCH_BYTES = 4 * 1024 * 1024
MAX_SOCIAL_PER_RUN = 8
HTTP_TIMEOUT_SECONDS = 10
REQ_PER_SECOND = 1.0

A_TAG_RE = re.compile(r"""<a\b[^>]*href=["']([^"']+)["'][^>]*>(.*?)</a>""", re.IGNORECASE | re.DOTALL)
SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*src=["']([^"']+)["'][^>]*>""", re.IGNORECASE | re.DOTALL)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
META_RE = re.compile(
    r"""<meta[^>]+(?:name|property)=["']([^"']+)["'][^>]+content=["']([^"']+)["'][^>]*>""",
    re.IGNORECASE,
)
SCRIPT_STYLE_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?:\+?\d[\d\-\s().]{7,}\d)")
H_RE = re.compile(r"<h[1-3][^>]*>(.*?)</h[1-3]>", re.IGNORECASE | re.DOTALL)
TOKEN_RE = re.compile(r"[a-z0-9._-]+", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

SOCIAL_PLATFORM_HOSTS: dict[str, str] = {
    "instagram.com": "instagram",
    "facebook.com": "facebook",
    "linkedin.com": "linkedin",
    "x.com": "x",
    "twitter.com": "twitter",
    "youtube.com": "youtube",
    "tiktok.com": "tiktok",
}

SOCIAL_BOOKING_HINTS = (
    "booking",
    "reservation",
    "reserve",
    "book now",
    "payment",
    "pay",
    "invoice",
    "billing",
    "concierge",
    "loyalty",
    "prenot",
    "pagamento",
    "fattura",
)

SOCIAL_DM_HINTS = (
    "dm",
    "direct message",
    "direct-message",
    "message us",
    "send us a message",
    "via dm",
    "inbox",
    "private message",
    "messagg",
)


@dataclass(slots=True)
class FetchResult:
    final_url: str
    status_code: int | None
    content_type: str
    content: bytes
    error: str = ""


@dataclass(slots=True)
class DiscoveryCandidate:
    url: str
    score: int
    discovered_from: str
    anchor_text: str


@dataclass(slots=True)
class ParsedLink:
    url: str
    anchor: str


@dataclass(slots=True)
class SocialCandidate:
    url: str
    discovered_from_url: str
    anchor_text: str


class _RateLimiter:
    def __init__(self, min_interval_seconds: float) -> None:
        self.min_interval_seconds = max(0.0, min_interval_seconds)
        self._last_request_at = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request_at
        if elapsed < self.min_interval_seconds:
            time.sleep(self.min_interval_seconds - elapsed)
        self._last_request_at = time.monotonic()


class _CollectorV2:
    def __init__(self, db: Session, assessment: Assessment) -> None:
        self.db = db
        self.assessment = assessment
        self.settings = get_settings()
        self.headers = {"User-Agent": self.settings.website_user_agent}
        self.timeout = HTTP_TIMEOUT_SECONDS
        self.limiter = _RateLimiter(1.0 / REQ_PER_SECOND)
        self.target_host = self._normalize_target_host(assessment.domain or "")
        self.robots_cache: dict[str, RobotFileParser | None] = {}
        self.seen_hashes = self._load_seen_hashes()
        self.created_or_updated: list[Document] = []
        self.render_budget = MAX_JS_RENDER_PAGES
        self._logged_external: set[str] = set()
        self.social_budget = MAX_SOCIAL_PER_RUN
        self.social_candidates: dict[str, SocialCandidate] = {}

    def _normalize_target_host(self, raw_domain: str) -> str:
        value = (raw_domain or "").strip()
        if not value:
            return ""
        probe = value if "://" in value else f"https://{value}"
        parsed = urlparse(probe)
        host = (parsed.netloc or parsed.path or "").strip().lower()
        host = host.split("/")[0].split(":")[0].strip(".")
        return host

    def _load_seen_hashes(self) -> set[str]:
        hashes = set()
        doc_rows = self.db.execute(
            select(Document.content_hash).where(
                Document.assessment_id == self.assessment.id,
                Document.content_hash != "",
            )
        ).all()
        log_rows = self.db.execute(
            select(ExaminationLog.content_hash).where(
                ExaminationLog.assessment_id == self.assessment.id,
                ExaminationLog.content_hash != "",
            )
        ).all()
        for row in [*doc_rows, *log_rows]:
            value = row[0] if row else ""
            if value:
                hashes.add(value)
        return hashes

    def _log(
        self,
        *,
        url: str,
        source_type: str,
        status: str,
        discovered_from: str,
        http_status: int | None = None,
        content_hash: str = "",
        bytes_size: int | None = None,
        parse_summary: str = "",
        error_message: str = "",
        fetched_at: datetime | None = None,
        was_rendered: bool | None = None,
        extracted_chars: int | None = None,
        pdf_pages: int | None = None,
        pdf_text_chars: int | None = None,
    ) -> None:
        row = ExaminationLog(
            assessment_id=self.assessment.id,
            url=(url or "")[:1024],
            source_type=(source_type or "manual")[:32],
            status=(status or "fetched")[:32],
            http_status=http_status,
            content_hash=(content_hash or "")[:128],
            bytes=bytes_size,
            discovered_from=(discovered_from or "")[:128],
            fetched_at=fetched_at,
            was_rendered=was_rendered,
            extracted_chars=extracted_chars,
            pdf_pages=pdf_pages,
            pdf_text_chars=pdf_text_chars,
            parse_summary=parse_summary or "",
            error_message=error_message or "",
        )
        self.db.add(row)
        self.db.commit()

    def _log_external_once(self, url: str, discovered_from: str, parse_summary: str = "external link not fetched") -> None:
        key = f"{url}|{discovered_from}|{parse_summary}"
        if key in self._logged_external:
            return
        self._logged_external.add(key)
        self._log(
            url=url,
            source_type="manual",
            status="skipped_external",
            discovered_from=discovered_from,
            parse_summary=parse_summary,
            fetched_at=datetime.utcnow(),
        )

    def _normalize_url(self, value: str) -> str:
        raw = (value or "").strip()
        if not raw:
            return ""
        parsed = urlparse(raw)
        if not parsed.scheme:
            raw = f"https://{raw.lstrip('/')}"
            parsed = urlparse(raw)
        if parsed.scheme not in {"http", "https"}:
            return ""
        normalized = parsed._replace(
            scheme=parsed.scheme.lower(),
            netloc=parsed.netloc.lower(),
            fragment="",
        )
        path = normalized.path or "/"
        normalized = normalized._replace(path=path)
        return urlunparse(normalized)

    def _is_allowed_host(self, url: str) -> bool:
        host = urlparse(url).netloc.split(":")[0].lower()
        if not host or not self.target_host:
            return False
        return host == self.target_host or host.endswith(f".{self.target_host}")

    def _is_pdf_url(self, url: str) -> bool:
        path = (urlparse(url).path or "").lower()
        return path.endswith(".pdf")

    def _host_without_www(self, url: str) -> str:
        try:
            host = (urlparse(url).netloc or "").split(":")[0].strip().lower().strip(".")
        except Exception:
            return ""
        if host.startswith("www."):
            host = host[4:]
        return host

    def _social_platform_for_url(self, url: str) -> str:
        host = self._host_without_www(url)
        if not host:
            return ""
        for dom, platform in SOCIAL_PLATFORM_HOSTS.items():
            if host == dom or host.endswith(f".{dom}"):
                return platform
        return ""

    def _social_handle_for_url(self, url: str, platform: str) -> str:
        try:
            path = (urlparse(url).path or "").strip("/")
        except Exception:
            path = ""
        if not path:
            return ""
        parts = [p for p in path.split("/") if p]
        if not parts:
            return ""

        head = parts[0]
        if platform in {"instagram", "x", "twitter", "facebook"}:
            if head in {"share", "sharer.php", "intent", "search", "home"}:
                return ""
            return head.lstrip("@")[:255]

        if platform == "tiktok":
            return head.lstrip("@")[:255]

        if platform == "linkedin":
            if head in {"company", "in", "school"} and len(parts) >= 2:
                return parts[1].lstrip("@")[:255]
            return head.lstrip("@")[:255]

        if platform == "youtube":
            if head.startswith("@"):
                return head[1:][:255]
            if head in {"channel", "c", "user"} and len(parts) >= 2:
                return parts[1].lstrip("@")[:255]
            return head.lstrip("@")[:255]

        return head.lstrip("@")[:255]

    def _enqueue_social_candidate(self, url: str, *, discovered_from_url: str, anchor_text: str) -> None:
        normalized = self._normalize_url(url)
        if not normalized:
            return
        platform = self._social_platform_for_url(normalized)
        if not platform:
            return

        # Avoid common "share/intent" endpoints (we only want official profile-like URLs).
        low = normalized.lower()
        if any(x in low for x in ("/share", "/sharer", "/intent/", "sharearticle", "sharer.php")):
            return

        existing = self.social_candidates.get(normalized)
        if existing:
            # Keep the first candidate; it is enough for a controlled analysis.
            return

        self.social_candidates[normalized] = SocialCandidate(
            url=normalized,
            discovered_from_url=(discovered_from_url or "")[:1024],
            anchor_text=(anchor_text or "")[:160],
        )

    def _looks_like_pdf_candidate(self, url: str, anchor_text: str) -> bool:
        if self._is_pdf_url(url):
            return True
        low = f"{url} {anchor_text}".lower()
        return any(token in low for token in [" pdf", "download", "brochure", "report", "document", "whitepaper", "policy"])

    def _tokenize(self, text: str) -> list[str]:
        return [tok.lower() for tok in TOKEN_RE.findall((text or "").lower())]

    def _keyword_score(self, value: str) -> int:
        score = 0
        low = (value or "").lower()
        for key, weight in KEYWORD_WEIGHTS.items():
            if key in low:
                score += weight
        return score

    def _relevance_score(self, url: str, anchor_text: str, discovered_from: str) -> int:
        parsed = urlparse(url)
        path = (parsed.path or "/").lower()
        depth = len([x for x in path.split("/") if x])
        score = 1
        score += self._keyword_score(path)
        score += self._keyword_score(anchor_text)
        if depth <= 2:
            score += 1
        if discovered_from.startswith("seed"):
            score += 5
        elif discovered_from.startswith("sitemap"):
            score += 2
        elif discovered_from.startswith("homepage"):
            score += 2
        if self._is_pdf_url(url):
            score += 2
        return score

    def _add_candidate(self, candidates: dict[str, DiscoveryCandidate], url: str, discovered_from: str, anchor_text: str) -> None:
        if not url:
            return
        score = self._relevance_score(url, anchor_text, discovered_from)
        existing = candidates.get(url)
        if existing and existing.score >= score:
            return
        candidates[url] = DiscoveryCandidate(
            url=url,
            score=score,
            discovered_from=discovered_from,
            anchor_text=anchor_text[:160],
        )

    def _get_robots_parser(self, url: str) -> RobotFileParser | None:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if host in self.robots_cache:
            return self.robots_cache[host]

        robots_url = f"{parsed.scheme}://{host}/robots.txt"
        rp = RobotFileParser()
        try:
            self.limiter.wait()
            res = requests.get(robots_url, timeout=self.timeout, headers=self.headers, allow_redirects=True)
            if res.status_code < 400 and res.text.strip():
                rp.parse(res.text.splitlines())
                self.robots_cache[host] = rp
                return rp
        except Exception:
            pass

        self.robots_cache[host] = None
        return None

    def _can_fetch(self, url: str) -> bool:
        rp = self._get_robots_parser(url)
        if not rp:
            return True
        try:
            return rp.can_fetch(self.headers["User-Agent"], url)
        except Exception:
            return True

    def _fetch(self, url: str, *, max_bytes: int, source_type: str, discovered_from: str) -> FetchResult | None:
        fetched_at = datetime.utcnow()
        if not self._can_fetch(url):
            self._log(
                url=url,
                source_type=source_type,
                status="blocked",
                discovered_from="robots.txt",
                parse_summary="blocked by robots policy",
                fetched_at=fetched_at,
            )
            return None

        try:
            self.limiter.wait()
            with requests.get(url, timeout=self.timeout, headers=self.headers, allow_redirects=True, stream=True) as res:
                chunks: list[bytes] = []
                byte_count = 0
                for chunk in res.iter_content(8192):
                    if not chunk:
                        continue
                    byte_count += len(chunk)
                    if byte_count > max_bytes:
                        self._log(
                            url=res.url or url,
                            source_type=source_type,
                            status="skipped",
                            discovered_from=discovered_from,
                            http_status=res.status_code,
                            bytes_size=byte_count,
                            parse_summary=f"max size exceeded ({max_bytes} bytes)",
                            fetched_at=fetched_at,
                        )
                        return None
                    chunks.append(chunk)

                result = FetchResult(
                    final_url=res.url or url,
                    status_code=res.status_code,
                    content_type=res.headers.get("Content-Type", ""),
                    content=b"".join(chunks),
                )
        except Exception as exc:
            self._log(
                url=url,
                source_type=source_type,
                status="failed",
                discovered_from=discovered_from,
                error_message=f"{exc.__class__.__name__}: {exc}",
                fetched_at=fetched_at,
            )
            return None

        if not result.status_code or result.status_code >= 400:
            self._log(
                url=result.final_url or url,
                source_type=source_type,
                status="failed",
                discovered_from=discovered_from,
                http_status=result.status_code,
                error_message=f"http_status={result.status_code}",
                bytes_size=len(result.content),
                fetched_at=fetched_at,
            )
            return None

        return result

    def _extract_links(self, html_text: str, base_url: str) -> list[ParsedLink]:
        found: list[ParsedLink] = []
        for raw_href, raw_text in A_TAG_RE.findall(html_text):
            href = html.unescape(raw_href).strip()
            if not href or href.startswith("#") or href.lower().startswith("javascript:"):
                continue
            full = self._normalize_url(urljoin(base_url, href))
            if full:
                anchor = self._clean_html_text(raw_text)[:160]
                found.append(ParsedLink(url=full, anchor=anchor))
        deduped: list[ParsedLink] = []
        seen: set[str] = set()
        for row in found:
            if row.url in seen:
                continue
            seen.add(row.url)
            deduped.append(row)
        return deduped

    def _extract_script_sources(self, html_text: str, base_url: str) -> list[str]:
        found: list[str] = []
        for raw_src in SCRIPT_SRC_RE.findall(html_text or ""):
            src = html.unescape(raw_src).strip()
            if not src:
                continue
            full = self._normalize_url(urljoin(base_url, src))
            if full:
                found.append(full)
        deduped: list[str] = []
        seen: set[str] = set()
        for item in found:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
        return deduped[:40]

    def _clean_html_text(self, raw_html: str) -> str:
        value = COMMENT_RE.sub(" ", raw_html)
        value = SCRIPT_STYLE_RE.sub(" ", value)
        value = TAG_RE.sub(" ", value)
        value = html.unescape(value)
        value = re.sub(r"\s+", " ", value)
        return value.strip()

    def _extract_title(self, raw_html: str, fallback_url: str) -> str:
        match = TITLE_RE.search(raw_html or "")
        if match:
            title = self._clean_html_text(match.group(1))[:255]
            if title:
                return title
        path = PurePosixPath(urlparse(fallback_url).path or "/")
        if path.name:
            return path.name[:255]
        return urlparse(fallback_url).netloc[:255]

    def _extract_meta(self, raw_html: str) -> dict[str, str]:
        data: dict[str, str] = {}
        for key, value in META_RE.findall(raw_html or ""):
            k = (key or "").strip().lower()
            if k in {"description", "keywords", "og:description", "og:title"}:
                data[k] = self._clean_html_text(value)[:1000]
        return data

    def _detect_language(self, text: str) -> str:
        value = (text or "").lower()
        if len(value) < 80:
            return "unknown"

        profiles = {
            "en": (" the ", " and ", " with ", " for ", " from "),
            "it": (" il ", " la ", " per ", " con ", " che "),
            "es": (" el ", " la ", " para ", " con ", " que "),
            "fr": (" le ", " la ", " pour ", " avec ", " que "),
        }
        scores: dict[str, int] = {}
        padded = f" {value} "
        for lang, tokens in profiles.items():
            scores[lang] = sum(padded.count(token) for token in tokens)
        best = max(scores, key=scores.get)
        if scores[best] <= 1:
            return "unknown"
        return best

    def _build_html_document_payload(self, url: str, raw_html: str) -> tuple[str, str, str, int, list[ParsedLink]]:
        clean_text = self._clean_html_text(raw_html)
        title = self._extract_title(raw_html, url)
        meta = self._extract_meta(raw_html)
        script_sources = self._extract_script_sources(raw_html, url)
        emails = sorted(set(EMAIL_RE.findall(clean_text.lower())))[:20]
        phones = sorted(set(PHONE_RE.findall(clean_text)))[:20]
        headings = [self._clean_html_text(item) for item in H_RE.findall(raw_html or "")]
        headings = [h for h in headings if h][:20]

        sections = []
        if meta:
            sections.append("META: " + "; ".join(f"{k}={v}" for k, v in meta.items()))
        if headings:
            sections.append("HEADINGS: " + " | ".join(headings))
        if emails:
            sections.append("CONTACT_EMAILS: " + ", ".join(emails))
        if phones:
            sections.append("CONTACT_PHONES: " + ", ".join(phones))
        if script_sources:
            sections.append("SCRIPT_SRCS: " + " | ".join(script_sources))
        if clean_text:
            sections.append("BODY: " + clean_text[:180000])

        extracted_text = "\n".join(sections).strip()[:220000]
        language = self._detect_language(extracted_text)
        links = self._extract_links(raw_html, url)
        return title, extracted_text, language, len(extracted_text), links

    def _build_pdf_document_payload(self, url: str, data: bytes) -> tuple[str, str, str, int, int]:
        title = PurePosixPath(urlparse(url).path or "/").name or "document.pdf"
        if PdfReader is None:
            return title[:255], "", "unknown", 0, 0
        try:
            reader = PdfReader(io.BytesIO(data))
        except Exception:
            return title[:255], "", "unknown", 0, 0

        meta_title = ""
        try:
            meta_title = str((reader.metadata or {}).get("/Title", "")).strip()
        except Exception:
            meta_title = ""
        if meta_title:
            title = meta_title

        page_count = len(reader.pages)
        pages: list[str] = []
        for idx, page in enumerate(reader.pages):
            if idx >= 60:
                break
            try:
                value = page.extract_text() or ""
            except Exception:
                value = ""
            if value:
                pages.append(value)

        extracted_text = re.sub(r"\s+", " ", "\n".join(pages)).strip()[:220000]
        language = self._detect_language(extracted_text)
        text_chars = len(extracted_text)
        return title[:255], extracted_text, language, page_count, text_chars

    def _render_with_playwright(self, url: str) -> tuple[str, str]:
        if sync_playwright is None:
            return "", "playwright-not-installed"
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
                page.wait_for_timeout(800)
                rendered = page.content() or ""
                browser.close()
                return rendered, ""
        except Exception as exc:
            return "", f"playwright-error:{exc.__class__.__name__}"

    def _upsert_document(
        self,
        *,
        url: str,
        doc_type: str,
        title: str,
        extracted_text: str,
        language: str,
        content_hash: str,
    ) -> Document:
        existing = self.db.execute(
            select(Document).where(
                Document.assessment_id == self.assessment.id,
                Document.url == url,
            )
            .order_by(Document.created_at.desc(), Document.id.desc())
            .limit(1)
        ).scalars().first()

        if existing:
            existing.doc_type = doc_type
            existing.title = (title or "")[:255]
            existing.extracted_text = extracted_text or ""
            existing.language = (language or "unknown")[:16]
            existing.content_hash = (content_hash or "")[:128]
            self.db.commit()
            self.db.refresh(existing)
            self.created_or_updated.append(existing)
            return existing

        row = Document(
            assessment_id=self.assessment.id,
            url=(url or "")[:1024],
            doc_type=(doc_type or "html")[:32],
            title=(title or "")[:255],
            extracted_text=extracted_text or "",
            language=(language or "unknown")[:16],
            content_hash=(content_hash or "")[:128],
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        self.created_or_updated.append(row)
        return row

    def _discover_sitemap_urls(self, root_url: str) -> list[DiscoveryCandidate]:
        candidates: dict[str, DiscoveryCandidate] = {}
        sitemap_queue = [urljoin(root_url, "/sitemap.xml")]
        visited: set[str] = set()
        discovered_count = 0

        while sitemap_queue and discovered_count < MAX_DISCOVERY_SITEMAP_URLS:
            sitemap_url = self._normalize_url(sitemap_queue.pop(0))
            if not sitemap_url or sitemap_url in visited:
                continue
            visited.add(sitemap_url)

            result = self._fetch(
                sitemap_url,
                max_bytes=MAX_FETCH_BYTES,
                source_type="rss",
                discovered_from="discovery/sitemap",
            )
            if not result:
                continue

            body = result.content.decode("utf-8", errors="ignore")
            parsed_ok = True
            loc_values: list[str] = []
            try:
                root = ET.fromstring(body)
                for elem in root.iter():
                    if elem.tag.lower().endswith("loc") and (elem.text or "").strip():
                        loc_values.append((elem.text or "").strip())
            except Exception:
                parsed_ok = False

            self._log(
                url=sitemap_url,
                source_type="rss",
                status="parsed" if parsed_ok else "failed",
                discovered_from="discovery/sitemap",
                http_status=result.status_code,
                bytes_size=len(result.content),
                extracted_chars=len(body),
                parse_summary=f"sitemap entries={len(loc_values)}" if parsed_ok else "invalid sitemap xml",
                error_message="" if parsed_ok else "invalid sitemap xml",
                fetched_at=datetime.utcnow(),
            )

            if not parsed_ok:
                continue

            for raw in loc_values:
                normalized = self._normalize_url(raw)
                if not normalized:
                    continue
                if normalized.endswith(".xml") and "sitemap" in normalized.lower() and len(sitemap_queue) < 40:
                    sitemap_queue.append(normalized)
                    continue
                if not self._is_allowed_host(normalized):
                    self._log_external_once(normalized, discovered_from="discovery/sitemap", parse_summary="sitemap external url")
                    continue
                self._add_candidate(candidates, normalized, "sitemap", "sitemap")
                discovered_count += 1
                if discovered_count >= MAX_DISCOVERY_SITEMAP_URLS:
                    break

        return list(candidates.values())

    def _discover_homepage_urls(self, root_url: str) -> list[DiscoveryCandidate]:
        candidates: dict[str, DiscoveryCandidate] = {}
        result = self._fetch(
            root_url,
            max_bytes=MAX_FETCH_BYTES,
            source_type="html",
            discovered_from="discovery/homepage",
        )
        if not result:
            return []

        if not self._is_allowed_host(result.final_url):
            self._log_external_once(result.final_url, discovered_from="discovery/homepage", parse_summary="homepage redirected external")
            return []

        content_type = (result.content_type or "").lower()
        if "html" not in content_type:
            self._log(
                url=result.final_url,
                source_type="html",
                status="skipped",
                discovered_from="discovery/homepage",
                http_status=result.status_code,
                bytes_size=len(result.content),
                parse_summary=f"homepage non-html content-type={result.content_type}",
                fetched_at=datetime.utcnow(),
            )
            return []

        body = result.content.decode("utf-8", errors="ignore")
        links = self._extract_links(body, result.final_url)
        self._log(
            url=result.final_url,
            source_type="html",
            status="parsed",
            discovered_from="discovery/homepage",
            http_status=result.status_code,
            bytes_size=len(result.content),
            extracted_chars=len(body),
            parse_summary=f"homepage links discovered={len(links)}",
            fetched_at=datetime.utcnow(),
        )

        for link in links:
            if not self._is_allowed_host(link.url):
                if self._social_platform_for_url(link.url):
                    self._enqueue_social_candidate(
                        link.url,
                        discovered_from_url=result.final_url,
                        anchor_text=link.anchor,
                    )
                else:
                    self._log_external_once(link.url, discovered_from="homepage link")
                continue
            self._add_candidate(candidates, link.url, "homepage", link.anchor)

        return list(candidates.values())

    def _build_discovery_pool(self, root_url: str) -> list[DiscoveryCandidate]:
        candidates: dict[str, DiscoveryCandidate] = {}
        self._add_candidate(candidates, root_url, "seed/homepage", "homepage")
        for path in SEED_PATHS:
            self._add_candidate(candidates, self._normalize_url(urljoin(root_url, path)), "seed/path", path)
        for item in self._discover_sitemap_urls(root_url):
            self._add_candidate(candidates, item.url, item.discovered_from, item.anchor_text)
        for item in self._discover_homepage_urls(root_url):
            self._add_candidate(candidates, item.url, item.discovered_from, item.anchor_text)

        pool = [x for x in candidates.values() if self._is_allowed_host(x.url)]
        pool.sort(key=lambda x: (x.score, -len(urlparse(x.url).path or "")), reverse=True)
        return pool

    def _select_html_targets(self, discovery_pool: list[DiscoveryCandidate]) -> dict[str, DiscoveryCandidate]:
        selected: dict[str, DiscoveryCandidate] = {}
        for item in discovery_pool:
            if self._is_pdf_url(item.url):
                continue
            if item.url not in selected:
                selected[item.url] = item
            if len(selected) >= MAX_SELECTED_HTML_URLS:
                break
        return selected

    def _process_pdf(self, pdf_url: str, discovered_from: str) -> None:
        result = self._fetch(
            pdf_url,
            max_bytes=MAX_PDF_BYTES,
            source_type="pdf",
            discovered_from=discovered_from,
        )
        if not result:
            return

        content_type = (result.content_type or "").lower()
        if "pdf" not in content_type and not self._is_pdf_url(result.final_url):
            self._log(
                url=result.final_url,
                source_type="pdf",
                status="skipped",
                discovered_from=discovered_from,
                http_status=result.status_code,
                bytes_size=len(result.content),
                parse_summary=f"non-pdf content-type={result.content_type}",
                fetched_at=datetime.utcnow(),
            )
            return

        content_hash = hashlib.sha256(result.content).hexdigest() if result.content else ""
        if content_hash and content_hash in self.seen_hashes:
            self._log(
                url=result.final_url,
                source_type="pdf",
                status="skipped",
                discovered_from=discovered_from,
                http_status=result.status_code,
                content_hash=content_hash,
                bytes_size=len(result.content),
                parse_summary="duplicate content hash in assessment",
                fetched_at=datetime.utcnow(),
            )
            return

        title, extracted_text, language, pdf_pages, pdf_text_chars = self._build_pdf_document_payload(result.final_url, result.content)
        status = "parsed" if pdf_text_chars >= 200 else "pdf_needs_ocr_candidate"
        self._upsert_document(
            url=result.final_url,
            doc_type="pdf",
            title=title,
            extracted_text=extracted_text,
            language=language,
            content_hash=content_hash,
        )
        if content_hash:
            self.seen_hashes.add(content_hash)

        self._log(
            url=result.final_url,
            source_type="pdf",
            status=status,
            discovered_from=discovered_from,
            http_status=result.status_code,
            content_hash=content_hash,
            bytes_size=len(result.content),
            extracted_chars=pdf_text_chars,
            pdf_pages=pdf_pages,
            pdf_text_chars=pdf_text_chars,
            parse_summary=f"pdf parsed title={title[:80]} text_chars={pdf_text_chars}",
            fetched_at=datetime.utcnow(),
        )

    def _parse_human_count(self, raw: str) -> int | None:
        s = (raw or "").strip().lower()
        if not s:
            return None
        s = s.replace("followers", "").replace("follower", "").strip()
        s = s.replace(" ", "")
        if s.count(",") == 1 and "." not in s and any(s.endswith(x) for x in ("k", "m", "b")):
            s = s.replace(",", ".")
        s = s.replace(",", "")
        m = re.match(r"^([0-9]+(?:\\.[0-9]+)?)([kmb])?$", s)
        if not m:
            digits = re.sub(r"\\D", "", s)
            if digits.isdigit():
                try:
                    return int(digits)
                except Exception:
                    return None
            return None
        try:
            num = float(m.group(1))
        except Exception:
            return None
        mul = 1
        suf = (m.group(2) or "").lower()
        if suf == "k":
            mul = 1000
        elif suf == "m":
            mul = 1_000_000
        elif suf == "b":
            mul = 1_000_000_000
        try:
            return int(num * mul)
        except Exception:
            return None

    def _json_unescape(self, raw: str) -> str:
        value = raw or ""
        try:
            return json.loads(f"\"{value}\"")
        except Exception:
            return value.replace("\\\\n", "\\n").replace("\\\\t", "\\t").strip()

    def _extract_social_fields(self, *, platform: str, url: str, raw_html: str) -> dict:
        meta = self._extract_meta(raw_html)
        og_title = (meta.get("og:title") or meta.get("title") or "").strip()
        og_desc = (meta.get("og:description") or meta.get("description") or "").strip()

        profile_name = ""
        bio_text = ""
        verified: bool | None = None
        follower_count: int | None = None
        business_category = ""
        link_in_bio = ""

        # Platform-specific best-effort parsing (public HTML only, no login).
        if platform == "instagram":
            full_name = ""
            m = re.search(r'\"full_name\"\\s*:\\s*\"([^\"]*)\"', raw_html)
            if m:
                full_name = self._json_unescape(m.group(1))
            m = re.search(r'\"biography\"\\s*:\\s*\"([^\"]*)\"', raw_html)
            if m:
                bio_text = self._json_unescape(m.group(1))
            m = re.search(r'\"is_verified\"\\s*:\\s*(true|false)', raw_html, re.IGNORECASE)
            if m:
                verified = True if m.group(1).lower() == "true" else False
            m = re.search(r'\"edge_followed_by\"\\s*:\\s*\\{\\s*\"count\"\\s*:\\s*(\\d+)', raw_html)
            if m and (m.group(1) or "").isdigit():
                follower_count = int(m.group(1))
            m = re.search(r'\"external_url\"\\s*:\\s*\"([^\"]*)\"', raw_html)
            if m:
                link_in_bio = self._json_unescape(m.group(1))
            m = re.search(r'\"category_name\"\\s*:\\s*\"([^\"]*)\"', raw_html)
            if m:
                business_category = self._json_unescape(m.group(1))
            profile_name = (full_name or og_title or "").strip()
        else:
            profile_name = (og_title or "").strip()
            bio_text = (og_desc or "").strip()
            low_blob = (og_title + " " + og_desc).lower()
            if "verified" in low_blob:
                verified = True

            # follower count can sometimes appear in meta descriptions (LinkedIn/X/YouTube variants)
            m = re.search(r"([0-9][0-9.,]*\\s*[kKmM]?)\\s+followers", og_desc or "", re.IGNORECASE)
            if m:
                follower_count = self._parse_human_count(m.group(1))

        # Clean common suffixes in titles (keep a compact display name).
        if profile_name:
            for suffix in (
                "• instagram photos and videos",
                "| instagram",
                "instagram",
                "| facebook",
                "| linkedin",
                "| x",
                "| twitter",
                "| youtube",
                "| tiktok",
            ):
                if profile_name.lower().endswith(suffix):
                    profile_name = profile_name[: -len(suffix)].strip(" -|•")
            profile_name = " ".join(profile_name.split())[:255]

        # Pick a "link in bio" candidate from the extracted text if platform parser didn't find one.
        if not link_in_bio and bio_text:
            urls = URL_RE.findall(bio_text or "")
            if urls:
                link_in_bio = urls[0][:1024]

        return {
            "profile_name": profile_name,
            "bio_text": bio_text[:2400],
            "verified": verified,
            "follower_count": follower_count,
            "business_category": business_category[:255],
            "link_in_bio": link_in_bio[:1024],
        }

    def _upsert_social_node(
        self,
        *,
        platform: str,
        handle: str,
        profile_url: str,
        document_id: int | None,
        bio_text: str,
        business_category: str,
        follower_count: int | None,
        verified_status: bool | None,
        has_email_in_bio: bool,
        has_phone_in_bio: bool,
        link_in_bio: str,
        mentions_booking: bool,
        mentions_dm_contact: bool,
        signals: list[str],
        evidence_refs: list[dict],
    ) -> SocialTrustNode:
        existing = (
            self.db.execute(
                select(SocialTrustNode).where(
                    SocialTrustNode.assessment_id == self.assessment.id,
                    SocialTrustNode.profile_url == profile_url,
                )
            )
            .scalars()
            .first()
        )
        if not existing and handle:
            existing = (
                self.db.execute(
                    select(SocialTrustNode).where(
                        SocialTrustNode.assessment_id == self.assessment.id,
                        SocialTrustNode.platform == platform,
                        SocialTrustNode.handle == handle,
                    )
                )
                .scalars()
                .first()
            )

        if existing:
            existing.platform = (platform or "")[:32]
            existing.handle = (handle or "")[:255]
            existing.profile_url = (profile_url or "")[:1024]
            existing.document_id = int(document_id) if document_id else None
            existing.verified_status = verified_status
            existing.bio_text = bio_text or ""
            existing.business_category = (business_category or "")[:255]
            existing.follower_count = int(follower_count) if follower_count is not None else None
            existing.has_email_in_bio = bool(has_email_in_bio)
            existing.has_phone_in_bio = bool(has_phone_in_bio)
            existing.link_in_bio = (link_in_bio or "")[:1024]
            existing.mentions_booking = bool(mentions_booking)
            existing.mentions_dm_contact = bool(mentions_dm_contact)
            existing.signals_json = json.dumps(signals or [], ensure_ascii=True)
            existing.evidence_refs_json = json.dumps(evidence_refs or [], ensure_ascii=True)
            self.db.commit()
            self.db.refresh(existing)
            return existing

        row = SocialTrustNode(
            assessment_id=self.assessment.id,
            platform=(platform or "")[:32],
            handle=(handle or "")[:255],
            profile_url=(profile_url or "")[:1024],
            document_id=int(document_id) if document_id else None,
            verified_status=verified_status,
            bio_text=bio_text or "",
            business_category=(business_category or "")[:255],
            follower_count=int(follower_count) if follower_count is not None else None,
            has_email_in_bio=bool(has_email_in_bio),
            has_phone_in_bio=bool(has_phone_in_bio),
            link_in_bio=(link_in_bio or "")[:1024],
            mentions_booking=bool(mentions_booking),
            mentions_dm_contact=bool(mentions_dm_contact),
            signals_json=json.dumps(signals or [], ensure_ascii=True),
            trust_friction_score=0,
            evidence_refs_json=json.dumps(evidence_refs or [], ensure_ascii=True),
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def _process_social_page(self, candidate: SocialCandidate) -> None:
        url = candidate.url
        fetched_at = datetime.utcnow()
        platform = self._social_platform_for_url(url)
        if not platform:
            self._log(
                url=url,
                source_type="social",
                status="skipped",
                discovered_from=candidate.discovered_from_url or "social",
                parse_summary="not a supported social platform",
                fetched_at=fetched_at,
            )
            return

        handle_guess = self._social_handle_for_url(url, platform)
        origin_url = (candidate.discovered_from_url or "").strip()
        origin_doc_id: int | None = None
        origin_title = ""
        if origin_url.startswith("http"):
            doc = (
                self.db.execute(
                    select(Document).where(
                        Document.assessment_id == self.assessment.id,
                        Document.url == origin_url,
                    )
                    .order_by(Document.created_at.desc(), Document.id.desc())
                    .limit(1)
                )
                .scalars()
                .first()
            )
            if doc:
                origin_doc_id = int(doc.id)
                origin_title = doc.title or ""

        result = self._fetch(
            url,
            max_bytes=MAX_SOCIAL_FETCH_BYTES,
            source_type="social",
            discovered_from=candidate.discovered_from_url or "social",
        )
        if not result:
            title = f"{platform} {('@' + handle_guess) if handle_guess else 'profile'}".strip()
            evidence_refs = [
                {
                    "url": url[:1024],
                    "title": title[:255],
                    "snippet": "Social profile link discovered, but fetch was blocked or failed (limited OSINT mode).",
                    "doc_id": None,
                    "confidence": 35,
                    "signal_type": "SOCIAL_TRUST_NODE",
                }
            ]
            if origin_url:
                evidence_refs.append(
                    {
                        "url": origin_url[:1024],
                        "title": origin_title[:255],
                        "snippet": f"Official site links to {platform} profile ({candidate.anchor_text or 'social link'}).",
                        "doc_id": origin_doc_id,
                        "confidence": 55,
                        "signal_type": "SOCIAL_TRUST_NODE",
                    }
                )
            self._upsert_social_node(
                platform=platform,
                handle=handle_guess,
                profile_url=url,
                document_id=None,
                bio_text="",
                business_category="",
                follower_count=None,
                verified_status=None,
                has_email_in_bio=False,
                has_phone_in_bio=False,
                link_in_bio="",
                mentions_booking=False,
                mentions_dm_contact=False,
                signals=[],
                evidence_refs=evidence_refs,
            )
            return

        content_type = (result.content_type or "").lower()
        if "html" not in content_type:
            self._log(
                url=result.final_url,
                source_type="social",
                status="skipped",
                discovered_from=candidate.discovered_from_url or "social",
                http_status=result.status_code,
                bytes_size=len(result.content),
                parse_summary=f"social non-html content-type={result.content_type}",
                fetched_at=fetched_at,
            )
            return

        raw_html = result.content.decode("utf-8", errors="ignore")
        content_hash = hashlib.sha256(result.content).hexdigest() if result.content else ""
        if content_hash and content_hash in self.seen_hashes:
            self._log(
                url=result.final_url,
                source_type="social",
                status="skipped",
                discovered_from=candidate.discovered_from_url or "social",
                http_status=result.status_code,
                content_hash=content_hash,
                bytes_size=len(result.content),
                parse_summary="duplicate content hash in assessment",
                fetched_at=fetched_at,
            )
            return

        handle = self._social_handle_for_url(result.final_url or url, platform)
        fields = self._extract_social_fields(platform=platform, url=(result.final_url or url), raw_html=raw_html)
        profile_name = str(fields.get("profile_name") or "").strip()
        bio_text = str(fields.get("bio_text") or "").strip()
        verified = fields.get("verified")
        follower_count = fields.get("follower_count")
        business_category = str(fields.get("business_category") or "").strip()
        link_in_bio = str(fields.get("link_in_bio") or "").strip()

        has_email = bool(EMAIL_RE.search(bio_text or ""))
        has_phone = bool(PHONE_RE.search(bio_text or ""))
        low_bio = (bio_text or "").lower()
        mentions_booking = any(k in low_bio for k in SOCIAL_BOOKING_HINTS) or any(k in (link_in_bio or "").lower() for k in SOCIAL_BOOKING_HINTS)
        mentions_dm = any(k in low_bio for k in SOCIAL_DM_HINTS)

        signals: list[str] = []
        if has_email or has_phone:
            signals.append("SOCIAL_CONTACT_CHANNEL")
        if mentions_dm:
            signals.append("DIRECT_MESSAGE_WORKFLOW")
        if mentions_booking and link_in_bio:
            signals.append("SOCIAL_TO_BOOKING_DEPENDENCY")
        if bool(verified) is True:
            signals.append("VERIFIED_TRUST_ANCHOR")
        if bool(verified) is False and follower_count is not None and int(follower_count or 0) >= 50000:
            signals.append("HIGH_IMPERSONATION_ATTRACTIVENESS")

        # origin_doc_id/title/url already resolved above for evidence linking.

        title = profile_name or f"{platform} {('@' + handle) if handle else 'profile'}"
        extracted_lines = [
            "SOCIAL_TRUST_NODE",
            f"PLATFORM: {platform}",
            f"HANDLE: {handle}" if handle else "HANDLE: (unknown)",
            f"VERIFIED: {verified}" if verified is not None else "VERIFIED: unknown",
            f"FOLLOWERS: {follower_count}" if follower_count is not None else "FOLLOWERS: unknown",
        ]
        if business_category:
            extracted_lines.append(f"BUSINESS_CATEGORY: {business_category}")
        if link_in_bio:
            extracted_lines.append(f"LINK_IN_BIO: {link_in_bio}")
        if signals:
            extracted_lines.append("SOCIAL_SIGNALS: " + ", ".join(signals))
        if candidate.anchor_text:
            extracted_lines.append(f"DISCOVERY_ANCHOR: {candidate.anchor_text}")
        if origin_url:
            extracted_lines.append(f"DISCOVERED_FROM: {origin_url}")
        if bio_text:
            extracted_lines.append("BIO: " + bio_text)
        extracted_text = "\n".join(extracted_lines).strip()[:220000]
        language = self._detect_language(extracted_text)

        doc = self._upsert_document(
            url=(result.final_url or url),
            doc_type="social",
            title=title,
            extracted_text=extracted_text,
            language=language,
            content_hash=content_hash,
        )
        if content_hash:
            self.seen_hashes.add(content_hash)

        evidence_refs = [
            {
                "url": (result.final_url or url)[:1024],
                "title": title[:255],
                "snippet": (bio_text or title)[:600],
                "doc_id": int(doc.id),
                "confidence": 65,
                "signal_type": "SOCIAL_TRUST_NODE",
            }
        ]
        if origin_url:
            evidence_refs.append(
                {
                    "url": origin_url[:1024],
                    "title": origin_title[:255],
                    "snippet": f"Official site links to {platform} profile ({candidate.anchor_text or 'social link'}).",
                    "doc_id": origin_doc_id,
                    "confidence": 60,
                    "signal_type": "SOCIAL_TRUST_NODE",
                }
            )

        self._upsert_social_node(
            platform=platform,
            handle=handle,
            profile_url=(result.final_url or url),
            document_id=int(doc.id),
            bio_text=bio_text,
            business_category=business_category,
            follower_count=int(follower_count) if follower_count is not None else None,
            verified_status=verified if isinstance(verified, bool) else None,
            has_email_in_bio=has_email,
            has_phone_in_bio=has_phone,
            link_in_bio=link_in_bio,
            mentions_booking=bool(mentions_booking),
            mentions_dm_contact=bool(mentions_dm),
            signals=signals,
            evidence_refs=evidence_refs,
        )

        self._log(
            url=(result.final_url or url),
            source_type="social",
            status="parsed",
            discovered_from=candidate.discovered_from_url or "social",
            http_status=result.status_code,
            content_hash=content_hash,
            bytes_size=len(result.content),
            extracted_chars=len(extracted_text),
            parse_summary=f"social parsed platform={platform} handle={handle or '-'} verified={verified} bio_chars={len(bio_text)}",
            fetched_at=fetched_at,
        )

    def _process_html_page(
        self,
        url: str,
        depth: int,
        discovered_from: str,
        selected: dict[str, DiscoveryCandidate],
        queue: list[tuple[str, int, str]],
        queued: set[str],
        visited: set[str],
        pdf_candidates: list[tuple[str, str]],
    ) -> None:
        result = self._fetch(
            url,
            max_bytes=MAX_FETCH_BYTES,
            source_type="html",
            discovered_from=discovered_from,
        )
        if not result:
            return

        if not self._is_allowed_host(result.final_url):
            self._log_external_once(result.final_url, discovered_from=discovered_from, parse_summary="redirected external")
            return

        content_type = (result.content_type or "").lower()
        if "pdf" in content_type or self._is_pdf_url(result.final_url):
            self._process_pdf(result.final_url, discovered_from)
            return

        if "html" not in content_type:
            self._log(
                url=result.final_url,
                source_type="html",
                status="skipped",
                discovered_from=discovered_from,
                http_status=result.status_code,
                bytes_size=len(result.content),
                parse_summary=f"non-html content-type={result.content_type}",
                fetched_at=datetime.utcnow(),
            )
            return

        raw_html = result.content.decode("utf-8", errors="ignore")
        title, extracted_text, language, extracted_chars, links = self._build_html_document_payload(result.final_url, raw_html)
        was_rendered = False
        render_note = ""
        if (extracted_chars < 800 or not title.strip()) and self.render_budget > 0:
            self.render_budget -= 1
            rendered_html, render_error = self._render_with_playwright(result.final_url)
            if rendered_html:
                t2, x2, l2, c2, links2 = self._build_html_document_payload(result.final_url, rendered_html)
                if c2 >= extracted_chars or (not title.strip() and t2.strip()):
                    title, extracted_text, language, extracted_chars, links = t2, x2, l2, c2, links2
                was_rendered = True
            elif render_error:
                render_note = render_error

        content_hash = hashlib.sha256(result.content).hexdigest() if result.content else ""
        if content_hash and content_hash in self.seen_hashes:
            self._log(
                url=result.final_url,
                source_type="html",
                status="skipped",
                discovered_from=discovered_from,
                http_status=result.status_code,
                content_hash=content_hash,
                bytes_size=len(result.content),
                was_rendered=was_rendered,
                extracted_chars=extracted_chars,
                parse_summary="duplicate content hash in assessment",
                fetched_at=datetime.utcnow(),
            )
            return

        self._upsert_document(
            url=result.final_url,
            doc_type="html",
            title=title,
            extracted_text=extracted_text,
            language=language,
            content_hash=content_hash,
        )
        if content_hash:
            self.seen_hashes.add(content_hash)

        summary = f"html parsed title={title[:80]} chars={extracted_chars}"
        if render_note:
            summary += f" render_note={render_note}"
        self._log(
            url=result.final_url,
            source_type="html",
            status="parsed",
            discovered_from=discovered_from,
            http_status=result.status_code,
            content_hash=content_hash,
            bytes_size=len(result.content),
            was_rendered=was_rendered,
            extracted_chars=extracted_chars,
            parse_summary=summary,
            fetched_at=datetime.utcnow(),
        )

        for link in links:
            if not self._is_allowed_host(link.url):
                if self._looks_like_pdf_candidate(link.url, link.anchor):
                    pdf_candidates.append((link.url, f"{result.final_url} link"))
                elif self._social_platform_for_url(link.url):
                    self._enqueue_social_candidate(
                        link.url,
                        discovered_from_url=result.final_url,
                        anchor_text=link.anchor,
                    )
                else:
                    self._log_external_once(link.url, discovered_from=f"{result.final_url} link")
                continue

            if self._looks_like_pdf_candidate(link.url, link.anchor):
                pdf_candidates.append((link.url, f"{result.final_url} link"))
                continue

            if depth >= 2:
                continue

            if link.url in selected and link.url not in visited and link.url not in queued:
                queue.append((link.url, depth + 1, f"{result.final_url} link"))
                queued.add(link.url)

    def run(self) -> list[Document]:
        root_url = self._normalize_url(f"https://{self.target_host}/")
        if not root_url or not self.target_host:
            self._log(
                url=f"collector://assessment/{self.assessment.id}",
                source_type="manual",
                status="failed",
                discovered_from="collector_v2",
                error_message="invalid target domain",
                fetched_at=datetime.utcnow(),
            )
            return []

        discovery_pool = self._build_discovery_pool(root_url)
        selected = self._select_html_targets(discovery_pool)
        if root_url not in selected:
            selected[root_url] = DiscoveryCandidate(
                url=root_url,
                score=999,
                discovered_from="seed/homepage",
                anchor_text="homepage",
            )

        queue: list[tuple[str, int, str]] = []
        for idx, item in enumerate(selected.values()):
            queue.append((item.url, 0 if item.url == root_url else 1, item.discovered_from))
            if idx >= MAX_SELECTED_HTML_URLS:
                break
        queued = {x[0] for x in queue}
        visited: set[str] = set()
        pdf_candidates: list[tuple[str, str]] = []

        while queue:
            current_url, depth, discovered_from = queue.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)
            self._process_html_page(
                current_url,
                depth,
                discovered_from,
                selected,
                queue,
                queued,
                visited,
                pdf_candidates,
            )

        seen_pdf: set[str] = set()
        processed_pdf = 0
        for pdf_url, discovered_from in pdf_candidates:
            normalized = self._normalize_url(pdf_url)
            if not normalized or normalized in seen_pdf:
                continue
            seen_pdf.add(normalized)

            if processed_pdf >= MAX_PDF_PER_RUN:
                self._log(
                    url=normalized,
                    source_type="pdf",
                    status="skipped",
                    discovered_from=discovered_from,
                    parse_summary=f"pdf run limit reached ({MAX_PDF_PER_RUN})",
                    fetched_at=datetime.utcnow(),
                )
                continue

            self._process_pdf(normalized, discovered_from)
            processed_pdf += 1

        processed_social = 0
        for cand in list(self.social_candidates.values()):
            if processed_social >= MAX_SOCIAL_PER_RUN:
                self._log(
                    url=cand.url,
                    source_type="social",
                    status="skipped",
                    discovered_from=cand.discovered_from_url or "social",
                    parse_summary=f"social run limit reached ({MAX_SOCIAL_PER_RUN})",
                    fetched_at=datetime.utcnow(),
                )
                continue
            self._process_social_page(cand)
            processed_social += 1

        return self.created_or_updated


def collect_documents(assessment_id: int, db: Session | None = None) -> list[Document]:
    """Collector v2 entrypoint.

    Runs discovery (sitemap/homepage/seeded paths), selects top-relevance URLs,
    crawls selected pages (depth 1-2), follows linked PDFs (including externally hosted PDFs
    referenced from target pages), stores normalized documents, and logs all outcomes.
    """
    if db is None:
        with SessionLocal() as local_db:
            return collect_documents(assessment_id, db=local_db)

    assessment = db.get(Assessment, assessment_id)
    if not assessment:
        return []

    collector = _CollectorV2(db=db, assessment=assessment)
    try:
        return collector.run()
    except Exception:
        logger.exception("collector_v2 failed for assessment %s", assessment_id)
        collector._log(
            url=f"collector://assessment/{assessment_id}",
            source_type="manual",
            status="failed",
            discovered_from="collector_v2",
            error_message="unexpected collector failure",
            fetched_at=datetime.utcnow(),
        )
        return []
