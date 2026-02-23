from __future__ import annotations

from urllib.parse import urlparse


def normalize_target_host(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    probe = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(probe)
    host = (parsed.netloc or parsed.path or "").strip().lower()
    host = host.split("/")[0].split(":")[0].strip(".")
    return host


def canonical_domain_for_api(value: str) -> str:
    """Return host-only domain value for API endpoints and DNS lookups."""
    return normalize_target_host(value)

