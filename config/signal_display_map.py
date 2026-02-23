from __future__ import annotations

import re
from typing import Any


SIGNAL_DISPLAY_MAP: dict[str, dict[str, str]] = {
    "WORKFLOW_HANDLING_CUES": {
        "display_name": "Publicly exposed operational processes",
        "short_label": "Operational process exposure",
    },
    "CHANNEL_AMBIGUITY": {
        "display_name": "Multiple or unclear contact channels",
        "short_label": "Channel ambiguity",
    },
    "VENDOR_PLATFORM_CUES": {
        "display_name": "Third-party service dependency",
        "short_label": "External platform dependency",
    },
    "ROLE_TARGETABILITY_SIGNAL": {
        "display_name": "Identifiable staff roles exposed publicly",
        "short_label": "Public role exposure",
    },
    "EMAIL_SPOOFING_RISK": {
        "display_name": "Weak email authentication posture",
        "short_label": "Email spoofing risk",
    },
    "DIRECT_MESSAGE_WORKFLOW_SIGNAL": {
        "display_name": "Direct messaging used for operational requests",
        "short_label": "Direct messaging channel",
    },
    # Existing internal bundle names mapped to human-readable equivalents.
    "INFORMAL_WORKFLOW": {
        "display_name": "Publicly exposed operational processes",
        "short_label": "Operational process exposure",
    },
    "VENDOR_DEPENDENCY": {
        "display_name": "Third-party service dependency",
        "short_label": "External platform dependency",
    },
    "IDENTITY_SIGNALS": {
        "display_name": "Publicly visible staff and contact channels",
        "short_label": "Identity/contact exposure",
    },
    "EXTERNAL_VISIBILITY": {
        "display_name": "High external visibility and narrative pressure",
        "short_label": "External visibility pressure",
    },
    "INFRA_ENDPOINTS": {
        "display_name": "Public support/portal infrastructure exposure",
        "short_label": "Support/portal exposure",
    },
}


def _fallback_label(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "Signal bundle"
    text = re.sub(r"[_\-]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text.title()


def get_signal_display_entry(internal_name: str, fallback_name: str = "") -> dict[str, str]:
    key = str(internal_name or "").strip().upper()
    entry = SIGNAL_DISPLAY_MAP.get(key)
    if entry:
        return {
            "display_name": str(entry.get("display_name", "")).strip() or _fallback_label(fallback_name or key),
            "short_label": str(entry.get("short_label", "")).strip() or _fallback_label(fallback_name or key),
        }
    fallback = _fallback_label(fallback_name or key)
    return {"display_name": fallback, "short_label": fallback}


def map_bundle_display(
    *,
    bundle_type: str,
    bundle_title: str,
    signal_types: list[str] | None = None,
) -> dict[str, str]:
    # 1) Bundle type mapping.
    mapped = get_signal_display_entry(bundle_type, fallback_name=bundle_title or bundle_type)
    # 2) If not specifically mapped and we have a signal type, attempt signal-level mapping.
    if (
        mapped["display_name"] == _fallback_label(bundle_title or bundle_type)
        and signal_types
        and len(signal_types) > 0
    ):
        mapped = get_signal_display_entry(str(signal_types[0]), fallback_name=bundle_title or bundle_type)
    return mapped


__all__ = ["SIGNAL_DISPLAY_MAP", "get_signal_display_entry", "map_bundle_display"]
