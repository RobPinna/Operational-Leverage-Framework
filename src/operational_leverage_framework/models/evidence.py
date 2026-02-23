from __future__ import annotations

from dataclasses import dataclass
from typing import TypedDict


class RawEvidenceItem(TypedDict, total=False):
    url: str
    snippet: str
    signal_type: str
    is_boilerplate: bool
    weight: float
    quality_tier: str


@dataclass(slots=True, frozen=True)
class EvidenceItem:
    url: str
    snippet: str
    signal_type: str = ""
    is_boilerplate: bool = False
    weight: float = 1.0
    quality_tier: str = ""

    def to_signal_model_payload(self) -> RawEvidenceItem:
        return {
            "url": self.url,
            "snippet": self.snippet,
            "signal_type": self.signal_type,
            "is_boilerplate": self.is_boilerplate,
            "weight": self.weight,
            "quality_tier": self.quality_tier,
        }


def to_evidence_item(payload: RawEvidenceItem) -> EvidenceItem:
    return EvidenceItem(
        url=str(payload.get("url", "")),
        snippet=str(payload.get("snippet", "")),
        signal_type=str(payload.get("signal_type", "")),
        is_boilerplate=bool(payload.get("is_boilerplate", False)),
        weight=float(payload.get("weight", 1.0) or 1.0),
        quality_tier=str(payload.get("quality_tier", "")),
    )
