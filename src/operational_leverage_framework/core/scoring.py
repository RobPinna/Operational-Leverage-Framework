from __future__ import annotations

from typing import Any

from app.services.signal_model import compute_hypothesis_confidence

from ..models import EvidenceItem


def compute_confidence(
    evidence: list[EvidenceItem],
    *,
    base_avg: int = 60,
    sector: str = "",
    risk_type: str = "impersonation",
) -> tuple[int, dict[str, Any]]:
    payload = [item.to_signal_model_payload() for item in evidence]
    return compute_hypothesis_confidence(
        payload,
        base_avg=base_avg,
        sector=sector,
        risk_type=risk_type,
    )
