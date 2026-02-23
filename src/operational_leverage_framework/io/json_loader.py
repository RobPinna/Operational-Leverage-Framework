from __future__ import annotations

import json
from pathlib import Path

from ..models import EvidenceItem, to_evidence_item


def load_evidence_file(path: Path) -> list[EvidenceItem]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("Input JSON must be a list of evidence items.")
    items: list[EvidenceItem] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("Each evidence item must be an object.")
        items.append(to_evidence_item(item))  # type: ignore[arg-type]
    return items


def dump_result_file(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
