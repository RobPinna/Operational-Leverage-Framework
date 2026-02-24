import json
from typing import Any


def to_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=True, default=str)


def from_json(value: str, fallback: Any):
    try:
        return json.loads(value) if value else fallback
    except Exception:
        return fallback
