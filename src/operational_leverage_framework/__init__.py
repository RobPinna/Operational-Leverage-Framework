from __future__ import annotations

from pathlib import Path
import sys
import tomllib

from .core.scoring import compute_confidence

__version__ = "0.1.0"


def get_runtime_version() -> str:
    candidates: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        candidates.append(Path(meipass) / "pyproject.toml")

    candidates.append(Path.cwd() / "pyproject.toml")
    candidates.append(Path(__file__).resolve().parents[2] / "pyproject.toml")

    seen: set[Path] = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        if not path.exists():
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        version = str((data.get("project", {}) or {}).get("version", "")).strip()
        if version:
            return version
    return __version__


__all__ = ["__version__", "compute_confidence", "get_runtime_version"]
