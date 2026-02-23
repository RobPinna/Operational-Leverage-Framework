from __future__ import annotations

import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
VENV_SITE_PACKAGES = ROOT_DIR / ".venv" / "Lib" / "site-packages"

for path in (ROOT_DIR, SRC_DIR, VENV_SITE_PACKAGES):
    value = str(path)
    if path.exists() and value not in sys.path:
        sys.path.insert(0, value)
