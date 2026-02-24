from __future__ import annotations

from pathlib import Path
import shutil


ROOT_DIR = Path(__file__).resolve().parents[1]
TARGETS = ("build", "dist", "dist_release")


def main() -> int:
    for name in TARGETS:
        path = ROOT_DIR / name
        if not path.exists():
            continue
        shutil.rmtree(path, ignore_errors=True)
        print(f"removed: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
