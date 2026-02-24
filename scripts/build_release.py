from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess
import sys


ROOT_DIR = Path(__file__).resolve().parents[1]
SPEC_PATH = ROOT_DIR / "OperationalLeverageFramework.spec"
DIST_DIR = ROOT_DIR / "dist"
DIST_RELEASE_DIR = ROOT_DIR / "dist_release"
ARTIFACT_BASENAME = "OperationalLeverageFramework"


def _format_cmd(cmd: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline(cmd)
    return " ".join(cmd)


def _run(cmd: list[str], *, cwd: Path | None = None, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    print(f"+ {_format_cmd(cmd)}")
    return subprocess.run(
        cmd,
        cwd=str(cwd or ROOT_DIR),
        text=True,
        capture_output=capture_output,
    )


def _ensure_pyinstaller() -> None:
    probe = _run([sys.executable, "-m", "PyInstaller", "--version"], capture_output=True)
    if probe.returncode != 0:
        msg = (probe.stderr or probe.stdout or "").strip()
        if msg:
            print(msg, file=sys.stderr)
        print("error: PyInstaller is not available. Install it in your environment first.", file=sys.stderr)
        raise SystemExit(1)
    version = (probe.stdout or "").strip()
    if version:
        print(f"PyInstaller {version}")


def _resolve_built_artifact() -> Path:
    exe_suffix = ".exe" if os.name == "nt" else ""
    onefile = DIST_DIR / f"{ARTIFACT_BASENAME}{exe_suffix}"
    if onefile.exists():
        return onefile

    onefolder = DIST_DIR / ARTIFACT_BASENAME
    if onefolder.exists():
        return onefolder

    matches = sorted(DIST_DIR.glob(f"{ARTIFACT_BASENAME}*"))
    if matches:
        return matches[0]

    print("error: build finished but no expected artifact was found in dist/.", file=sys.stderr)
    raise SystemExit(1)


def _copy_to_release(artifact_path: Path) -> Path:
    DIST_RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    dest = DIST_RELEASE_DIR / artifact_path.name
    if dest.exists():
        if dest.is_dir():
            shutil.rmtree(dest)
        else:
            dest.unlink()

    if artifact_path.is_dir():
        shutil.copytree(artifact_path, dest)
    else:
        shutil.copy2(artifact_path, dest)
    return dest


def main() -> int:
    if not SPEC_PATH.exists():
        print(f"error: spec file not found: {SPEC_PATH}", file=sys.stderr)
        return 1

    _ensure_pyinstaller()
    build = _run([sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", str(SPEC_PATH)])
    if build.returncode != 0:
        return build.returncode

    artifact = _resolve_built_artifact()
    final_path = _copy_to_release(artifact)
    print(f"final artifact: {final_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
