# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules


ROOT = Path(__file__).resolve().parent

datas = [
    (str(ROOT / "templates"), "templates"),
    (str(ROOT / "static"), "static"),
]

if (ROOT / "pyproject.toml").exists():
    datas.append((str(ROOT / "pyproject.toml"), "."))

hiddenimports = collect_submodules("uvicorn")

a = Analysis(
    [str(ROOT / "src" / "operational_leverage_framework" / "packaged_app.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="OperationalLeverageFramework",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
