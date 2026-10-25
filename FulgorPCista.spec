# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas_pn, binaries_pn, hiddenimports_pn = collect_all('pythonnet')

datas = [('ui', 'ui'), ('app.ico', '.'), ('OpenHardwareMonitorServer.exe', '.'), ('OpenHardwareMonitorServer.exe.config', '.'), ('LibreHardwareMonitorLib.dll', '.')] + datas_pn
binaries = binaries_pn
hiddenimports = hiddenimports_pn + ['clr']

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
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
    [],
    exclude_binaries=True,
    name='FulgorPCista',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['app.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='FulgorPCista',
)
