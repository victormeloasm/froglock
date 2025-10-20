# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['FROGLock_GHOST_v5_3.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['argon2.low_level', 'blake3'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['numpy', 'gmpy2'],
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
    name='FROGLock_GHOST_v5_3',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir='%TEMP%\\frog_%USERNAME%',
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
