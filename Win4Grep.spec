# PyInstaller spec to build Win4Grep.exe
# Build:  .\.venv\Scripts\python -m PyInstaller --noconfirm Win4Grep.spec
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

hiddenimports = []
datas = []
for pkg in ("blackboxprotobuf", "nska_deserialize"):
    hiddenimports += collect_submodules(pkg)
    datas += collect_data_files(pkg)
hiddenimports += collect_submodules("Crypto")

block_cipher = None

a = Analysis(
    ["app_entry.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "PIL", "pytest"],
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="Win4Grep",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,            # GUI app, no console window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
