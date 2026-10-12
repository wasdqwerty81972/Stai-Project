# PyInstaller spec for the local STAI protection Windows service.
# No private key or editable rule package is bundled. A raw 32-byte trusted
# Ed25519 public key may be supplied through STAI_TRUSTED_RULES_PUBLIC_KEY.

from pathlib import Path
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

installer_dir = Path(SPECPATH).resolve()
project_root = installer_dir.parents[1]
entry_script = installer_dir / "service_entry.py"
datas = []
binaries = []
hiddenimports = [
    "pywintypes",
    "pythoncom",
    "servicemanager",
    "win32api",
    "win32event",
    "win32file",
    "win32pipe",
    "win32security",
    "win32service",
    "win32serviceutil",
    "win32timezone",
    "yara",
]

public_key_path = os.environ.get("STAI_TRUSTED_RULES_PUBLIC_KEY")
if public_key_path:
    key_path = Path(public_key_path).resolve(strict=True)
    pem = key_path.read_bytes()
    if (
        not pem.lstrip().startswith(b"-----BEGIN PUBLIC KEY-----")
        or b"PRIVATE KEY" in pem
    ):
        raise ValueError("only a public-key PEM file is accepted; private keys are rejected")
    public_key = serialization.load_pem_public_key(pem)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("trusted rules key must be Ed25519")
    raw_key_path = Path(os.environ["STAI_BUILD_ROOT"]) / "resources" / "trusted-rules.pub"
    raw_key_path.parent.mkdir(parents=True, exist_ok=True)
    raw_key_path.write_bytes(
        public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    datas.append((str(raw_key_path), "resources"))

a = Analysis(
    [str(entry_script)],
    pathex=[str(project_root)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "tests", "test", "unittest"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="STAIProtectionService",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    target_arch="x86_64",
    codesign_identity=None,
    entitlements_file=None,
)
