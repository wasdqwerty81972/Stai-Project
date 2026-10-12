"""Importable entry point for the frozen Windows service executable."""

import sys
from pathlib import Path

import yara

from cyber_os.protection.rule_package import InvalidRulePackage, RulePackage
from cyber_os.protection.windows_service import main


def _verify_rules(manifest: str, signature: str) -> int:
    """Verify a rule package using only the public key embedded in this build."""
    resource_root = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
    public_key_path = resource_root / "resources" / "trusted-rules.pub"
    try:
        public_key = public_key_path.read_bytes()
        RulePackage.load(Path(manifest), Path(signature), public_key)
    except (OSError, InvalidRulePackage):
        print("Rule package verification failed.", file=sys.stderr)
        return 2
    print("Rule package signature and schema verified.")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--stai-smoke-check"]:
        # The packaging script uses this non-installing path to verify that
        # Python, pywin32, YARA, and the protection imports all load when frozen.
        print(f"STAI protection service imports ready (YARA {yara.__version__}).")
    elif len(sys.argv) == 4 and sys.argv[1] == "--stai-verify-rules":
        raise SystemExit(_verify_rules(sys.argv[2], sys.argv[3]))
    else:
        main()
