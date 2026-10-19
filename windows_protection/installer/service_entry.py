"""Importable entry point for the frozen Windows service executable."""

import os
import sys
import time
import logging
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
    elif sys.argv[1:] == ["--stai-local-dev"]:
        if os.environ.get("STAI_LOCAL_DEV_SERVICE") != "1":
            raise SystemExit(
                "Set STAI_LOCAL_DEV_SERVICE=1 to run the user-scoped development host."
            )
        from cyber_os.protection.windows_service import create_default_host

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
            stream=sys.stderr,
        )
        host = create_default_host()
        host.start()
        status = host.get_status()
        print(
            "STAI local development host started "
            f"(rules_trusted={status.get('rules_trusted')}, "
            f"rules_version={status.get('rules_version')}, "
            f"driver_state={status.get('driver_state')}).",
            flush=True,
        )
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            host.stop()
    else:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
            stream=sys.stderr,
        )
        main()
