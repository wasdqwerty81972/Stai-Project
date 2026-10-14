"""Make one live request through AiApi's authenticated Codex CLI route."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from key_manager import AiApi


EXPECTED_MODEL = "gpt-6-luna"


def main() -> int:
    api = AiApi()
    status = api.get_status()
    configured_model = status.get("codex_cli_model")
    print(f"Configured model: {configured_model}")

    if configured_model != EXPECTED_MODEL:
        print(f"FAIL: Expected CODEX_CLI_MODEL to be {EXPECTED_MODEL!r}.")
        return 1
    if not status.get("codex_cli_authenticated"):
        reason = status.get("codex_cli_unavailable_reason") or "Codex CLI is not authenticated."
        print(f"FAIL: {reason}")
        return 1

    try:
        response = api.chat_with_role(
            "coder",
            "You are running a model connectivity check. Follow the user's instruction exactly.",
            "Reply with exactly: GPT-6 Luna connection OK",
        )
    except Exception as error:
        print(f"FAIL: Codex CLI model request failed ({type(error).__name__}).")
        return 1

    reply = response.choices[0].message.content.strip()
    print(f"Model selected by AiApi: {response.model}")
    print(f"Response received: {bool(reply)}")
    if not reply or response.model != EXPECTED_MODEL or "GPT-6 Luna connection OK" not in reply:
        print("FAIL: AiApi did not return the expected GPT-6 Luna response.")
        return 1

    print("PASS: AiApi routed the live request through the authenticated Codex CLI.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
