import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import key_manager
from key_manager import AiApi


class _KeyPool:
    def __init__(self):
        self.calls = []

    def client_for_role(self, index):
        self.calls.append(index)
        model = SimpleNamespace(generate_content=lambda **_kwargs: SimpleNamespace(
            candidates=[SimpleNamespace(content=SimpleNamespace(
                parts=[SimpleNamespace(text="Gemini fallback response")]
            ))]
        ))
        return SimpleNamespace(models=model), f"gemini-key-{index + 1}"

    def status(self):
        return [{"label": "gemini-key-1", "available": True}]


def _api() -> AiApi:
    api = AiApi.__new__(AiApi)
    api._codex_cli_path = r"C:\Codex\codex.cmd"
    api._codex_cli_authenticated = True
    api._codex_cli_model = "gpt-6-luna"
    api._codex_model = "gpt-6-luna"
    api._codex_reasoning_effort = "medium"
    api._codex_client = None
    api._km = _KeyPool()
    api.model_override = None
    api.reasoning_level_override = None
    return api


def _codex_events(text: str) -> str:
    return "\n".join(
        (
            json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": text}}),
            json.dumps({"type": "turn.completed", "usage": {"output_tokens": 5}}),
        )
    )


def test_role_chat_uses_authenticated_codex_cli_before_gemini():
    api = _api()

    def fail_openai(**_kwargs):
        raise AssertionError("OpenAI API must not be called when Codex CLI is authenticated")

    api._codex_client = SimpleNamespace(
        responses=SimpleNamespace(create=fail_openai)
    )

    with patch(
        "key_manager.subprocess.run",
        return_value=SimpleNamespace(returncode=0, stdout=_codex_events("Codex response"), stderr=""),
    ) as run:
        response = api.chat_with_role("investigator", "System prompt", "Question")

    command = run.call_args.args[0]
    assert response.choices[0].message.content == "Codex response"
    assert response.model == "gpt-6-luna"
    assert command[1:3] == ["exec", "--json"]
    assert command[command.index("--model") + 1] == "gpt-6-luna"
    disabled_options = list(zip(command, command[1:]))
    for feature in ("shell_tool", "unified_exec", "unified_exec_tty", "shell_snapshot"):
        assert ("--disable", feature) in disabled_options
    assert run.call_args.kwargs["input"].endswith("Question")
    assert run.call_args.kwargs["timeout"] > 0
    assert api._km.calls == []


def test_unauthenticated_codex_cli_is_skipped_for_direct_openai():
    api = _api()
    api._codex_cli_authenticated = False
    api._codex_client = SimpleNamespace(
        responses=SimpleNamespace(
            create=lambda **_kwargs: SimpleNamespace(output_text="Direct OpenAI response")
        )
    )

    with patch("key_manager.subprocess.run") as run:
        response = api.chat_with_role("investigator", "System", "Question")

    assert response.choices[0].message.content == "Direct OpenAI response"
    run.assert_not_called()
    assert api._km.calls == []


def test_codex_cli_tool_decision_is_validated_and_returned_for_host_dispatch():
    tool = {
        "type": "function",
        "name": "network_inspect",
        "description": "Inspect local network connections.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": True},
    }
    decision = {
        "action_type": "tool",
        "tool_name": "network_inspect",
        "arguments": {"target": "localhost"},
        "response": "",
    }
    api = _api()

    def run_codex(command, **kwargs):
        assert "--output-schema" not in command
        assert '"action_type":"tool"' in kwargs["input"]
        return SimpleNamespace(returncode=0, stdout=_codex_events(json.dumps(decision)), stderr="")

    with patch("key_manager.subprocess.run", side_effect=run_codex):
        response = api.chat_with_role("investigator", "System", "Inspect localhost", tools=[tool])

    assert json.loads(response.choices[0].message.content) == {
        "action_type": "tool",
        "tool_name": "network_inspect",
        "arguments": {"target": "localhost"},
    }
    assert api._km.calls == []


def test_codex_cli_failure_falls_back_to_gemini_without_hiding_failure():
    api = _api()
    with patch(
        "key_manager.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="codex", timeout=120),
    ):
        response = api.chat_with_role("investigator", "System", "Question")

    assert response.choices[0].message.content == "Gemini fallback response"
    assert api._km.calls == [0]


def test_codex_cli_and_direct_openai_failures_reach_gemini_fallback():
    api = _api()
    direct_calls = []

    def fail_direct(**_kwargs):
        direct_calls.append(True)
        raise RuntimeError("OpenAI unavailable")

    api._codex_client = SimpleNamespace(responses=SimpleNamespace(create=fail_direct))
    with patch(
        "key_manager.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="codex", timeout=120),
    ):
        response = api.chat_with_role("investigator", "System", "Question")

    assert direct_calls == [True]
    assert response.choices[0].message.content == "Gemini fallback response"
    assert api._km.calls == [0]


def test_vision_chat_uses_codex_cli_image_input():
    api = _api()
    image_data = b"test image bytes"

    def run_codex(command, **kwargs):
        image_path = command[command.index("--image") + 1]
        assert Path(image_path).read_bytes() == image_data
        assert kwargs["input"].endswith("Describe this image")
        return SimpleNamespace(
            returncode=0,
            stdout=_codex_events("Image description"),
            stderr="",
        )

    with patch("key_manager.subprocess.run", side_effect=run_codex):
        response = api.chat_vision(
            "Describe the image.",
            "Describe this image",
            image_data,
            mime_type="image/png",
        )

    assert response.choices[0].message.content == "Image description"
    assert response.model == "gpt-6-luna"
    assert api._km.calls == []


def test_status_prefers_authenticated_codex_cli_without_api_key():
    role_key_manager = Mock()
    role_key_manager.status.return_value = []

    with (
        patch.object(key_manager, "CODEX_CLI_PATH", r"C:\Codex\codex.cmd"),
        patch.object(key_manager, "OPENAI_API_KEY", ""),
        patch.object(key_manager, "RoleKeyManager", return_value=role_key_manager),
        patch(
            "key_manager.subprocess.run",
            return_value=SimpleNamespace(
                returncode=0, stdout="Logged in using ChatGPT", stderr=""
            ),
        ),
    ):
        status = AiApi().get_status()

    assert status["codex_cli_authenticated"] is True
    assert status["codex_cli_model"] == "gpt-6-luna"
    assert status["mode"] == "codex_cli"
