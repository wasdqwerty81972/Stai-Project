from unittest.mock import Mock, patch

import key_manager


def test_missing_openai_key_reports_gpt_model_fallback_reason():
    role_key_manager = Mock()
    role_key_manager.status.return_value = []

    with (
        patch.object(key_manager, "OPENAI_API_KEY", ""),
        patch.object(key_manager, "CODEX_CLI_PATH", None),
        patch.object(key_manager, "_OPENAI_AVAILABLE", True),
        patch.object(key_manager, "RoleKeyManager", return_value=role_key_manager),
    ):
        status = key_manager.AiApi().get_status()

    assert status["openai_codex_model"] == "gpt-6-luna"
    assert status["openai_codex_available"] is False
    assert "key" in status["openai_codex_unavailable_reason"].lower()
