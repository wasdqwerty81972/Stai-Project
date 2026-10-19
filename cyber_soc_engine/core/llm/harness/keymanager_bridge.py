"""
keymanager_bridge.py

Drop-in replacement for cyber_soc_engine's ClaudeService.
All AI calls route through key_manager.AiApi / MockRoleKeyManager.
No direct Claude/Anthropic/OpenAI SDK usage.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

# Ensure project root is importable
sys.path.insert(0, str(__file__).rsplit("core", 1)[0])

from key_manager import AiApi, MockRoleKeyManager


class KeyManagerBridge:
    """
    Bridge that mimics the old ClaudeService interface but routes through
    key_manager.py (AiApi + MockRoleKeyManager).

    Usage:
        from core.llm.harness.keymanager_bridge import KeyManagerBridge
        bridge = KeyManagerBridge()
        response = bridge.chat("You are a SOC analyst", "Analyze this alert")
    """

    def __init__(self, use_mock: bool = True):
        self.use_mock = use_mock
        self._api = AiApi(use_mock=use_mock)
        self._mock = MockRoleKeyManager()
        self.has_api_key = lambda: True  # Always "available" via key_manager

    def chat(self, system: str, user: str, model: Optional[str] = None, **kwargs) -> str:
        """
        Chat completion. Returns text string, matching old ClaudeService.chat().
        """
        if self.use_mock:
            return self._mock.generate(
                "tools",
                contents=[{"role": "user", "parts": [{"text": f"{system}\n\n{user}"}]}]
            )[0].candidates[0].content.parts[0].text

        try:
            resp = self._api.chat(system, user)
            return resp.choices[0].message.content
        except Exception as e:
            return f"[AI ERROR] {e}"

    def chat_with_role(self, role: str, system: str, user: str, **kwargs) -> str:
        """
        Role-based chat completion.
        """
        if self.use_mock:
            canned = self._mock._CANNED
            return canned.get(role, canned.get("default", "Demo mode - no response"))

        try:
            resp = self._api.chat_with_role(role, system, user)
            return resp.choices[0].message.content
        except Exception as e:
            return f"[AI ERROR] {e}"

    def chat_json(self, system: str, user: str, schema: Optional[Dict] = None, **kwargs) -> Dict[str, Any]:
        """
        JSON-mode chat. Returns dict.
        """
        text = self.chat(system, user, **kwargs)
        try:
            import json
            return json.loads(text)
        except Exception:
            return {"raw": text}

    def vision(self, system: str, user: str, image_bytes: bytes, mime_type: str = "image/png", **kwargs) -> str:
        """
        Vision/multimodal completion.
        """
        if self.use_mock:
            return "[DEMO] Vision analysis - connect OmniRoute or Gemini keys for live analysis"

        try:
            resp = self._api.chat_vision(system, user, image_bytes, mime_type=mime_type)
            return resp.choices[0].message.content
        except Exception as e:
            return f"[AI ERROR] {e}"

    def embedding(self, text: str, **kwargs) -> List[float]:
        """
        Generate embedding vector. Returns dummy vector in mock mode.
        """
        if self.use_mock:
            import random
            vec = [random.gauss(0, 1) for _ in range(768)]
            norm = sum(x ** 2 for x in vec) ** 0.5
            return [x / norm for x in vec]

        try:
            return self._api.embed(text)
        except Exception:
            import random
            vec = [random.gauss(0, 1) for _ in range(768)]
            norm = sum(x ** 2 for x in vec) ** 0.5
            return [x / norm for x in vec]


# Singleton for compatibility
_service: Optional[KeyManagerBridge] = None


def get_service(use_mock: bool = True) -> KeyManagerBridge:
    global _service
    if _service is None:
        _service = KeyManagerBridge(use_mock=use_mock)
    return _service


def ClaudeService(*args, **kwargs):
    """Drop-in replacement for core.llm.harness.claude.ClaudeService"""
    return get_service(use_mock=True)
