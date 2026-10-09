"""Regression coverage for Gemini key failover in role-based chat."""

from types import SimpleNamespace

from key_manager import AiApi


class TemporaryProviderError(Exception):
    code = 503


class _FailingModels:
    def generate_content(self, **_kwargs):
        raise TemporaryProviderError("503 UNAVAILABLE")


class _WorkingModels:
    def generate_content(self, **_kwargs):
        return SimpleNamespace(
            candidates=[
                SimpleNamespace(
                    content=SimpleNamespace(
                        parts=[SimpleNamespace(text="Recovered using the next Gemini key.")]
                    )
                )
            ]
        )


class _KeyPool:
    def __init__(self):
        self.calls = []

    def client_for_role(self, index):
        self.calls.append(index)
        client = (
            SimpleNamespace(models=_FailingModels())
            if index == 0
            else SimpleNamespace(models=_WorkingModels())
        )
        return client, f"gemini-key-{index + 1}"

    def status(self):
        return [
            {"label": "gemini-key-1", "mode": "fallback"},
            {"label": "gemini-key-2", "mode": "fallback"},
        ]


def test_role_chat_tries_next_gemini_key_after_temporary_provider_error():
    api = AiApi.__new__(AiApi)
    api._km = _KeyPool()
    # __init__ is bypassed here to avoid building a real RoleKeyManager, so
    # restore the one attribute chat_with_role reads that it would have set.
    api.model_override = None

    response = api.chat_with_role("investigator", "System", "Investigate this")

    assert response.choices[0].message.content == "Recovered using the next Gemini key."
    assert api._km.calls == [0, 1]
