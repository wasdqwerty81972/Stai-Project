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

class _StreamingModels:
    def __init__(self):
        self.configs = []

    def generate_content_stream(self, **kwargs):
        self.configs.append(kwargs["config"])
        return iter([
            SimpleNamespace(text="partial "),
            SimpleNamespace(text="answer"),
        ])


def test_role_chat_applies_thinking_level_and_streams_deltas():
    from key_manager import _genai_types

    class Config:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class ThinkingConfig:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    original_available = __import__("key_manager")._GENAI_AVAILABLE
    original_types = _genai_types
    import key_manager
    key_manager._GENAI_AVAILABLE = True
    key_manager._genai_types = SimpleNamespace(GenerateContentConfig=Config, ThinkingConfig=ThinkingConfig)
    try:
        api = AiApi.__new__(AiApi)
        models = _StreamingModels()
        api._km = SimpleNamespace(client_for_role=lambda _index: (SimpleNamespace(models=models), "gemini-key-1"), status=lambda: [])
        api.model_override = "gemini-3.1-pro-preview"
        api.reasoning_level_override = "high"
        deltas = []

        response = api.chat_with_role("investigator", "System", "Investigate", on_delta=deltas.append)

        assert response.choices[0].message.content == "partial answer"
        assert deltas == ["partial ", "answer"]
        assert models.configs[0].thinking_config.thinking_level == "HIGH"

        api.reasoning_level_override = "medium"
        api.chat_with_role("investigator", "System", "Emergency", on_delta=deltas.append)
        assert models.configs[1].thinking_config.thinking_level == "MEDIUM"
    finally:
        key_manager._GENAI_AVAILABLE = original_available
        key_manager._genai_types = original_types


def test_cybersecurity_orchestrator_streams_only_when_response_callsite_requests_it():
    from cyber_agent import CyberSecurityOrchestrator

    class Api:
        def __init__(self):
            self.callbacks = []

        def chat_with_role(self, role, system, user, **kwargs):
            self.callbacks.append(kwargs.get("on_delta"))
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="answer"))])

    orchestrator = CyberSecurityOrchestrator.__new__(CyberSecurityOrchestrator)
    orchestrator.use_mock = False
    orchestrator.response_delta_callback = lambda _delta: None
    orchestrator._api = Api()

    orchestrator._call_role("investigator", "system", "internal")
    orchestrator._call_role("investigator", "system", "final", stream_response=True)

    assert orchestrator._api.callbacks == [None, orchestrator.response_delta_callback]


def test_role_chat_does_not_fail_over_after_partial_stream_output():
    class PartialFailureModels:
        def generate_content_stream(self, **_kwargs):
            yield SimpleNamespace(text="partial")
            raise TemporaryProviderError("503 after partial output")

    class NeverReachedModels(_WorkingModels):
        def generate_content_stream(self, **_kwargs):
            return iter([SimpleNamespace(text="second answer")])

    pool = _KeyPool()
    requested = []
    def select_client(index):
        requested.append(index)
        return (
            SimpleNamespace(models=PartialFailureModels() if index == 0 else NeverReachedModels()),
            f"gemini-key-{index + 1}",
        )
    pool.client_for_role = select_client
    api = AiApi.__new__(AiApi)
    api._km = pool
    api.model_override = None
    api.reasoning_level_override = None
    deltas = []

    try:
        api.chat_with_role("investigator", "System", "Question", on_delta=deltas.append)
    except RuntimeError as exc:
        assert "partial output" in str(exc)
    else:
        raise AssertionError("A partial streamed response must not be silently retried")

    assert deltas == ["partial"]
    assert requested == [0]
