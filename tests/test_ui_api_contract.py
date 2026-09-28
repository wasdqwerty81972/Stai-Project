"""Contract tests for the SVS chat bridge."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from ui import api_server as server
from ui.event_bus import AgentEvent, event_bus


@pytest.fixture
def isolated_history(monkeypatch, tmp_path):
    old_history = server.chat_history
    old_runs = dict(server._active_runs)
    old_loop = server._main_loop
    monkeypatch.setattr(server, "_history_path", str(tmp_path / "history.json"))
    monkeypatch.setattr(server, "_get_loop", lambda: None)
    server.chat_history = server.deque(maxlen=server.MAX_HISTORY)
    server._active_runs.clear()
    try:
        yield
    finally:
        server.chat_history = old_history
        server._active_runs.clear()
        server._active_runs.update(old_runs)
        server._main_loop = old_loop


def test_chat_response_and_history_share_one_event_id(monkeypatch, isolated_history):
    monkeypatch.setattr(server, "_run_agent_prompt_sync", lambda prompt, sid, model: "Answer")
    monkeypatch.setattr(server, "_generate_conversation_title", lambda prompt: "Investigation")

    with TestClient(server.app) as client:
        reply = client.post("/api/chat", json={"message": "Question", "session_id": "alpha", "model": "auto"})
        assert reply.status_code == 200
        payload = reply.json()
        history = client.get("/api/conversations/alpha/messages").json()

    user_rows = [row for row in history if row["type"] == "user_message"]
    response_rows = [row for row in history if row["type"] == "response"]
    assert len(user_rows) == len(response_rows) == 1
    assert payload["session_id"] == "alpha"
    assert payload["user_event_id"] == user_rows[0]["event_id"]
    assert payload["response_event_id"] == response_rows[0]["event_id"]
    assert payload["message"] == response_rows[0]["message"] == "Answer"


def test_agent_events_keep_their_session_when_another_session_is_active(monkeypatch, isolated_history):
    class Agent:
        cancel_event = threading.Event()

        def process_chat_command(self, prompt, session_id):
            event_bus.publish(AgentEvent(type="tool_started", message=prompt))
            return prompt

    monkeypatch.setattr(server, "_get_agent", lambda: Agent())
    server._run_agent_prompt_sync("first", "alpha")
    server._run_agent_prompt_sync("second", "beta")

    assert [row["message"] for row in server.get_messages("alpha")] == ["first"]
    assert [row["message"] for row in server.get_messages("beta")] == ["second"]
    assert all(row["event_id"] for row in server.get_messages("alpha") + server.get_messages("beta"))


def test_cancel_does_not_signal_shared_agent_when_sessions_overlap(monkeypatch, isolated_history):
    cancel_event = threading.Event()
    cancelled_ids = []
    runtime = SimpleNamespace(
        active_run_ids=lambda: ["investigation-alpha", "investigation-beta"],
        cancel_run=lambda run_id: cancelled_ids.append(run_id) or True,
    )
    monkeypatch.setattr(server, "_get_agent", lambda: SimpleNamespace(cancel_event=cancel_event, agent_runtime=runtime))
    server._active_runs.update({"alpha": cancel_event, "beta": cancel_event})

    result = server.agent_cancel({"session_id": "beta"})

    assert result["cancelled"] is False
    assert result["reason"] == "concurrent_runs"
    assert not cancel_event.is_set()
    assert cancelled_ids == []
    assert "alpha" in server._active_runs and "beta" in server._active_runs


def test_cancel_keeps_run_active_until_worker_exits(monkeypatch, isolated_history):
    cancel_event = threading.Event()
    monkeypatch.setattr(server, "_get_agent", lambda: SimpleNamespace(cancel_event=cancel_event))
    server._active_runs["alpha"] = cancel_event

    result = server.agent_cancel({"session_id": "alpha"})

    assert result == {"ok": True, "cancelled": True}
    assert cancel_event.is_set()
    assert server._active_runs["alpha"] is cancel_event
    assert server.get_messages("alpha")[-1]["type"] == "agent_cancelled"


def test_cancel_error_does_not_expose_exception_text(monkeypatch, isolated_history):
    class BrokenAgent:
        @property
        def agent_runtime(self):
            raise RuntimeError("private provider token")

    monkeypatch.setattr(server, "_get_agent", lambda: BrokenAgent())
    server._active_runs["alpha"] = threading.Event()

    with TestClient(server.app) as client:
        reply = client.post("/api/agent/cancel", json={"session_id": "alpha"})

    assert reply.status_code == 500
    assert reply.json() == {"ok": False, "error": "Unable to cancel run"}
    assert "private provider token" not in reply.text


def test_agent_runs_do_not_overlap_across_sessions(monkeypatch, isolated_history):
    entered_first = threading.Event()
    release_first = threading.Event()
    entered_second = threading.Event()

    class Agent:
        cancel_event = threading.Event()

        def process_chat_command(self, prompt, session_id):
            if session_id == "alpha":
                entered_first.set()
                assert release_first.wait(2)
            else:
                entered_second.set()
            return prompt

    monkeypatch.setattr(server, "_get_agent", lambda: Agent())
    first = threading.Thread(target=server._run_agent_prompt_sync, args=("first", "alpha"))
    second = threading.Thread(target=server._run_agent_prompt_sync, args=("second", "beta"))
    first.start()
    assert entered_first.wait(2)
    second.start()
    try:
        assert not entered_second.wait(0.1)
    finally:
        release_first.set()
        first.join(2)
        second.join(2)
    assert entered_second.is_set()


def test_unsupported_model_does_not_record_or_execute_prompt(monkeypatch, isolated_history):
    calls = []
    monkeypatch.setattr(server, "_run_agent_prompt_sync", lambda *args: calls.append(args))

    with TestClient(server.app) as client:
        reply = client.post("/api/chat", json={"message": "Question", "session_id": "alpha", "model": "unknown"})
        history = client.get("/api/conversations/alpha/messages").json()

    assert reply.status_code == 400
    assert history == []
    assert calls == []


def test_approval_response_is_recorded_in_requested_session(isolated_history):
    with TestClient(server.app) as client:
        reply = client.post(
            "/api/approval/request-1/respond",
            params={"approved": "true", "session_id": "alpha"},
        )
        alpha_history = client.get("/api/conversations/alpha/messages").json()
        default_history = client.get("/api/conversations/default/messages").json()

    assert reply.status_code == 200
    assert len(alpha_history) == 1
    assert alpha_history[0]["type"] == "approval_response"
    assert alpha_history[0]["session_id"] == "alpha"
    assert alpha_history[0]["data"] == {"request_id": "request-1", "approved": True}
    assert default_history == []


def test_agent_approve_uses_payload_session(monkeypatch, isolated_history):
    monkeypatch.setattr(server, "_get_agent", lambda: SimpleNamespace())

    with TestClient(server.app) as client:
        reply = client.post(
            "/api/agent/approve",
            json={"request_id": "request-2", "decision": "reject", "session_id": "beta"},
        )
        beta_history = client.get("/api/conversations/beta/messages").json()

    assert reply.status_code == 200
    assert len(beta_history) == 1
    assert beta_history[0]["type"] == "approval_response"
    assert beta_history[0]["session_id"] == "beta"
    assert beta_history[0]["data"]["approved"] is False
