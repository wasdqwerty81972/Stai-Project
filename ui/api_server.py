"""
ui/api_server.py — FastAPI server exposing CyberAgent over HTTP + WebSocket.

Wraps the existing in-process event_bus and CyberAgent so the HackerAI
web UI can connect from any browser.

Run:
    python -m uvicorn ui.api_server:app --host 127.0.0.1 --port 8000
    # then open http://localhost:3000 for HackerAI UI
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from collections import deque
from datetime import datetime
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from ui.event_bus import AgentEvent, event_bus

# ---------------------------------------------------------------------------
# Lazy agent singleton — created on first request so the server can start
# even if some dependencies are still initializing.
# ---------------------------------------------------------------------------

_agent: Any | None = None
_agent_lock = threading.Lock()
_active_runs: dict[str, threading.Event] = {}
_active_runs_lock = threading.Lock()


def _get_agent() -> Any:
    global _agent
    if _agent is None:
        with _agent_lock:
            if _agent is None:
                from cyber_agent import CyberAgent  # noqa: E402  (deferred)
                _agent = CyberAgent(workspace_path=".")
    return _agent


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="CyberAgent API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:6763",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:6763",
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory chat history (deque capped at 200 entries)
# ---------------------------------------------------------------------------

MAX_HISTORY = 200
chat_history: deque[dict[str, Any]] = deque(maxlen=MAX_HISTORY)
_history_lock = threading.Lock()
_history_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".sessions", "ui_conversations.json")


def _load_history() -> None:
    try:
        with open(_history_path, "r", encoding="utf-8") as handle:
            chat_history.extend(json.load(handle)[-MAX_HISTORY:])
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return


def _save_history() -> None:
    os.makedirs(os.path.dirname(_history_path), exist_ok=True)
    temporary_path = f"{_history_path}.tmp"
    with open(temporary_path, "w", encoding="utf-8") as handle:
        json.dump(list(chat_history)[-MAX_HISTORY:], handle, ensure_ascii=True)
    os.replace(temporary_path, _history_path)


@app.get("/health")
def health() -> dict[str, str]:
    """Lightweight readiness probe that does not initialize the agent."""
    return {"status": "ok"}


@app.get("/")
def service_info() -> dict[str, Any]:
    """Human-readable backend landing response instead of FastAPI's 404 page."""
    return {
        "service": "SVS-Cyber API",
        "status": "ok",
        "frontend": "http://127.0.0.1:6763",
        "health": "/health",
        "websocket": "/ws",
    }


@app.get("/api/health")
def api_health() -> dict[str, str]:
    """Compatibility health path for frontend and desktop probes."""
    return health()


@app.get("/api/models")
def list_models() -> list[dict[str, str]]:
    """Return only model modes the local agent can actually execute."""
    return [{
        "id": "auto",
        "label": "Automatic",
        "description": "Use SVS-Cyber's configured local provider routing",
    }]


@app.post("/api/chat")
async def chat(payload: dict[str, Any]) -> dict[str, Any]:
    """Run one user message through the real CyberAgent.

    The agent publishes application events while this request is running; the
    WebSocket remains the live channel for progress and tool activity.
    """
    messages = payload.get("messages")
    prompt = payload.get("message")
    if not isinstance(prompt, str):
        if isinstance(messages, list) and messages:
            latest = messages[-1]
            prompt = latest.get("content", "") if isinstance(latest, dict) else ""
        else:
            prompt = ""
    prompt = prompt.strip()
    if not prompt:
        return {"status": "error", "message": "A non-empty message is required"}

    session_id = payload.get("session_id") or payload.get("chatId") or "default"
    model = payload.get("model")
    had_user_message = any(
        entry.get("session_id") == session_id and entry.get("type") == "user_message"
        for entry in chat_history
    )
    user_event = AgentEvent(
        type="user_message",
        session_id=session_id,
        source="ui",
        message=prompt,
        data={"model": model} if model else {},
    )
    event_bus.publish(user_event)
    response = await asyncio.to_thread(_run_agent_prompt_sync, prompt, session_id, model)
    response_event = AgentEvent(
        type="response",
        session_id=session_id,
        source="api_server",
        message=response,
        data={"model": model} if model else {},
    )
    event_bus.publish(response_event)
    if not had_user_message:
        title = await asyncio.to_thread(_generate_conversation_title, prompt)
        event_bus.publish(AgentEvent(
            type="conversation_title",
            session_id=session_id,
            source="api_server",
            message=title,
        ))
    return {
        "status": "completed",
        "session_id": session_id,
        "message": response,
        "model": model,
        "user_event_id": user_event.event_id,
        "response_event_id": response_event.event_id,
    }


def _generate_conversation_title(prompt: str) -> str:
    """Ask the configured provider for a short investigation title."""
    try:
        agent = _get_agent()
        title = agent.orchestrator._call_role(
            "investigator",
            "Create concise titles for cybersecurity investigations.",
            f"Return only a 3-6 word title for this investigation request:\n{prompt}",
        ).strip().strip('"')
        if title and not title.startswith("[AI ERROR]"):
            return title[:80]
    except Exception:
        pass
    return "New investigation"

# ---------------------------------------------------------------------------
# WebSocket connection registry
# ---------------------------------------------------------------------------

active_connections: list[WebSocket] = []
_ws_lock = threading.Lock()
_main_loop: asyncio.AbstractEventLoop | None = None


def _set_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _main_loop
    _main_loop = loop


def _get_main_loop() -> asyncio.AbstractEventLoop:
    if _main_loop is None:
        raise RuntimeError("Main event loop has not been initialized yet.")
    return _main_loop


async def _broadcast(payload: dict[str, Any]) -> None:
    """Send a JSON payload to every connected WebSocket client."""
    data = json.dumps(payload, default=str)
    with _ws_lock:
        dead: list[WebSocket] = []
        for ws in active_connections:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            try:
                active_connections.remove(ws)
            except ValueError:
                pass


def _on_event(event: AgentEvent) -> None:
    """Global event-bus callback — persists + broadcasts every event."""
    with _history_lock:
        chat_history.append(event.to_dict())
        _save_history()
    loop = _get_loop()
    if loop is not None:
        asyncio.run_coroutine_threadsafe(_broadcast(event.to_dict()), loop)


# Subscribe once at import time so nothing is missed.
event_bus.subscribe_all(_on_event)
_load_history()

# ---------------------------------------------------------------------------
# REST — Chat history
# ---------------------------------------------------------------------------


@app.get("/api/conversations")
def list_conversations() -> list[dict[str, Any]]:
    """Return lightweight investigation metadata, never lifecycle rows as titles."""
    sessions: dict[str, dict[str, Any]] = {}
    for entry in chat_history:
        sid = entry.get("session_id") or "default"
        if sid not in sessions:
            sessions[sid] = {
                "id": sid,
                "title": "Untitled investigation",
                "last_message": "",
                "timestamp": entry.get("timestamp", ""),
            }
        if entry.get("type") == "user_message" and entry.get("message") and sessions[sid]["title"] == "Untitled investigation":
            sessions[sid]["title"] = str(entry["message"])[:80]
        if entry.get("type") == "conversation_title" and entry.get("message"):
            sessions[sid]["title"] = str(entry["message"])[:80]
        if entry.get("type") in {"user_message", "response"} and entry.get("message"):
            sessions[sid]["last_message"] = str(entry["message"])[:80]
            sessions[sid]["timestamp"] = entry.get("timestamp", "")
    return list(reversed(list(sessions.values())))


@app.get("/api/conversations/{session_id}/messages")
def get_messages(session_id: str) -> list[dict[str, Any]]:
    return [e for e in chat_history if e.get("session_id", "default") == session_id]


@app.delete("/api/conversations/{session_id}")
def clear_session(session_id: str) -> dict[str, str]:
    global chat_history
    chat_history = deque(
        (e for e in chat_history if e.get("session_id", "default") != session_id),
        maxlen=MAX_HISTORY,
    )
    with _history_lock:
        _save_history()
    return {"status": "cleared", "session_id": session_id}


@app.delete("/api/conversations")
def clear_all_conversations() -> dict[str, Any]:
    """Clear persisted task history for a local/demo workspace."""
    global chat_history
    with _history_lock:
        chat_history = deque(maxlen=MAX_HISTORY)
        _save_history()
    return {"status": "cleared", "count": 0}


# ---------------------------------------------------------------------------
# REST — Findings
# ---------------------------------------------------------------------------


def _agent_db():
    """Return the agent's investigation state store."""
    agent = _get_agent()
    # Prefer the orchestrator's store (ToolOrchestrator.investigation_state)
    orch = getattr(agent, "orchestrator", None)
    if orch is not None and hasattr(orch, "investigation_state"):
        return orch.investigation_state
    # Fall back to the agent's own investigations store
    if hasattr(agent, "investigations"):
        return agent.investigations
    if hasattr(agent, "investigation_state"):
        return agent.investigation_state
    return None


@app.get("/api/findings")
def list_findings(limit: int = 100) -> list[dict[str, Any]]:
    """Return findings across all investigations, newest first."""
    store = _agent_db()
    if store is None:
        return []
    findings: list[dict[str, Any]] = []
    for state in store.recent(limit=limit):
        for finding in state.get("findings", []) or []:
            findings.append({
                "investigation_id": state.get("investigation_id"),
                "session_id": state.get("session_id"),
                "objective": state.get("objective", ""),
                "created_at": state.get("updated_at", ""),
                **finding,
            })
    findings.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return findings[:limit]


@app.get("/api/investigations")
def list_investigations(limit: int = 50) -> list[dict[str, Any]]:
    """Return investigation summaries, newest first."""
    store = _agent_db()
    if store is None:
        return []
    return store.recent(limit=limit)


@app.get("/api/investigations/{investigation_id}")
def get_investigation(investigation_id: str) -> dict[str, Any]:
    """Return a single investigation with all its events, tool calls, and findings."""
    store = _agent_db()
    if store is None:
        return {"error": "Investigation store unavailable"}
    state = store.load(investigation_id)
    if state is None:
        return {"error": f"Investigation {investigation_id} not found"}
    return state


# ---------------------------------------------------------------------------
# REST — Tools
# ---------------------------------------------------------------------------


@app.get("/api/tools")
def list_tools() -> list[dict[str, Any]]:
    agent = _get_agent()
    return [
        {
            "name": name,
            "description": getattr(tool, "description", name),
            "risk_level": tool.risk_level.value if hasattr(tool, "risk_level") else "unknown",
            "environments": getattr(tool, "environments", []) or ["native"],
        }
        for name, tool in agent.registry.tools.items()
    ]


# ---------------------------------------------------------------------------
# REST — Workflow steps (observability)
# ---------------------------------------------------------------------------


@app.get("/api/workflow/steps")
def get_workflow_steps(limit: int = 50) -> list[dict[str, Any]]:
    history = event_bus.get_history()
    steps = [
        e.to_dict()
        for e in history
        if e.type.startswith("nat_step_") or e.type in ("tool_started", "tool_completed", "tool_failed")
    ]
    return steps[-limit:]


@app.post("/api/workflow/steps/{step_id}/toggle")
def toggle_step(step_id: str, enabled: bool) -> dict[str, Any]:
    event_bus.publish(
        AgentEvent(
            type="step_toggle",
            message=f"Step {step_id} {'enabled' if enabled else 'disabled'}",
            data={"step_id": step_id, "enabled": enabled},
        )
    )
    return {"step_id": step_id, "enabled": enabled}


# ---------------------------------------------------------------------------
# REST — Human-in-the-loop approval
# ---------------------------------------------------------------------------


@app.post("/api/approval/{request_id}/respond")
def respond_to_approval(request_id: str, approved: bool) -> dict[str, Any]:
    event_bus.publish(
        AgentEvent(
            type="approval_response",
            message=f"Approval {request_id}: {'approved' if approved else 'denied'}",
            data={"request_id": request_id, "approved": approved},
        )
    )
    return {"request_id": request_id, "approved": approved}


# ---------------------------------------------------------------------------
# REST — HackerAI-Derived Agent Control Routes
# (lib/api/agent-approval-route.ts, agent-cancel-route.ts, agent-resume-route.ts)
# ---------------------------------------------------------------------------


@app.post("/api/agent/approve")
def agent_approve(payload: dict[str, Any]) -> dict[str, Any]:
    req_id = payload.get("request_id") or payload.get("requestId", "")
    decision = payload.get("decision") or ("approve" if payload.get("approved") else "reject")
    approved = decision in ("approve", "approved", True)
    prefix_grant = payload.get("prefix_grant") or payload.get("grantRule", "")
    agent = _get_agent()
    if prefix_grant and hasattr(agent, "approval_engine"):
        agent.approval_engine.add_grant(prefix_grant)
    event_bus.publish(
        AgentEvent(
            type="approval_response",
            message=f"Approval {req_id}: {'approved' if approved else 'denied'}",
            data={"request_id": req_id, "approved": approved, "decision": decision, "grant": prefix_grant},
        )
    )
    return {"status": "ok", "request_id": req_id, "approved": approved}


@app.post("/api/agent/cancel")
def agent_cancel(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    session_id = str(payload.get("session_id") or payload.get("sessionId") or "default")
    with _active_runs_lock:
        if session_id not in _active_runs:
            return {"status": "not_found", "message": "No active run for this session"}
    agent = _get_agent()
    agent.cancel_event.set()
    event_bus.publish(
        AgentEvent(
            type="agent_cancelled",
            session_id=session_id,
            message="User requested run cancellation",
            source="api_server",
        )
    )
    return {"status": "cancelled", "session_id": session_id}


@app.post("/api/agent/resume")
def agent_resume(payload: dict[str, Any]) -> dict[str, Any]:
    prompt = payload.get("prompt") or payload.get("message", "continue")
    _run_agent_prompt(prompt)
    return {"status": "resumed", "prompt": prompt}


@app.get("/api/agent/status")
def agent_status() -> dict[str, Any]:
    agent = _get_agent()
    tasks = agent.task_manager.get_tasks() if hasattr(agent, "task_manager") else []
    notes = agent.notes_manager.list_notes() if hasattr(agent, "notes_manager") else []
    inv = agent.current_investigation
    return {
        "status": "idle" if not agent.cancel_event.is_set() else "cancelled",
        "investigation_id": inv.get("investigation_id") if inv else None,
        "tasks_count": len(tasks),
        "notes_count": len(notes),
        "tasks": tasks,
        "notes": notes,
        "active_subagents": len(agent.agent_runtime.subagent_manager.active_subagents) if hasattr(agent, "agent_runtime") else 0,
    }


@app.get("/api/tasks")
def get_tasks() -> list[dict[str, Any]]:
    agent = _get_agent()
    return agent.task_manager.get_tasks() if hasattr(agent, "task_manager") else []


@app.post("/api/tasks")
def update_tasks(payload: dict[str, Any]) -> dict[str, Any]:
    agent = _get_agent()
    tasks = payload.get("tasks", [])
    if hasattr(agent, "task_manager"):
        res = agent.task_manager.update_tasks(tasks)
        return {"status": "ok", "tasks": res}
    return {"status": "error", "message": "TaskManager unavailable"}


@app.get("/api/notes")
def get_notes(tag: str | None = None) -> list[dict[str, Any]]:
    agent = _get_agent()
    return agent.notes_manager.list_notes(tag=tag) if hasattr(agent, "notes_manager") else []


@app.post("/api/notes")
def create_note(payload: dict[str, Any]) -> dict[str, Any]:
    agent = _get_agent()
    title = payload.get("title", "Note")
    content = payload.get("content", "")
    tags = payload.get("tags", ["evidence"])
    if hasattr(agent, "notes_manager"):
        note = agent.notes_manager.create_note(title, content, tags)
        return {"status": "ok", "note": note}
    return {"status": "error", "message": "NotesManager unavailable"}


@app.get("/api/subagents")
def get_subagents() -> list[dict[str, Any]]:
    agent = _get_agent()
    if hasattr(agent, "agent_runtime") and hasattr(agent.agent_runtime, "subagent_manager"):
        mgr = agent.agent_runtime.subagent_manager
        return [r.to_dict() for r in mgr.subagent_results.values()]
    return []


# ---------------------------------------------------------------------------
# REST — Agent state snapshot
# ---------------------------------------------------------------------------


@app.get("/api/state")
def get_state() -> dict[str, Any]:
    agent = _get_agent()
    try:
        findings = agent.db_list_findings()
    except Exception:
        findings = []
    return {
        "tools": len(agent.registry.tools),
        "findings": len(findings),
        "nat": agent.nat_status(),
        "active": False,
        "wsl": getattr(agent, "wsl_available", False),
        "cyberos": getattr(agent, "cyberos_available", False),
    }


# ---------------------------------------------------------------------------
# WebSocket — real-time streaming
# ---------------------------------------------------------------------------


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    with _ws_lock:
        active_connections.append(ws)

    # Send current state immediately on connect
    try:
        await ws.send_json({"type": "state", "data": _get_state()})
    except Exception:
        pass

    try:
        while True:
            raw = await ws.receive_text()
            payload = json.loads(raw)

            if payload.get("type") == "prompt":
                _run_agent_prompt(payload.get("message", ""))
            elif payload.get("type") == "cancel":
                agent = _get_agent()
                agent.cancel_event.set()
    except WebSocketDisconnect:
        pass
    finally:
        with _ws_lock:
            try:
                active_connections.remove(ws)
            except ValueError:
                pass


def _get_state() -> dict[str, Any]:
    agent = _get_agent()
    try:
        findings = agent.db_list_findings()
    except Exception:
        findings = []
    return {
        "tools": len(agent.registry.tools),
        "findings": len(findings),
        "nat": agent.nat_status(),
        "active": False,
        "wsl": getattr(agent, "wsl_available", False),
        "cyberos": getattr(agent, "cyberos_available", False),
    }


def _run_agent_prompt(prompt: str) -> None:
    """Run agent synchronously in a background thread, stream events via WebSocket."""
    def run() -> None:
        try:
            response = _run_agent_prompt_sync(prompt, "default")
            payload = json.dumps({"type": "response", "message": response}, default=str)
        except Exception as exc:
            payload = json.dumps({"type": "error", "message": str(exc)}, default=str)

        # Schedule broadcast on the running asyncio event loop
        loop = _get_loop()
        if loop is not None:
            asyncio.run_coroutine_threadsafe(_broadcast(json.loads(payload)), loop)
        else:
            # Fallback: broadcast synchronously to all active connections
            for ws in list(active_connections):
                try:
                    ws.send_text(payload)
                except Exception:
                    pass

    threading.Thread(target=run, daemon=True).start()


def _run_agent_prompt_sync(prompt: str, session_id: str, model: str | None = None) -> str:
    """Execute one prompt and attach the session to newly emitted events."""
    agent = _get_agent()
    # The orchestrator owns provider routing.  Avoid mutating undeclared
    # attributes and never pretend that the UI chose a provider.
    if model and model != "auto":
        raise ValueError("This SVS-Cyber backend only supports automatic model routing")
    with _active_runs_lock:
        _active_runs[session_id] = agent.cancel_event
    try:
        with event_bus.session_scope(session_id):
            return str(agent.process_chat_command(prompt, session_id=session_id))
    finally:
        with _active_runs_lock:
            _active_runs.pop(session_id, None)


def _get_loop() -> Any:
    """Return the stored main asyncio event loop, or None."""
    try:
        return _get_main_loop()
    except RuntimeError:
        return None


@app.on_event("startup")
def _capture_main_loop() -> None:
    _set_main_loop(asyncio.get_event_loop())
