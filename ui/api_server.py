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
import inspect
import ipaddress
import json
import os
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from ui.event_bus import AgentEvent, event_bus

# Protection service imports (lazy-loaded)
_protection_service: Any | None = None
_protection_service_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Lazy agent singleton — created on first request so the server can start
# even if some dependencies are still initializing.
# ---------------------------------------------------------------------------

_agent: Any | None = None
_agent_lock = threading.Lock()
_active_runs: dict[str, threading.Event] = {}
_active_runs_lock = threading.Lock()
_agent_run_lock = threading.Lock()


def _get_agent() -> Any:
    global _agent
    if _agent is None:
        with _agent_lock:
            if _agent is None:
                from cyber_agent import CyberAgent  # noqa: E402  (deferred)
                _agent = CyberAgent(workspace_path=".")
    return _agent


def _get_protection_service() -> Any:
    """Lazy-initialize the protection service singleton."""
    global _protection_service
    if _protection_service is None:
        with _protection_service_lock:
            if _protection_service is None:
                try:
                    from cyber_os.protection import (
                        ProtectionConfig,
                        ProtectionService,
                        ProtectionStore,
                        RulePackage,
                        RuleSet,
                    )
                    from pathlib import Path
                    import tempfile

                    # Create/store directory
                    data_dir = Path(os.path.dirname(os.path.dirname(__file__))) / ".protection"
                    data_dir.mkdir(parents=True, exist_ok=True)

                    # Load or create rule package
                    rules: RuleSet
                    manifest_path = data_dir / "manifest.json"
                    sig_path = data_dir / "manifest.sig"
                    pubkey_path = data_dir / "public.key"

                    if manifest_path.exists() and sig_path.exists() and pubkey_path.exists():
                        public_key = pubkey_path.read_bytes()
                        rules = RulePackage.load(manifest_path, sig_path, public_key)
                    else:
                        # Empty rule set for development
                        rules = RuleSet(version="dev-empty", rules=())

                    store = ProtectionStore(data_dir / "protection.db")
                    quarantine_root = data_dir / "quarantine"

                    config = ProtectionConfig(
                        quarantine_root=quarantine_root,
                        rules=rules,
                        store=store,
                        yara_timeout_seconds=5,
                    )
                    _protection_service = ProtectionService(config)
                except Exception as e:
                    # Return a mock service that reports unavailable. Capture the
                    # error text now: the ``except`` name ``e`` is cleared when this
                    # block exits, so the nested methods (invoked later) must not
                    # close over ``e`` directly or they raise NameError.
                    err_text = str(e)

                    class _UnavailableService:
                        @property
                        def store(self):
                            # Store-scoped routes (threats, scan-job lookup) call
                            # ``service.store.<method>``; expose the same object so
                            # the unavailable path returns honest empty/None results
                            # instead of raising AttributeError (HTTP 500).
                            return self
                        def get_status(self, **kwargs):
                            from types import SimpleNamespace
                            return SimpleNamespace(
                                state="unavailable",
                                driver_state="unknown",
                                service_state="error",
                                rules_version="unknown",
                                last_scan=None,
                                counts={"detected": 0, "blocked": 0, "quarantined": 0},
                                windows_security={"registered_av_provider": None, "defender_mode": None, "query_available": False},
                                sensor_coverage={},
                                last_error=err_text,
                            )
                        def list_threats(self, limit=100):
                            return []
                        def create_scan_job(self, job_id, scope):
                            from types import SimpleNamespace
                            return SimpleNamespace(job_id=job_id, scope=scope, state="failed", files_scanned=0, files_total=0, detections=0, errors=0, started_at=datetime.now().isoformat(), completed_at=datetime.now().isoformat(), error_message=err_text)
                        def update_scan_job(self, *args, **kwargs):
                            return False
                        def get_scan_job(self, job_id):
                            return None
                        def scan_file(self, path):
                            from types import SimpleNamespace
                            return SimpleNamespace(status="unknown", action="allow", rule_id=None, rule_version="unknown", sha256=None, reason=f"service unavailable: {err_text}")
                        def start_scan(self, scope):
                            return self.create_scan_job("failed", scope)
                        def cancel_scan(self, job_id):
                            return False
                        def quarantine_detection(self, detection_id):
                            from types import SimpleNamespace
                            return SimpleNamespace(success=False, item=None, error=f"service unavailable: {err_text}")
                        def restore_quarantine(self, item_id):
                            from types import SimpleNamespace
                            return SimpleNamespace(success=False, item=None, error=f"service unavailable: {err_text}")
                        def list_quarantine(self):
                            return []
                    _protection_service = _UnavailableService()

    return _protection_service


def _session_conversation_history(session_id: str) -> list[dict[str, str]]:
    """Return bounded user/assistant turns for one investigation only."""
    turns: list[dict[str, str]] = []
    for event in chat_history:
        if event.get("session_id") != session_id or event.get("type") not in {"user_message", "response"}:
            continue
        message = str(event.get("message") or "").strip()
        if message:
            turns.append({"role": "user" if event["type"] == "user_message" else "assistant", "content": message[:1200]})
    return turns[-12:]


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="CyberAgent API")

COMMUNICATIONS_ALLOWED_ORIGINS = {
    "http://localhost:3000",
    "http://localhost:6763",
    "http://localhost:8080",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:6763",
    "http://127.0.0.1:8080",
}

SUPPORTED_CHAT_MODELS = {
    "auto",
    "gemini-3.1-flash-lite",
    "gemini-3.1-pro-preview",
    "gemini-3.8-flash",
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(COMMUNICATIONS_ALLOWED_ORIGINS),
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
    """Return Gemini-only models that the local agent can execute."""
    return [
        {"id": "auto", "label": "Automatic", "description": "Use SVS-Cyber's default Gemini routing"},
        {"id": "gemini-3.1-flash-lite", "label": "Gemini 3.1 Flash-Lite", "description": "Fast, efficient investigations"},
        {"id": "gemini-3.1-pro-preview", "label": "Gemini 3.1 Pro", "description": "Advanced reasoning for complex investigations"},
        {"id": "gemini-3.8-flash", "label": "Gemini 3.8 Flash", "description": "Latest fast Gemini model"},
    ]


@app.get("/api/commands")
def list_commands() -> list[dict[str, str]]:
    """Expose composer-safe slash-command metadata without prompt bodies."""
    # Import on demand: importing cyber_os eagerly initializes its full agent
    # stack, which should not delay the lightweight API health check.
    from cyber_os.assets import get_command_registry

    return [
        {
            "name": str(command["name"]),
            "description": str(command["description"]),
            "argument_hint": str(command.get("argument_hint") or ""),
        }
        for command in get_command_registry().index()
    ]


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
    if model and model not in SUPPORTED_CHAT_MODELS:
        raise HTTPException(status_code=400, detail="Unsupported Gemini model")
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


@app.get("/api/reports/web-assessments/{report_id}.pdf")
def download_web_assessment_report(report_id: str, request: Request) -> FileResponse:
    """Serve one generated assessment PDF to the local desktop client only."""
    if not _is_loopback_request(request):
        raise HTTPException(status_code=403, detail="Report downloads are local-only")

    from cyber_os.web_assessment_report import get_web_assessment_report_path

    try:
        report_path = get_web_assessment_report_path(report_id)
    except (FileNotFoundError, ValueError):
        raise HTTPException(status_code=404, detail="Web assessment report not found") from None

    return FileResponse(
        path=report_path,
        media_type="application/pdf",
        filename=f"web-assessment-{report_id}.pdf",
        headers={"Cache-Control": "private, no-store"},
    )


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
    # Snapshot under the lock: iterating a deque that ``_on_event`` appends to
    # concurrently raises RuntimeError mid-response.
    with _history_lock:
        entries = list(chat_history)
    sessions: dict[str, dict[str, Any]] = {}
    for entry in entries:
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
    with _history_lock:
        return [e for e in list(chat_history) if e.get("session_id", "default") == session_id]


@app.delete("/api/conversations/{session_id}")
def clear_session(session_id: str) -> dict[str, str]:
    global chat_history
    # Rebuilt under the lock. Filtering outside it raced with ``_on_event``,
    # which appends to the deque it is about to replace, so a clear could
    # resurrect events published during the call.
    with _history_lock:
        chat_history = deque(
            (e for e in chat_history if e.get("session_id", "default") != session_id),
            maxlen=MAX_HISTORY,
        )
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


def _resolve_sensor_response_approval(
    request_id: str,
    approved: bool,
    approved_by: str,
    request: Request | None = None,
) -> list[str] | None:
    """Route CyberOS containment approvals to the engine that owns them.

    ``None`` means this is a regular agent approval. A response-prefixed ID is
    never allowed to fall through to the unrelated CyberAgent approval map.
    """
    if not request_id.startswith("response-"):
        return None
    if request is None:
        raise HTTPException(status_code=403, detail="Containment approval requires the local SVS-Cyber UI")
    _require_loopback(request)
    agent = _get_agent()
    engine = getattr(agent, "cyberos_engine", None)
    if engine is None or not hasattr(engine, "has_pending_response_approval"):
        raise HTTPException(status_code=503, detail="CyberOS response approval service unavailable")
    if not engine.has_pending_response_approval(request_id):
        raise HTTPException(status_code=404, detail="Response approval is expired or unknown")
    return engine.resolve_response_approval(request_id, approved, approved_by=approved_by)


@app.post("/api/approval/{request_id}/respond")
def respond_to_approval(
    request: Request,
    request_id: str,
    approved: bool,
    session_id: str = "default",
    approved_by: str = "local_user",
) -> dict[str, Any]:
    actions = _resolve_sensor_response_approval(
        request_id,
        approved,
        approved_by or session_id or "local_user",
        request=request,
    )
    response_data: dict[str, Any] = {"request_id": request_id, "approved": approved}
    if actions is not None:
        response_data["actions"] = actions
    event_bus.publish(
        AgentEvent(
            type="approval_response",
            session_id=session_id,
            message=f"Approval {request_id}: {'approved' if approved else 'denied'}",
            data=response_data,
        )
    )
    return response_data


# ---------------------------------------------------------------------------
# REST — HackerAI-Derived Agent Control Routes
# (lib/api/agent-approval-route.ts, agent-cancel-route.ts, agent-resume-route.ts)
# ---------------------------------------------------------------------------


def agent_approve(payload: dict[str, Any], request: Request | None = None) -> dict[str, Any]:
    req_id = payload.get("request_id") or payload.get("requestId", "")
    session_id = str(payload.get("session_id") or payload.get("sessionId") or "default")
    decision = payload.get("decision") or ("approve" if payload.get("approved") else "reject")
    approved = decision in ("approve", "approved", True)
    prefix_grant = payload.get("prefix_grant") or payload.get("grantRule", "")
    agent = _get_agent()
    actions = _resolve_sensor_response_approval(
        str(req_id),
        approved,
        str(payload.get("approved_by") or payload.get("approvedBy") or session_id or "local_user"),
        request=request,
    )
    if prefix_grant and hasattr(agent, "approval_engine"):
        agent.approval_engine.add_grant(prefix_grant)
    response_data = {"request_id": req_id, "approved": approved, "decision": decision, "grant": prefix_grant}
    if actions is not None:
        response_data["actions"] = actions
    event_bus.publish(
        AgentEvent(
            type="approval_response",
            session_id=session_id,
            message=f"Approval {req_id}: {'approved' if approved else 'denied'}",
            data=response_data,
        )
    )
    return {"status": "ok", **response_data}


@app.post("/api/agent/approve")
def agent_approve_route(request: Request, payload: dict[str, Any]) -> dict[str, Any]:
    return agent_approve(payload, request=request)


@app.post("/api/agent/cancel")
def agent_cancel(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Cancel an active agent run for the given session.

    Returns:
        { ok: true, cancelled: true } — run was found and cancellation was signalled
        { ok: true, cancelled: false, reason: "no_active_run" } — nothing was running
    HTTP 500 with a generic error on unexpected exceptions.
    """
    try:
        payload = payload or {}
        session_id = str(payload.get("session_id") or payload.get("sessionId") or "default")

        with _active_runs_lock:
            if session_id not in _active_runs:
                return {"ok": True, "cancelled": False, "reason": "no_active_run"}
            if len(_active_runs) > 1:
                return {"ok": True, "cancelled": False, "reason": "concurrent_runs"}

            # Hold the registry lock until signalling finishes. The worker's
            # finally block owns removal; it cannot exit and hand off to a
            # different session while this request targets its agent state.
            cancelled = False
            agent = _get_agent()
            if hasattr(agent, "agent_runtime") and hasattr(agent.agent_runtime, "cancel_run"):
                for inv_id in list(agent.agent_runtime.active_run_ids()):
                    try:
                        if agent.agent_runtime.cancel_run(inv_id):
                            cancelled = True
                    except Exception:
                        pass
            if hasattr(agent, "cancel_event"):
                try:
                    agent.cancel_event.set()
                    cancelled = True
                except Exception:
                    pass

        if cancelled:
            event_bus.publish(
                AgentEvent(
                    type="agent_cancelled",
                    session_id=session_id,
                    message="User requested run cancellation",
                    source="api_server",
                )
            )
            return {"ok": True, "cancelled": True}
        return {"ok": True, "cancelled": False, "reason": "cancel_unavailable"}
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": "Unable to cancel run"},
        )


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


def _get_sensor_service() -> Any:
    """Return the CyberOS Windows sensor service without exposing raw events."""
    agent = _get_agent()
    engine = getattr(agent, "cyberos_engine", None)
    service = getattr(engine, "sensor_service", None)
    if service is None:
        raise HTTPException(status_code=503, detail="Sensor service unavailable")
    return service


def _sensor_status_with_registry(service: Any) -> dict[str, Any]:
    from cyber_os.sensors.sensor_registry import REGISTRY_VERSION, build_runtime_registry

    status = service.get_status()
    status["registry_version"] = REGISTRY_VERSION
    status["registry"] = build_runtime_registry(
        str(status.get("platform") or "unknown"),
        status.get("capabilities") or (),
    )
    engine = getattr(_get_agent(), "cyberos_engine", None)
    pending_approvals = getattr(engine, "get_pending_response_approvals", None)
    status["pending_approvals"] = pending_approvals() if callable(pending_approvals) else []
    return status


@app.get("/api/sensors/status")
def sensor_status() -> dict[str, Any]:
    """Report Phase 1 runtime health and the complete logical sensor registry."""
    return _sensor_status_with_registry(_get_sensor_service())


@app.post("/api/sensors/start")
def start_sensor_monitoring() -> dict[str, Any]:
    """Start passive telemetry collection through CyberOS's managed lifecycle."""
    agent = _get_agent()
    if not getattr(agent, "cyberos_available", False):
        raise HTTPException(status_code=503, detail="CyberOS is unavailable")
    agent.cyberos_start()
    return _sensor_status_with_registry(_get_sensor_service())


@app.post("/api/sensors/stop")
def stop_sensor_monitoring() -> dict[str, Any]:
    """Stop sensor collection and wait for its managed workers to close."""
    agent = _get_agent()
    if not getattr(agent, "cyberos_available", False):
        raise HTTPException(status_code=503, detail="CyberOS is unavailable")
    agent.cyberos_stop()
    return _sensor_status_with_registry(_get_sensor_service())


@app.on_event("shutdown")
async def _stop_cyberos_sensors_on_shutdown() -> None:
    """Close active sensor and engine workers during API shutdown."""
    agent = _agent
    stop = getattr(agent, "cyberos_stop", None) if agent is not None else None
    if not callable(stop):
        return
    engine = getattr(agent, "cyberos_engine", None)
    active = bool(getattr(engine, "running", False))
    service = getattr(engine, "sensor_service", None)
    if not active and service is not None:
        try:
            active = bool(service.get_status().get("running"))
        except Exception:
            active = False
    if active:
        await asyncio.to_thread(stop)


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

    # Send current state immediately on connect. Shaped as a full AgentEvent:
    # the client filters and renders every frame through the same reducer, and a
    # bare {"type","data"} dict left event.session_id undefined, so the frame
    # was dropped by the session check rather than applied.
    try:
        await ws.send_json(
            AgentEvent(
                type="state",
                status="ok",
                message="Backend state",
                source="api_server",
                data=_get_state(),
            ).to_dict()
        )
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
    if model and model not in SUPPORTED_CHAT_MODELS:
        raise ValueError("Unsupported Gemini model")
    # CyberAgent keeps cancellation and investigation state on one singleton.
    # Serialize runs so one session cannot clear or signal another run's state.
    with _agent_run_lock:
        agent = _get_agent()
        provider = getattr(getattr(agent, "orchestrator", None), "_api", None)
        previous_model = getattr(provider, "model_override", None)
        if provider is not None:
            provider.model_override = None if model in (None, "auto") else model
        with _active_runs_lock:
            _active_runs[session_id] = agent.cancel_event
        try:
            with event_bus.session_scope(session_id):
                history = _session_conversation_history(session_id)
                if "conversation_history" in inspect.signature(agent.process_chat_command).parameters:
                    return str(agent.process_chat_command(prompt, session_id=session_id, conversation_history=history))
                return str(agent.process_chat_command(prompt, session_id=session_id))
        finally:
            if provider is not None:
                provider.model_override = previous_model
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


def _is_loopback_request(request: Request) -> bool:
    host = request.client.host if request.client else ""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _require_loopback(request: Request) -> None:
    if not _is_loopback_request(request):
        raise HTTPException(status_code=403, detail="Communications administration is local-only")
    origin = request.headers.get("origin")
    if origin not in COMMUNICATIONS_ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="Communications administration requires the local SVS-Cyber UI")


def _remote_chat(message: str, session_id: str, channel: str) -> str:
    """Use the same CyberAgent path as /api/chat, with remote-origin events."""
    event_bus.publish(AgentEvent(
        type="user_message", session_id=session_id, source=f"messaging:{channel}", message=message,
    ))
    try:
        response = _run_agent_prompt_sync(message, session_id)
    except Exception as exc:
        event_bus.publish(AgentEvent(
            type="agent_error", session_id=session_id, source=f"messaging:{channel}",
            status="failed", message="Remote agent request failed", data={"error_type": type(exc).__name__},
        ))
        raise
    event_bus.publish(AgentEvent(
        type="response", session_id=session_id, source=f"messaging:{channel}", message=response,
    ))
    return response


class _LocalMessagingChatClient:
    def chat(self, message: str, session_id: str) -> str:
        # The gateway already runs this blocking call in asyncio.to_thread.
        return _remote_chat(message, session_id, "external")


_communications_event_listener = None


@app.on_event("startup")
async def _start_communications_gateway() -> None:
    global _communications_event_listener
    from stai_messaging.service import AdapterManager, set_manager

    manager = AdapterManager(_LocalMessagingChatClient(), os.path.join(os.path.dirname(os.path.dirname(__file__)), ".sessions"))
    set_manager(manager)
    _communications_event_listener = manager.enqueue_event
    event_bus.subscribe_all(_communications_event_listener)
    # Optional connectors initialize in the background so unavailable platform
    # services never delay the local agent API from becoming ready.
    app.state.communications_manager = manager
    app.state.communications_start_task = asyncio.create_task(manager.start(), name="svs-communications-start")


@app.on_event("shutdown")
async def _stop_communications_gateway() -> None:
    from stai_messaging.service import get_manager, set_manager

    manager = get_manager()
    if _communications_event_listener is not None:
        event_bus.unsubscribe_all(_communications_event_listener)
    startup_task = getattr(app.state, "communications_start_task", None)
    if startup_task is not None and not startup_task.done():
        startup_task.cancel()
        try:
            await startup_task
        except asyncio.CancelledError:
            pass
    if manager is not None:
        await manager.stop()
    set_manager(None)


def _get_communications_manager(request: Request):
    _require_loopback(request)
    from stai_messaging.service import get_manager

    manager = get_manager()
    if manager is None:
        raise HTTPException(status_code=503, detail="Communications service is not initialized")
    return manager


@app.get("/api/communications/status")
def communications_status(request: Request) -> dict[str, Any]:
    return _get_communications_manager(request).status()


@app.put("/api/communications/settings")
async def communications_settings(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    manager = _get_communications_manager(request)
    enabled = payload.get("enabled", {})
    if not isinstance(enabled, dict) or any(not isinstance(value, bool) for value in enabled.values()):
        raise HTTPException(status_code=400, detail="enabled must map platform names to booleans")
    try:
        return await manager.set_enabled(enabled)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.put("/api/communications/notifications")
def communications_notifications(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    manager = _get_communications_manager(request)
    try:
        return manager.configure_notifications(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/communications/credentials/{platform}/{account_id}")
async def communications_set_credential(platform: str, account_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
    manager = _get_communications_manager(request)
    token = payload.get("token")
    if not isinstance(token, str) or not token.strip():
        raise HTTPException(status_code=400, detail="token is required")
    try:
        await manager.set_credential(platform, account_id, token)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"status": "saved", "platform": platform, "account_id": account_id}


@app.delete("/api/communications/credentials/{platform}/{account_id}")
async def communications_delete_credential(platform: str, account_id: str, request: Request) -> dict[str, Any]:
    manager = _get_communications_manager(request)
    try:
        await manager.delete_credential(platform, account_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"status": "deleted", "platform": platform, "account_id": account_id}


@app.get("/api/communications/pairing-requests")
def communications_pairing_requests(request: Request) -> list[dict[str, Any]]:
    return _get_communications_manager(request).identities.pending_requests()


@app.get("/api/communications/pairings")
def communications_pairings(request: Request) -> list[dict[str, Any]]:
    return _get_communications_manager(request).paired_destinations()


@app.post("/api/communications/pairing-requests/{request_id}/approve")
def communications_approve_pairing(request_id: str, payload: dict[str, Any], request: Request) -> dict[str, Any]:
    manager = _get_communications_manager(request)
    role = payload.get("role", "viewer")
    if not isinstance(role, str):
        raise HTTPException(status_code=400, detail="role must be a string")
    try:
        approved = manager.identities.approve_pairing(request_id, role=role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not approved:
        raise HTTPException(status_code=404, detail="Pairing request expired or no longer exists")
    return {"status": "approved", "role": role}


@app.delete("/api/communications/pairings/{platform}/{account_id}/{sender_id}")
def communications_revoke_pairing(platform: str, account_id: str, sender_id: str, request: Request) -> dict[str, Any]:
    manager = _get_communications_manager(request)
    revoked = manager.identities.revoke(platform, account_id, sender_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="Paired identity not found")
    notifications = manager.public_settings()["notifications"]
    notifications["destinations"] = [
        item for item in notifications["destinations"]
        if item != ":".join((platform, account_id, sender_id))
    ]
    manager.configure_notifications(notifications)
    return {"status": "revoked"}


@app.post("/api/communications/disable")
async def communications_disable(request: Request) -> dict[str, Any]:
    manager = _get_communications_manager(request)
    return await manager.set_enabled({platform: False for platform in manager.PLATFORMS})


@app.post("/api/communications/test")
async def communications_test(payload: dict[str, Any], request: Request) -> dict[str, Any]:
    manager = _get_communications_manager(request)
    key = payload.get("destination")
    identity = next((item for item in manager.identities.list_pairings() if manager.destination_key(item) == key), None)
    if identity is None:
        raise HTTPException(status_code=404, detail="Choose a paired account as the test destination")
    adapter = manager._adapters.get((identity["channel"], identity["account_id"]))
    if adapter is None or not identity.get("destination_id"):
        raise HTTPException(status_code=409, detail="The selected platform is not connected")
    from stai_messaging.contracts import OutboundReply
    try:
        await adapter.send_message(OutboundReply(identity["channel"], identity["destination_id"], "SVS-Cyber communications test message."))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Test delivery failed ({type(exc).__name__})") from exc
    return {"status": "delivered"}


@app.get("/api/communications/deliveries")
def communications_deliveries(request: Request) -> list[dict[str, Any]]:
    return _get_communications_manager(request).delivery_history()


# ---------------------------------------------------------------------------
# Protection API Routes
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    scope: Literal["quick", "system"] = Field(..., description="Scan scope: quick or system")


class ScanResponse(BaseModel):
    job_id: str
    scope: str
    state: str
    files_scanned: int
    files_total: int
    detections: int
    errors: int
    started_at: str
    completed_at: str | None = None
    error_message: str | None = None


class ThreatResponse(BaseModel):
    detection_id: str
    sha256: str
    rule_id: str
    rule_version: str
    action: str
    confidence: str
    severity: str
    file_type: str | None = None
    size_bytes: int | None = None
    file_path: str | None = None
    created_at: str
    triage_enqueued: bool


class QuarantineItemResponse(BaseModel):
    item_id: str
    original_path: str
    quarantined_path: str
    sha256: str
    rule_id: str
    rule_version: str
    action_result: str
    detection_id: str
    created_at: str
    restored_at: str | None = None
    restore_result: str | None = None


class QuarantineResponse(BaseModel):
    success: bool
    item: QuarantineItemResponse | None = None
    error: str | None = None


class AgentMessageRequest(BaseModel):
    session_id: str
    message: str
    detection_id: str | None = None


class AgentMessageResponse(BaseModel):
    session_id: str
    message: str
    tool_calls: list = []
    response_action: str | None = None


class ProtectionStatusResponse(BaseModel):
    state: str
    driver_state: str
    service_state: str
    rules_version: str
    last_scan: str | None = None
    counts: dict[str, int]
    windows_security: dict[str, Any]
    sensor_coverage: dict[str, Any]
    last_error: str | None = None


@app.get("/api/protection/status", response_model=ProtectionStatusResponse)
def protection_status() -> dict[str, Any]:
    """Get current protection status including driver, service, rules, and counts."""
    service = _get_protection_service()
    status = service.get_status()
    return {
        "state": status.state,
        "driver_state": status.driver_state,
        "service_state": status.service_state,
        "rules_version": status.rules_version,
        "last_scan": status.last_scan,
        "counts": status.counts,
        "windows_security": status.windows_security,
        "sensor_coverage": status.sensor_coverage,
        "last_error": status.last_error,
    }


@app.post("/api/protection/scans", response_model=ScanResponse)
def start_protection_scan(request: ScanRequest) -> dict[str, Any]:
    """Start a protection scan (quick or system)."""
    service = _get_protection_service()
    if request.scope not in ("quick", "system"):
        raise HTTPException(status_code=422, detail="scope must be 'quick' or 'system'")
    job = service.start_scan(request.scope)
    return {
        "job_id": job.job_id,
        "scope": job.scope,
        "state": job.state,
        "files_scanned": job.files_scanned,
        "files_total": job.files_total,
        "detections": job.detections,
        "errors": job.errors,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "error_message": job.error_message,
    }


@app.get("/api/protection/scans/{job_id}", response_model=ScanResponse)
def get_protection_scan(job_id: str) -> dict[str, Any]:
    """Get scan job progress."""
    service = _get_protection_service()
    job = service.store.get_scan_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="scan job not found")
    return {
        "job_id": job.job_id,
        "scope": job.scope,
        "state": job.state,
        "files_scanned": job.files_scanned,
        "files_total": job.files_total,
        "detections": job.detections,
        "errors": job.errors,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "error_message": job.error_message,
    }


@app.delete("/api/protection/scans/{job_id}")
def cancel_protection_scan(job_id: str) -> dict[str, Any]:
    """Cancel a running scan job."""
    service = _get_protection_service()
    cancelled = service.cancel_scan(job_id)
    if not cancelled:
        raise HTTPException(status_code=404, detail="scan job not found or not running")
    return {"status": "cancelled", "job_id": job_id}


@app.get("/api/protection/threats", response_model=list[ThreatResponse])
def list_protection_threats(limit: int = 100) -> list[dict[str, Any]]:
    """List detected threats (blocked + observed)."""
    service = _get_protection_service()
    threats = service.store.list_threats(limit=limit)
    return [
        {
            "detection_id": t.detection_id,
            "sha256": t.sha256,
            "rule_id": t.rule_id,
            "rule_version": t.rule_version,
            "action": t.action,
            "confidence": t.confidence,
            "severity": t.severity,
            "file_type": t.file_type,
            "size_bytes": t.size_bytes,
            "file_path": t.file_path,
            "created_at": t.created_at,
            "triage_enqueued": t.triage_enqueued,
        }
        for t in threats
    ]


@app.get("/api/protection/triage")
def get_protection_triage(detection_id: str) -> dict[str, Any]:
    """Get triage info for a detection."""
    # For now, return not implemented - triage is stored separately
    raise HTTPException(status_code=501, detail="triage endpoint not yet implemented")


@app.post("/api/protection/triage/{detection_id}")
def request_protection_triage(detection_id: str) -> dict[str, Any]:
    """Request agent triage for a detection."""
    raise HTTPException(status_code=501, detail="triage endpoint not yet implemented")


@app.get("/api/protection/agent/conversations/{session_id}")
def get_protection_agent_history(session_id: str) -> dict[str, Any]:
    """Get agent conversation history for a detection."""
    raise HTTPException(status_code=501, detail="agent history endpoint not yet implemented")


@app.post("/api/protection/agent/messages", response_model=AgentMessageResponse)
def send_protection_agent_message(request: AgentMessageRequest) -> dict[str, Any]:
    """Send message to protection agent (investigation-scoped, no tools)."""
    # Agent chat is handled by the main agent but scoped to detection
    # For now, return a placeholder response
    return {
        "session_id": request.session_id,
        "message": "Protection agent analysis not yet implemented",
        "tool_calls": [],
        "response_action": None,
    }


@app.get("/api/protection/quarantine", response_model=list[QuarantineItemResponse])
def list_protection_quarantine() -> list[dict[str, Any]]:
    """List quarantined items."""
    service = _get_protection_service()
    items = service.list_quarantine()
    return [
        {
            "item_id": item.item_id,
            "original_path": item.original_path,
            "quarantined_path": item.quarantined_path,
            "sha256": item.sha256,
            "rule_id": item.rule_id,
            "rule_version": item.rule_version,
            "action_result": item.action_result,
            "detection_id": item.detection_id,
            "created_at": item.created_at,
            "restored_at": item.restored_at,
            "restore_result": item.restore_result,
        }
        for item in items
    ]


@app.post("/api/protection/quarantine/{item_id}/restore", response_model=QuarantineResponse)
def restore_protection_quarantine(item_id: str) -> dict[str, Any]:
    """Restore a quarantined file."""
    service = _get_protection_service()
    result = service.restore_quarantine(item_id)
    if not result.success:
        error = result.error or "unknown error"
        if "not found" in error.lower():
            raise HTTPException(status_code=404, detail=error)
        if "refused" in error.lower():
            raise HTTPException(status_code=409, detail=error)
        raise HTTPException(status_code=500, detail=error)
    return {
        "success": result.success,
        "item": {
            "item_id": result.item.item_id,
            "original_path": result.item.original_path,
            "quarantined_path": result.item.quarantined_path,
            "sha256": result.item.sha256,
            "rule_id": result.item.rule_id,
            "rule_version": result.item.rule_version,
            "action_result": result.item.action_result,
            "detection_id": result.item.detection_id,
            "created_at": result.item.created_at,
            "restored_at": result.item.restored_at,
            "restore_result": result.item.restore_result,
        } if result.item else None,
        "error": result.error,
    }
