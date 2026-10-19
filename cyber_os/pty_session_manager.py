"""
cyber_os/pty_session_manager.py — PTY & Command Session Manager for SVS-Cyber

Provides persistent, interactive session tracking for terminal commands with
bounded ring buffering, read cursors for delta inspection, idle timeouts,
and clean process lifecycle management.

Adapted from mature agent PTY session architecture for SVS-Cyber.

Features:
- Opaque session IDs (e.g. 'sess_a1b2c3d4')
- Fixed ring buffer (default 256 KB) to prevent memory blowups and context overflow
- Delta tracking: actions 'view' / 'wait' return only new output since last read
- Safe interactive input: action 'send' transmits data to process stdin
- Clean process termination: action 'kill' terminates process tree gracefully
- Thread-safe background stdout/stderr accumulation
"""

from __future__ import annotations

import collections
import os
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

MAX_BUFFER_BYTES = 256 * 1024  # 256 KB ring buffer
SESSION_IDLE_TIMEOUT_SECONDS = 600.0  # 10 minutes
SESSION_MAX_LIFETIME_SECONDS = 3600.0  # 1 hour


@dataclass
class TerminalSession:
    session_id: str
    command: str
    working_dir: str
    process: Optional[subprocess.Popen] = None
    created_at: float = field(default_factory=time.time)
    last_activity_at: float = field(default_factory=time.time)
    is_alive: bool = True
    exit_code: Optional[int] = None
    buffer: bytearray = field(default_factory=bytearray)
    read_cursor: int = 0
    buffer_truncated: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


class PtySessionManager:
    """Manages active interactive command sessions across the investigation."""

    _instance: Optional[PtySessionManager] = None
    _singleton_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> PtySessionManager:
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = PtySessionManager()
            return cls._instance

    def __init__(self) -> None:
        self.sessions: Dict[str, TerminalSession] = {}
        self._lock = threading.Lock()
        self._reaper_thread: Optional[threading.Thread] = None
        self._start_reaper()

    def _start_reaper(self) -> None:
        def _reap_loop():
            while True:
                time.sleep(30)
                self.reap_expired_sessions()

        self._reaper_thread = threading.Thread(target=_reap_loop, daemon=True, name="pty-reaper")
        self._reaper_thread.start()

    def create_session(
        self,
        command: str,
        working_dir: Optional[str] = None,
        shell: bool = True,
    ) -> TerminalSession:
        """Launches a command process and tracks it in a new managed session."""
        session_id = f"sess_{uuid.uuid4().hex[:12]}"
        cwd = working_dir or os.getcwd()

        session = TerminalSession(
            session_id=session_id,
            command=command,
            working_dir=cwd,
        )

        try:
            # Launch process with piped stdout/stderr
            proc = subprocess.Popen(
                command,
                shell=shell,
                cwd=cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
            session.process = proc

            # Reader thread to ingest process output into ring buffer
            def _reader():
                try:
                    while proc.poll() is None:
                        chunk = proc.stdout.read(4096) if proc.stdout else b""
                        if chunk:
                            self._append_to_buffer(session, chunk)
                        else:
                            time.sleep(0.05)
                    # Ingest remaining output on exit
                    if proc.stdout:
                        remaining = proc.stdout.read()
                        if remaining:
                            self._append_to_buffer(session, remaining)
                except Exception:
                    pass
                finally:
                    with session.lock:
                        session.is_alive = False
                        session.exit_code = proc.returncode if proc.returncode is not None else 0

            threading.Thread(target=_reader, daemon=True, name=f"pty-reader-{session_id}").start()

        except Exception as exc:
            session.is_alive = False
            session.exit_code = -1
            session.buffer.extend(f"[Error starting command: {exc}]".encode("utf-8"))

        with self._lock:
            self.sessions[session_id] = session

        return session

    def _append_to_buffer(self, session: TerminalSession, chunk: bytes) -> None:
        """Appends bytes into ring buffer, evicting oldest bytes if over capacity."""
        with session.lock:
            session.last_activity_at = time.time()
            session.buffer.extend(chunk)
            overflow = len(session.buffer) - MAX_BUFFER_BYTES
            if overflow > 0:
                del session.buffer[:overflow]
                session.buffer_truncated = True
                session.read_cursor = max(0, session.read_cursor - overflow)

    def interact(
        self,
        session_id: str,
        action: str = "wait",
        data: Optional[str] = None,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """
        Interacts with an active terminal session:
        - 'view': returns new output since last read without blocking
        - 'wait': waits up to timeout for new output or exit
        - 'send': sends string data + newline to stdin
        - 'kill': terminates the process
        """
        with self._lock:
            session = self.sessions.get(session_id)

        if not session:
            return {
                "session_id": session_id,
                "success": False,
                "error": f"Session '{session_id}' not found or already terminated.",
            }

        with session.lock:
            session.last_activity_at = time.time()

        if action == "kill":
            return self._kill_session(session)

        if action == "send":
            if not session.is_alive or not session.process or not session.process.stdin:
                return {
                    "session_id": session_id,
                    "success": False,
                    "error": "Session process is no longer alive.",
                }
            try:
                payload = (data or "") + "\n"
                session.process.stdin.write(payload.encode("utf-8"))
                session.process.stdin.flush()
                return {
                    "session_id": session_id,
                    "success": True,
                    "action": "send",
                    "sent_bytes": len(payload),
                }
            except Exception as exc:
                return {"session_id": session_id, "success": False, "error": str(exc)}

        if action == "wait":
            start_wait = time.time()
            while time.time() - start_wait < timeout:
                with session.lock:
                    if len(session.buffer) > session.read_cursor or not session.is_alive:
                        break
                time.sleep(0.1)

        # 'view' or after 'wait' -> read delta
        with session.lock:
            delta_bytes = session.buffer[session.read_cursor:]
            session.read_cursor = len(session.buffer)
            output_str = delta_bytes.decode("utf-8", errors="replace")
            return {
                "session_id": session_id,
                "success": True,
                "output": output_str,
                "is_alive": session.is_alive,
                "exit_code": session.exit_code,
                "truncated": session.buffer_truncated,
            }

    def _kill_session(self, session: TerminalSession) -> Dict[str, Any]:
        with session.lock:
            if session.process and session.is_alive:
                try:
                    session.process.terminate()
                    session.process.wait(timeout=2.0)
                except Exception:
                    try:
                        session.process.kill()
                    except Exception:
                        pass
                session.is_alive = False
                session.exit_code = -9
            return {
                "session_id": session.session_id,
                "success": True,
                "action": "kill",
                "message": "Process terminated.",
            }

    def reap_expired_sessions(self) -> None:
        """Cleans up dead or timed-out sessions."""
        now = time.time()
        to_delete = []
        with self._lock:
            for sid, sess in self.sessions.items():
                idle = now - sess.last_activity_at
                lifetime = now - sess.created_at
                if not sess.is_alive and idle > 300:
                    to_delete.append(sid)
                elif idle > SESSION_IDLE_TIMEOUT_SECONDS or lifetime > SESSION_MAX_LIFETIME_SECONDS:
                    self._kill_session(sess)
                    to_delete.append(sid)

            for sid in to_delete:
                self.sessions.pop(sid, None)
