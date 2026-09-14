"""
cyber_main.py — Canonical Primary Entry Point for SVS-Cyber

Launches the complete SVS-Cyber agent system:
1. CyberAgent & Tool Registry (200+ defensive security tools)
2. Resilient Multi-Step Agent Runtime (multi-turn loop, doom-loop protection, compaction)
3. Subagents Framework (13 specialists)
4. Local FastAPI / WebSocket API server (real-time telemetry, tasks, notes, approval routing)
5. HackerAI Next.js web interface

Usage:
    python cyber_main.py                # Launch with HackerAI web UI (recommended)
    python cyber_main.py --web          # Headless web server only (accessible via browser)
    python cyber_main.py --port 8080    # Custom port for the web server
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request


def build_parser() -> argparse.ArgumentParser:
    """Build the SVS-Cyber CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="SVS-Cyber: Autonomous Defensive Cybersecurity Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--web", "--server",
        action="store_true",
        help="Launch headless FastAPI server without opening the desktop window",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=6764,
        help="Port for the API / web server (default: 6764)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to bind the web server to (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--frontend-port",
        type=int,
        default=6763,
        help="Port for the HackerAI Next.js frontend (default: 6763)",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the frontend in the default browser",
    )
    parser.add_argument(
        "--desktop",
        action="store_true",
        help="Open the HackerAI-style Tauri desktop app instead of a browser",
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help="Open the frontend in a browser (default when --desktop is omitted)",
    )
    return parser


def main() -> int:
    """Canonical application launcher for SVS-Cyber."""
    parser = build_parser()
    args, _ = parser.parse_known_args()

    # Set working directory to project root
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)

    print("=" * 60)
    print("  SVS-CYBER: Autonomous Cybersecurity Agent Platform")
    print("=" * 60)

    backend_url = f"http://{args.host}:{args.port}"
    frontend_url = f"http://127.0.0.1:{args.frontend_port}"

    if args.web:
        import uvicorn
        print(f"[*] Mode: Headless Web Server")
        print(f"[*] Serving SVS-Cyber API at http://{args.host}:{args.port}")
        print(f"[*] HackerAI UI should be run separately from ui/hackerai")
        print(f"[*] Press Ctrl+C to terminate.")
        try:
            uvicorn.run("ui.api_server:app", host=args.host, port=args.port, log_level="info")
            return 0
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")
            return 0
    else:
        # HackerAI Web UI Mode. The desktop-facing launcher owns both child
        # processes so closing this process cannot leave the local stack behind.
        print(
            f"[*] Mode: {'HackerAI-style desktop app' if args.desktop else 'HackerAI Web UI'}"
        )
        print(f"[*] Backend API: {backend_url}")
        print(f"[*] HackerAI UI: {frontend_url}")

        children: list[subprocess.Popen[bytes]] = []
        child_env = {**os.environ, "NEXT_PUBLIC_BACKEND_ORIGIN": backend_url}
        path_entries = child_env.get("PATH", "").split(os.pathsep)
        child_env["PATH"] = os.pathsep.join(
            entry for entry in path_entries if "openclaw\\bin" not in entry.lower()
        )

        def start_process(command: list[str], cwd: str) -> subprocess.Popen[bytes]:
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=child_env,
                creationflags=creationflags,
            )
            children.append(process)
            return process

        def wait_ready(
            url: str,
            process: subprocess.Popen[bytes],
            timeout_seconds: int = 60,
        ) -> None:
            deadline = time.monotonic() + timeout_seconds
            last_error = "no response"
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"Process exited with code {process.returncode}: {url}")
                try:
                    with urllib.request.urlopen(url, timeout=1) as response:
                        if 200 <= response.status < 500:
                            return
                except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                    last_error = str(exc)
                time.sleep(0.25)
            raise TimeoutError(f"Timed out waiting for {url}: {last_error}")

        def is_ready(url: str) -> bool:
            try:
                with urllib.request.urlopen(url, timeout=1) as response:
                    return 200 <= response.status < 500
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                return False

        def stop_children() -> None:
            for process in reversed(children):
                if process.poll() is None:
                    process.terminate()
            for process in reversed(children):
                if process.poll() is None:
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()

        try:
            backend_health_url = f"{backend_url}/health"
            if is_ready(backend_health_url):
                print("[*] Backend is already running; reusing it.")
            else:
                backend = start_process(
                    [sys.executable, "-m", "uvicorn", "ui.api_server:app", "--host", args.host, "--port", str(args.port)],
                    project_root,
                )
                wait_ready(backend_health_url, backend)

            node = shutil.which("node") or shutil.which("node.exe")
            next_cli = os.path.join(
                project_root, "ui", "hackerai", "node_modules", "next", "dist", "bin", "next",
            )
            if not node or not os.path.isfile(next_cli):
                raise RuntimeError("Node.js or the local Next.js installation is unavailable")
            if is_ready(frontend_url):
                print("[*] Frontend is already running; reusing it.")
            else:
                frontend = start_process(
                    [node, next_cli, "dev", "-p", str(args.frontend_port), "--turbopack"],
                    os.path.join(project_root, "ui", "hackerai"),
                )
                wait_ready(
                    f"{frontend_url}/robots.txt",
                    frontend,
                    timeout_seconds=360,
                )

            if args.desktop:
                cargo = shutil.which("cargo")
                tauri_cli = os.path.join(
                    project_root,
                    "ui",
                    "hackerai",
                    "packages",
                    "desktop",
                    "node_modules",
                    ".bin",
                    "tauri.cmd",
                )
                if not cargo or not os.path.isfile(tauri_cli):
                    raise RuntimeError(
                        "Desktop mode requires Rust/Cargo and the local Tauri CLI. "
                        "Install Rust, then run `pnpm install` in ui/hackerai."
                    )
                desktop = start_process(
                    [tauri_cli, "dev", "-c", "src-tauri/tauri.dev.conf.json"],
                    os.path.join(project_root, "ui", "hackerai", "packages", "desktop"),
                )
                if desktop.poll() is not None:
                    raise RuntimeError(
                        f"Desktop app exited during startup with code {desktop.returncode}"
                    )
                print("[*] Native HackerAI-style desktop window is ready.")
            elif not args.no_open:
                import webbrowser
                webbrowser.open(frontend_url)
            print("[*] Frontend and backend are ready. Press Ctrl+C to terminate.")
            while True:
                for process in children:
                    if process.poll() is not None:
                        raise RuntimeError(f"Managed process exited with code {process.returncode}")
                time.sleep(1)
        except (KeyboardInterrupt, RuntimeError, TimeoutError) as exc:
            if not isinstance(exc, KeyboardInterrupt):
                print(f"[!] Startup/runtime failure: {exc}", file=sys.stderr)
                return 1
            return 0
        finally:
            stop_children()


if __name__ == "__main__":
    sys.exit(main())