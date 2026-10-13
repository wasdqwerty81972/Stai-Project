"""
cyber_main.py — Canonical Primary Entry Point for SVS-Cyber

Launches the complete SVS-Cyber agent system:
1. CyberAgent & Tool Registry (200+ defensive security tools)
2. Resilient Multi-Step Agent Runtime (multi-turn loop, doom-loop protection, compaction)
3. Subagents Framework (13 specialists)
4. Local FastAPI / WebSocket API server (real-time telemetry, tasks, notes, approval routing)
5. SVS Cyber Protection Dashboard on Windows, with an explicit AI Agent tab

Usage:
    python cyber_main.py                # Launch the SVS Cyber dashboard (native on Windows)
    python cyber_main.py --web          # Headless web server only (accessible via browser)
    python cyber_main.py --port 8080    # Custom port for the web server
    python cyber_main.py --browser      # Open the protection dashboard in a browser
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


def _http_ready(url: str, timeout: float = 1.0) -> bool:
    """Return True when the requested route succeeds, not just its server."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return 200 <= response.status < 400
    except urllib.error.HTTPError:
        # A listening server with a missing/broken readiness route is not ready.
        return False
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return False


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
        default=1420,
        help="Loopback port for the browser dashboard (default: 1420)",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the frontend in the default browser",
    )
    parser.add_argument(
        "--desktop",
        action="store_true",
        help="Open the native SVS Cyber protection dashboard",
    )
    parser.add_argument(
        "--browser",
        action="store_true",
        help="Open the SVS Cyber protection dashboard in a browser",
    )
    return parser


def should_launch_desktop(args: argparse.Namespace, platform_name: str | None = None) -> bool:
    """Choose the native protection dashboard by default on Windows."""
    current_platform = platform_name or os.name
    return bool(args.desktop or (current_platform == "nt" and not args.browser))


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
        launch_desktop = should_launch_desktop(args)
        if args.desktop and args.browser:
            parser.error("--desktop and --browser cannot be used together")
        # Windows opens the protection dashboard first; AI Agent is a separate tab.
        print(f"[*] Mode: {'SVS Cyber desktop dashboard' if launch_desktop else 'SVS Cyber browser dashboard'}")
        print(f"[*] Backend API: {backend_url}")
        print(f"[*] Protection dashboard: {frontend_url}")

        children: list[subprocess.Popen[bytes]] = []
        child_env = {**os.environ, "NEXT_PUBLIC_BACKEND_ORIGIN": backend_url}
        path_entries = child_env.get("PATH", "").split(os.pathsep)
        child_env["PATH"] = os.pathsep.join(
            entry for entry in path_entries if "openclaw\\bin" not in entry.lower()
        )

        def start_process(
            command: list[str], cwd: str, env: dict[str, str] | None = None
        ) -> subprocess.Popen[bytes]:
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=env or child_env,
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
                if _http_ready(url):
                    return
                last_error = "no response"
                time.sleep(0.25)
            raise TimeoutError(f"Timed out waiting for {url}: {last_error}")

        def is_ready(url: str) -> bool:
            return _http_ready(url)

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
            dashboard_dir = os.path.join(project_root, "ui", "hackerai", "packages", "protection-dashboard")
            desktop_dir = os.path.join(project_root, "ui", "hackerai", "packages", "desktop")
            if launch_desktop:
                cargo = shutil.which("cargo", path=child_env["PATH"])
                if not cargo and os.environ.get("USERPROFILE"):
                    cargo_candidate = os.path.join(
                        os.environ["USERPROFILE"], ".cargo", "bin", "cargo.exe"
                    )
                    if os.path.isfile(cargo_candidate):
                        cargo = cargo_candidate
                node = shutil.which("node", path=child_env["PATH"]) or shutil.which(
                    "node.exe", path=child_env["PATH"]
                )
                tauri_cli = os.path.join(
                    desktop_dir, "node_modules", ".bin", "tauri.cmd",
                )
                packaged_app = os.path.join(
                    desktop_dir, "src-tauri", "target", "release", "hackerai-desktop.exe"
                )
                if os.name != "nt":
                    raise RuntimeError(
                        "The native SVS Cyber desktop app is currently supported on Windows."
                    )
                if cargo and node and os.path.isfile(tauri_cli):
                    desktop_bin = os.path.join(desktop_dir, "node_modules", ".bin")
                    desktop_env = {
                        **child_env,
                        "PATH": os.pathsep.join(
                            (desktop_bin, os.path.dirname(cargo), child_env["PATH"])
                        ),
                    }
                    desktop = start_process(
                        [node, "scripts/run-tauri.js", "dev"],
                        desktop_dir,
                        env=desktop_env,
                    )
                    print("[*] Native SVS Cyber protection dashboard is starting.")
                elif os.path.isfile(packaged_app):
                    desktop = start_process([packaged_app], desktop_dir)
                    print("[*] Packaged SVS Cyber Windows app is starting.")
                else:
                    raise RuntimeError(
                        "The SVS Cyber desktop app needs Rust/Cargo, Node.js, and the local Tauri CLI "
                        "for development, or a previously built Windows app. Install Rust from "
                        "https://rustup.rs/, then run `pnpm install` in ui/hackerai and "
                        "`pnpm desktop:build` there."
                    )
                if desktop.poll() is not None:
                    raise RuntimeError(
                        f"Desktop app exited during startup with code {desktop.returncode}"
                    )
            else:
                pnpm = shutil.which("pnpm", path=child_env["PATH"]) or shutil.which("pnpm.cmd", path=child_env["PATH"])
                if not node or not pnpm:
                    raise RuntimeError("Node.js and pnpm are required to launch the protection dashboard")
                # Probe the dashboard root explicitly; a 2xx on "/" means the UI
                # is serving. Gating on an incidental route (e.g. /robots.txt),
                # which a Next.js dev server 404s, would hang startup for the
                # full timeout.
                frontend_ready_url = f"{frontend_url}/"
                if is_ready(frontend_ready_url):
                    print("[*] Protection dashboard is already running; reusing it.")
                else:
                    frontend = start_process(
                        [pnpm, "run", "dev", "--", "--port", str(args.frontend_port)],
                        dashboard_dir,
                    )
                    wait_ready(frontend_ready_url, frontend, timeout_seconds=120)
            if not launch_desktop and not args.no_open:
                import webbrowser
                webbrowser.open(frontend_url)
            print("[*] Dashboard and backend are ready. Use its AI Agent tab to open the assistant.")
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
