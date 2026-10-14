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

AGENT_SERVER_STARTUP_TIMEOUT_SECONDS = 300


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_ready(url: str, timeout: float = 1.0, *, follow_redirects: bool = True) -> bool:
    """Return True when the requested route succeeds, not just its server."""
    opener = urllib.request.build_opener() if follow_redirects else urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(url, timeout=timeout) as response:
            return 200 <= response.status < 400
    except urllib.error.HTTPError as error:
        if not follow_redirects and 300 <= error.code < 400:
            return True
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
        "--agent-port",
        type=int,
        default=3000,
        help="Loopback port for the HackerAI-style agent workspace (default: 3000)",
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


def find_built_desktop_app(desktop_dir: str) -> str | None:
    """Find a packaged release; debug binaries require the dev server."""
    candidate = os.path.join(
        desktop_dir,
        "src-tauri",
        "target",
        "release",
        "hackerai-desktop.exe",
    )
    return candidate if os.path.isfile(candidate) else None


def build_agent_server_command(
    project_root: str, fallback_node: str | None, port: int
) -> list[str] | None:
    """Use the pinned local Node runtime and a production build when available."""
    hackerai_dir = os.path.join(project_root, "ui", "hackerai")
    next_cli = os.path.join(hackerai_dir, "node_modules", "next", "dist", "bin", "next")
    local_node = os.path.join(project_root, "tools", "node-v22.22.3", "node.exe")
    agent_node = local_node if os.path.isfile(local_node) else fallback_node
    if not agent_node or not os.path.isfile(next_cli):
        return None

    build_id = os.path.join(hackerai_dir, ".next", "BUILD_ID")
    if os.path.isfile(build_id):
        return [agent_node, next_cli, "start", "--hostname", "127.0.0.1", "--port", str(port)]
    return [
        agent_node, next_cli, "dev", "--webpack", "--hostname", "127.0.0.1", "--port", str(port)
    ]


def _protection_pipe_ready(timeout_ms: int = 200) -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        wait_named_pipe = kernel32.WaitNamedPipeW
        wait_named_pipe.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32)
        wait_named_pipe.restype = ctypes.c_int
        return bool(wait_named_pipe(r"\\.\pipe\STAI.Protection.v1", timeout_ms))
    except (AttributeError, OSError):
        return False


def _wait_for_protection_pipe(timeout_seconds: float = 15) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _protection_pipe_ready():
            return True
        time.sleep(0.25)
    return False


def ensure_windows_protection_service(project_root: str) -> subprocess.Popen[bytes] | None:
    """Start the installed service, or the packaged user-mode dev host.

    The dashboard bridge talks to the protection named pipe, not cyber_main's
    HTTP API. Production service registration remains the installer's job. For
    local development, the test-channel executable may run as this user and is
    explicitly reported as EICAR-only with no kernel driver.
    """
    if os.name != "nt":
        return None

    service_name = "STAIProtection"
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    sc_exe = os.path.join(system_root, "System32", "sc.exe")
    try:
        query = subprocess.run(
            [sc_exe, "query", service_name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"[!] Could not query the Windows protection service: {error}")
        return None

    service_registered = query.returncode == 0
    if not service_registered and _protection_pipe_ready():
        print("[*] Protection service pipe is already available.")
        return None
    if not service_registered:
        tasklist = os.path.join(system_root, "System32", "tasklist.exe")
        try:
            running = subprocess.run(
                [tasklist, "/FI", "IMAGENAME eq STAIProtectionService.exe", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if "STAIProtectionService.exe" in running.stdout:
                print("[*] Local protection service process is already running.")
                return None
        except (OSError, subprocess.TimeoutExpired):
            pass

    if service_registered:
        state = query.stdout.upper()
        if "RUNNING" in state:
            if _wait_for_protection_pipe():
                print("[*] STAIProtection service is running and its dashboard pipe is ready.")
            else:
                print("[!] STAIProtection is running, but its dashboard pipe did not become available.")
            return None
        if "START_PENDING" in state:
            if _wait_for_protection_pipe():
                print("[*] STAIProtection finished starting; its dashboard pipe is ready.")
            else:
                print("[!] STAIProtection is still starting, but its dashboard pipe is not available yet.")
            return None

        try:
            started = subprocess.run(
                [sc_exe, "start", service_name],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"[!] Could not start STAIProtection: {error}")
            return None

        if started.returncode == 0 or "START_PENDING" in started.stdout.upper():
            if _wait_for_protection_pipe():
                print("[*] STAIProtection service started and its dashboard pipe is ready.")
            else:
                detail = (started.stderr or started.stdout).strip()
                print(f"[!] STAIProtection start was requested, but its dashboard pipe is unavailable. {detail}")
        else:
            detail = (started.stderr or started.stdout).strip()
            print(f"[!] STAIProtection did not start: {detail or 'Windows Service Control Manager rejected the request.'}")
        return None

    test_service = os.path.join(
        project_root,
        "windows_protection",
        "installer",
        "build",
        "Test",
        "dist",
        "STAIProtectionService.exe",
    )
    if not os.path.isfile(test_service):
        print("[!] STAIProtection is not installed and no local service build is available.")
        return None

    local_app_data = os.environ.get("LOCALAPPDATA") or project_root
    state_root = os.path.join(local_app_data, "SVSCyber")
    os.makedirs(state_root, exist_ok=True)
    service_env = {
        **os.environ,
        "STAI_LOCAL_DEV_SERVICE": "1",
        "STAI_PROTECTION_DATA_DIR": state_root,
        "PYTHONUNBUFFERED": "1",
    }
    service_log_path = os.path.join(state_root, "protection-service.log")
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        with open(service_log_path, "ab", buffering=0) as service_log:
            process = subprocess.Popen(
                [test_service, "debug"],
                cwd=os.path.dirname(test_service),
                env=service_env,
                stdin=subprocess.DEVNULL,
                stdout=service_log,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
            )
    except OSError as error:
        print(f"[!] Could not start local protection service: {error}")
        return None

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            print(f"[!] Local protection service exited with code {process.returncode}; see {service_log_path}.")
            return None
        if _protection_pipe_ready():
            print("[!] Local protection service is running in test mode: EICAR-only rules; kernel driver unavailable.")
            return process
        time.sleep(0.25)

    print(f"[!] Local protection service did not open its pipe in time; see {service_log_path}.")
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
    return None


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
    agent_url = f"http://127.0.0.1:{args.agent_port}"

    if args.web:
        import uvicorn
        protection_process = ensure_windows_protection_service(project_root)
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
        finally:
            if protection_process is not None and protection_process.poll() is None:
                protection_process.terminate()
                try:
                    protection_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    protection_process.kill()
    else:
        launch_desktop = should_launch_desktop(args)
        if args.desktop and args.browser:
            parser.error("--desktop and --browser cannot be used together")
        # Windows opens the protection dashboard first; the AI Agent action opens
        # the existing chat workspace in a separate native Tauri window.
        print(f"[*] Mode: {'SVS Cyber desktop dashboard' if launch_desktop else 'SVS Cyber browser dashboard'}")
        print(f"[*] Backend API: {backend_url}")
        print(f"[*] Protection dashboard: {frontend_url}")
        print(f"[*] AI Agent workspace: {agent_url}")

        protection_process = ensure_windows_protection_service(project_root)
        children: list[subprocess.Popen[bytes]] = []
        if protection_process is not None:
            children.append(protection_process)
        agent_process: subprocess.Popen[bytes] | None = None
        desktop_process: subprocess.Popen[bytes] | None = None
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
            *,
            follow_redirects: bool = True,
        ) -> None:
            deadline = time.monotonic() + timeout_seconds
            last_error = "no response"
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"Process exited with code {process.returncode}: {url}")
                if _http_ready(url, follow_redirects=follow_redirects):
                    return
                last_error = "no response"
                time.sleep(0.25)
            raise TimeoutError(f"Timed out waiting for {url}: {last_error}")

        def is_ready(url: str, *, follow_redirects: bool = True) -> bool :
            return _http_ready(url, follow_redirects=follow_redirects)

        def stop_children() -> None:
            for process in reversed(children):
                if process.poll() is None:
                    if os.name == "nt":
                        # Tauri's beforeDevCommand (Vite) is a grandchild of
                        # the CLI process; stop the whole tree so it cannot
                        # leave port 1420 occupied after shutdown.
                        subprocess.run(
                            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                        )
                    else:
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

            dashboard_dir = os.path.join(project_root, "ui", "hackerai", "packages", "protection-dashboard")
            hackerai_dir = os.path.join(project_root, "ui", "hackerai")
            next_cli = os.path.join(hackerai_dir, "node_modules", "next", "dist", "bin", "next")
            desktop_dir = os.path.join(project_root, "ui", "hackerai", "packages", "desktop")
            vite_cli = os.path.join(dashboard_dir, "node_modules", "vite", "bin", "vite.js")
            node = shutil.which("node", path=child_env["PATH"]) or shutil.which("node.exe", path=child_env["PATH"])
            agent_server_command = build_agent_server_command(project_root, node, args.agent_port)
            if launch_desktop:
                cargo = shutil.which("cargo", path=child_env["PATH"])
                if not cargo and os.environ.get("USERPROFILE"):
                    cargo_candidate = os.path.join(
                        os.environ["USERPROFILE"], ".cargo", "bin", "cargo.exe"
                    )
                    if os.path.isfile(cargo_candidate):
                        cargo = cargo_candidate
                node = shutil.which("node", path=child_env["PATH"]) or shutil.which("node.exe", path=child_env["PATH"])
                tauri_cli = os.path.join(
                    desktop_dir, "node_modules", ".bin", "tauri.cmd",
                )
                packaged_app = find_built_desktop_app(desktop_dir)
                if os.name != "nt":
                    raise RuntimeError(
                        "The native SVS Cyber desktop app is currently supported on Windows."
                    )
                if packaged_app:
                    desktop_process = start_process([packaged_app], desktop_dir)
                    print(f"[*] Built SVS Cyber Windows app is starting ({os.path.basename(os.path.dirname(packaged_app))} build).")
                elif cargo and node and os.path.isfile(tauri_cli):
                    desktop_bin = os.path.join(desktop_dir, "node_modules", ".bin")
                    desktop_env = {
                        **child_env,
                        "PATH": os.pathsep.join(
                            (desktop_bin, os.path.dirname(cargo), child_env["PATH"])
                        ),
                    }
                    desktop_process = start_process(
                        [node, "scripts/run-tauri.js", "dev"],
                        desktop_dir,
                        env=desktop_env,
                    )
                    print("[*] Native SVS Cyber protection dashboard is starting.")
                else:
                    raise RuntimeError(
                        "The SVS Cyber desktop app needs Rust/Cargo, Node.js, and the local Tauri CLI "
                        "for development, or a previously built Windows app. Install Rust from "
                        "https://rustup.rs/, then run `pnpm install` in ui/hackerai and "
                        "`pnpm desktop:build` there."
                    )
                if desktop_process.poll() is not None:
                    raise RuntimeError(
                        f"Desktop app exited during startup with code {desktop_process.returncode}"
                    )
            else:
                if not node or not os.path.isfile(vite_cli):
                    raise RuntimeError("Node.js and the local Vite dependency are required to launch the protection dashboard")
                # Probe the dashboard root explicitly; a 2xx on "/" means the UI
                # is serving. Gating on an incidental route (e.g. /robots.txt),
                # which a Next.js dev server 404s, would hang startup for the
                # full timeout.
                frontend_ready_url = f"{frontend_url}/"
                if is_ready(frontend_ready_url):
                    print("[*] Protection dashboard is already running; reusing it.")
                else:
                    frontend = start_process(
                        [node, vite_cli, "--host", "127.0.0.1", "--port", str(args.frontend_port), "--strictPort"],
                        dashboard_dir,
                    )
                    wait_ready(frontend_ready_url, frontend, timeout_seconds=120)
            # The native dashboard is the primary app. Its chat workspace is a
            # separately hosted Next.js app, so start it after the dashboard and
            # keep a missing/broken optional workspace from suppressing the UI.
            if is_ready(f"{agent_url}/", follow_redirects=False):
                print("[*] AI Agent workspace is already running; reusing it.")
            elif agent_server_command:
                try:
                    agent_process = start_process(
                        agent_server_command,
                        hackerai_dir,
                    )
                    mode = "production" if "start" in agent_server_command else "development"
                    print(f"[*] AI Agent workspace is starting in {mode} mode.")
                    wait_ready(
                        f"{agent_url}/",
                        agent_process,
                        timeout_seconds=AGENT_SERVER_STARTUP_TIMEOUT_SECONDS,
                        follow_redirects=False,
                    )
                except RuntimeError as exc:
                    if agent_process is not None and agent_process in children:
                        children.remove(agent_process)
                    agent_process = None
                    print(f"[!] AI Agent workspace is unavailable; the dashboard is still running: {exc}", file=sys.stderr)
                except TimeoutError:
                    print("[!] AI Agent workspace is still starting in the background; the dashboard is ready and the agent window can be opened once Next.js finishes compiling.", file=sys.stderr)
            else:
                print("[!] AI Agent workspace dependencies are unavailable; the dashboard is still running.", file=sys.stderr)
            if not launch_desktop and not args.no_open:
                import webbrowser
                webbrowser.open(frontend_url)
            print("[*] Dashboard and backend are ready. Use its AI Agent tab to open the assistant.")
            while True:
                for process in tuple(children):
                    if process.poll() is not None:
                        if process is agent_process:
                            children.remove(process)
                            agent_process = None
                            print(f"[!] AI Agent workspace exited with code {process.returncode}; the dashboard remains open.", file=sys.stderr)
                            continue
                        if process is desktop_process and process.returncode == 0:
                            return 0
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
