"""
key_manager.py

Manages API access with OmniRoute as primary and Gemini keys as fallback.

OmniRoute (Antigravity) is an OpenAI-compatible gateway running locally that
routes to all connected providers (Gemini, OpenAI, Claude, etc.).
Endpoint: http://localhost:20128/v1

Architecture:
  - OmniRoute client  — used for ALL roles via OpenAI-compatible SDK.
                        Routes to best available model automatically.
  - Gemini fallback   — 4 Gemini keys used if OmniRoute is unreachable.

  - client_for_role(i)  -> Returns an OmniRouteClient wrapper that looks
                           identical to the old Gemini client interface.
                           Falls back to Gemini key i if OmniRoute is down.

  - generate(pool, ...) -> OmniRoute call, Gemini fallback on failure.

Demo Mode
---------
Use MockRoleKeyManager() for offline demos — no real keys or internet needed.
"""

import itertools
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, List


def _load_local_env() -> None:
    """Load simple server-only .env.local values without logging secrets."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env.local")
    try:
        with open(env_path, "r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, value = line.split("=", 1)
                name = name.strip()
                value = value.strip().strip('"').strip("'")
                if name and value and not value.startswith("REPLACE_WITH_"):
                    os.environ.setdefault(name, value)
    except OSError:
        pass


_load_local_env()

OMNIROUTE_BASE_URL = os.environ.get("OMNIROUTE_BASE_URL", "http://localhost:20128/v1")
OMNIROUTE_API_KEY  = os.environ.get("OMNIROUTE_API_KEY",  "")
OMNIROUTE_MODEL    = os.environ.get("OMNIROUTE_MODEL",    "auto/coding")
GEMINI_MODEL       = os.environ.get("GEMINI_MODEL",       "gemini-3.5-flash-lite")

# Set to True to use OmniRoute as primary, with automatic Gemini fallback
ENABLE_OMNIROUTE = False  # TEMPORARILY DISABLED FOR TESTING


class _SimplePart:
    """Simple part container compatible with both OmniRoute shim and Gemini."""
    def __init__(self, text: str = None):
        self.text = text
    function_call = None


def _make_vision_part(data: bytes, mime_type: str):
    """Create a vision part compatible with the current client (OmniRoute shim or Gemini)."""
    if _GENAI_AVAILABLE:
        try:
            from google.genai import types
            return types.Part.from_bytes(data=data, mime_type=mime_type)
        except Exception:
            pass
    # Fallback simple object
    class _VisionPart:
        def __init__(self, data, mime_type):
            self.data = data
            self.mime_type = mime_type
            self.text = None
    return _VisionPart(data, mime_type)

try:
    from openai import OpenAI as _OpenAI
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False

try:
    from google import genai as _genai
    from google.genai import errors as _genai_errors
    from google.genai import types as _genai_types
    _GENAI_AVAILABLE = True
except ImportError:
    _GENAI_AVAILABLE = False
    _genai = None
    _genai_errors = None
    _genai_types = None


def _probe_omniroute(timeout: float = 2.0) -> bool:
    """Check if OmniRoute is reachable at the configured base URL."""
    if not _OPENAI_AVAILABLE:
        return False
    try:
        import urllib.request
        health_url = OMNIROUTE_BASE_URL.rstrip("/").replace("/v1", "") + "/health"
        req = urllib.request.Request(health_url, method="GET")
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception:
        try:
            import urllib.request
            models_url = OMNIROUTE_BASE_URL.rstrip("/") + "/models"
            req = urllib.request.Request(models_url, headers={"Authorization": f"Bearer {OMNIROUTE_API_KEY}"})
            urllib.request.urlopen(req, timeout=timeout)
            return True
        except Exception:
            return False


class _OmniRouteGenaiShim:
    """
    Wraps the OpenAI SDK client so it presents the same interface that
    video_editing_agent.py and coding_agent.py expect from a google.genai client:
        client.models.generate_content(model=..., contents=..., config=...)
    """

    def __init__(self, openai_client, model: str = OMNIROUTE_MODEL):
        self._client = openai_client
        self._model = model
        self.models = self

    def generate_content(self, model=None, contents=None, config=None, **kwargs):
        model = model or self._model
        messages = self._convert_contents(contents or [])

        system = None
        if config and hasattr(config, "system_instruction") and config.system_instruction:
            system = config.system_instruction

        if system:
            messages = [{"role": "system", "content": system}] + messages

        temperature = 0.3
        top_p = 0.9
        max_tokens = 4096
        if config:
            if hasattr(config, "temperature") and config.temperature is not None:
                temperature = config.temperature
            if hasattr(config, "top_p") and config.top_p is not None:
                top_p = config.top_p
            if hasattr(config, "max_tokens") and config.max_tokens is not None:
                max_tokens = config.max_tokens

        safe_model = model if "/" in model or "-" in model else self._model

        resp = self._client.chat.completions.create(
            model=safe_model,
            messages=messages,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
        )

        content = resp.choices[0].message.content
        if not content or not content.strip():
            content = "[The model returned an empty response. Please rephrase your request.]"
        return _OmniRouteResponse(content)

    def _convert_contents(self, contents) -> list:
        messages = []
        for c in contents:
            # Handle both object attributes and dict keys
            if isinstance(c, dict):
                role = c.get("role", "user")
                parts = c.get("parts", [])
            else:
                role = getattr(c, "role", "user")
                parts = getattr(c, "parts", [])
            
            if role == "model":
                role = "assistant"
            
            text_parts = []
            for p in parts:
                if isinstance(p, dict):
                    text = p.get("text")
                else:
                    text = getattr(p, "text", None)
                if text:
                    text_parts.append(text)
            
            if text_parts:
                messages.append({"role": role, "content": "\n".join(text_parts)})
        return messages


class _OmniRoutePart:
    def __init__(self, text: str):
        self.text = text
    function_call = None


class _OmniRouteContent:
    def __init__(self, text: str):
        self.role = "model"
        self._text = text

    @property
    def parts(self):
        return [_OmniRoutePart(self._text)]


class _OmniRouteCandidate:
    def __init__(self, text: str):
        self.content = _OmniRouteContent(text)


class _OmniRouteResponse:
    """Mimics google.genai response so existing agent code works unchanged."""
    def __init__(self, text: str):
        self._text = text or ""

    @property
    def candidates(self):
        return [_OmniRouteCandidate(self._text)]


@dataclass
class KeyState:
    key: str
    label: str
    cooldown_until: float = 0.0
    failure_count: int = 0

    def is_available(self) -> bool:
        return time.time() >= self.cooldown_until


class RoleKeyManager:
    SEARCH_POOL = "search"
    TOOL_POOL   = "tools"
    ALL_POOL    = "all"

    def __init__(self, keys: Optional[list] = None, cooldown_seconds: int = 60):
        self.cooldown_seconds = cooldown_seconds
        self._lock = threading.Lock()
        self._omniroute_client: Optional[_OmniRouteGenaiShim] = None
        self._omniroute_available = False

        self._try_init_omniroute()

        gemini_keys = self._load_gemini_keys(keys)
        self._states = [KeyState(key=k, label=f"gemini-key-{i + 1}") for i, k in enumerate(gemini_keys)]
        self._genai_clients = {}
        self._pools = {
            self.SEARCH_POOL: itertools.cycle(self._states[0:2]),
            self.TOOL_POOL:   itertools.cycle(self._states[2:5]),
            self.ALL_POOL:    itertools.cycle(self._states),
        }

    def _try_init_omniroute(self):
        if not ENABLE_OMNIROUTE:
            print("[KeyManager] OmniRoute disabled via ENABLE_OMNIROUTE flag — using Gemini only")
            return
        if not _OPENAI_AVAILABLE:
            print("[KeyManager] openai package not installed — OmniRoute disabled, using Gemini only")
            return
        if not OMNIROUTE_API_KEY:
            print("[KeyManager] OMNIROUTE_API_KEY is not configured — using Gemini only")
            return
        try:
            raw = _OpenAI(base_url=OMNIROUTE_BASE_URL, api_key=OMNIROUTE_API_KEY)
            self._omniroute_client = _OmniRouteGenaiShim(raw)
            self._omniroute_available = True
            print(f"[KeyManager] OmniRoute connected at {OMNIROUTE_BASE_URL} (model: {OMNIROUTE_MODEL})")
        except Exception as e:
            print(f"[KeyManager] OmniRoute init failed: {e} — falling back to Gemini")

    def _load_gemini_keys(self, keys: Optional[list]) -> list:
        manager_fallback = [
            "REPLACE_WITH_GEMINI_KEY_1",
            "REPLACE_WITH_GEMINI_KEY_2",
            "REPLACE_WITH_GEMINI_KEY_3",
            "REPLACE_WITH_GEMINI_KEY_4",
            "REPLACE_WITH_GEMINI_KEY_5",
        ]
        configured = list(keys or [])
        if not configured:
            primary = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            if primary:
                configured.append(primary)
        for index in range(1, 6):
            env_key = os.environ.get(f"GEMINI_API_KEY_{index}")
            if env_key and env_key not in configured:
                configured.append(env_key)
        configured = [
            key.strip()
            for key in configured
            if isinstance(key, str)
            and key.strip()
            and not key.strip().startswith("REPLACE_WITH_")
        ]
        if not configured:
            return []
        return configured[:5]

    def _genai_client_for(self, state: KeyState):
        if not _GENAI_AVAILABLE:
            raise RuntimeError("google-genai package not installed and OmniRoute is unavailable")
        if state.key not in self._genai_clients:
            self._genai_clients[state.key] = _genai.Client(
                api_key=state.key,
                http_options=_genai_types.HttpOptions(timeout=15000),
            )
        return self._genai_clients[state.key]

    def client_for_role(self, role_index: int):
        """
        Returns (client, label). Client presents the google.genai interface.
        Prefers OmniRoute; falls back to the Gemini key for that role index.
        """
        if self._omniroute_available and self._omniroute_client:
            return self._omniroute_client, f"omniroute-role-{role_index}"
        state = self._states[role_index % len(self._states)]
        try:
            return self._genai_client_for(state), state.label
        except Exception as e:
            print(f"[KeyManager] Key {state.label} failed: {e}")
            raise

    def _pool_states(self, pool_name: str) -> list:
        if pool_name == self.SEARCH_POOL:
            return self._states[0:2]
        if pool_name == self.TOOL_POOL:
            return self._states[2:5]
        return self._states

    def _next_available(self, pool_name: str) -> KeyState:
        pool = self._pools[pool_name]
        candidates = self._pool_states(pool_name)
        with self._lock:
            for _ in range(len(candidates) * 2):
                state = next(pool)
                if state.is_available():
                    return state
            return min(candidates, key=lambda s: s.cooldown_until)

    def generate(self, pool_name: str, **kwargs):
        """
        Try OmniRoute first, then round-robin Gemini keys in the pool.
        Returns (response, label) — response matches google.genai shape.
        """
        if self._omniroute_available and self._omniroute_client:
            try:
                resp = self._omniroute_client.models.generate_content(**kwargs)
                return resp, "omniroute"
            except Exception as e:
                print(f"[KeyManager] OmniRoute generate failed: {e} — falling back to Gemini")
                with self._lock:
                    self._omniroute_available = False

        if not _GENAI_AVAILABLE:
            raise RuntimeError("OmniRoute unavailable and google-genai not installed")

        candidates = self._pool_states(pool_name)
        last_error = None
        attempted = 0
        for _ in range(len(candidates)):
            state = self._next_available(pool_name)
            attempted += 1
            client = self._genai_client_for(state)
            try:
                response = client.models.generate_content(**kwargs)
                with self._lock:
                    state.failure_count = 0
                return response, state.label
            except _genai_errors.ClientError as e:
                last_error = e
                print(f"[KeyManager] Key {state.label} failed: {e}")
                with self._lock:
                    state.failure_count += 1
                    if getattr(e, "code", None) in (429, 403):
                        state.cooldown_until = time.time() + self.cooldown_seconds
                        continue
                raise
            except _genai_errors.ServerError as e:
                last_error = e
                print(f"[KeyManager] Key {state.label} failed: {e}")
                with self._lock:
                    state.cooldown_until = time.time() + 10
                continue
            except Exception as e:
                last_error = e
                print(f"[KeyManager] Key {state.label} failed: {e}")
                with self._lock:
                    state.failure_count += 1
                continue

        if attempted == 0:
            return self._circuit_breaker_error(pool_name, "No keys available in pool")
        if all(not s.is_available() for s in candidates):
            return self._circuit_breaker_error(pool_name, "All keys are currently rate-limited or failing")
        raise RuntimeError(
            f"All keys in pool '{pool_name}' are rate-limited or failing. Last error: {last_error}"
        )

    def _circuit_breaker_error(self, pool_name: str, reason: str):
        class _CircuitResponse:
            text = f"All AI keys are currently rate-limited or failing ({reason}). Try again in a moment."
        return _CircuitResponse(), "circuit-breaker"

    def get_key(self, label: str) -> str:
        """Compatibility for quiz_generator.py — returns first Gemini key."""
        return self._states[0].key if self._states else ""

    def status(self) -> list:
        result = []
        if self._omniroute_available:
            result.append({
                "label": "omniroute",
                "available": True,
                "cooldown_seconds_left": 0,
                "failure_count": 0,
                "mode": "primary",
            })
        for s in self._states:
            result.append({
                "label": s.label,
                "available": s.is_available(),
                "cooldown_seconds_left": max(0, round(s.cooldown_until - time.time())),
                "failure_count": s.failure_count,
                "mode": "fallback",
            })
        return result


# ---------------------------------------------------------------------------
# AE PATH AUTO-DETECTION UTILITY
# ---------------------------------------------------------------------------

def find_ae_scriptui_panels_dir() -> Optional[str]:
    """
    Auto-detect the After Effects ScriptUI Panels folder by scanning
    known install locations and drive letters. Returns the first found path.
    """
    import string

    ae_versions = [
        "2024", "2023", "2022", "2021", "2020", "2019", "2018",
        "CC 2024", "CC 2023", "CC 2022", "CC 2021", "CC 2020",
    ]
    sub = r"Adobe After Effects {ver}\Support Files\Scripts\ScriptUI Panels"

    drives = []
    for letter in string.ascii_uppercase:
        d = f"{letter}:\\"
        if os.path.exists(d):
            drives.append(d)

    base_dirs = [
        r"Program Files\Adobe",
        r"Adobe",
        r"",
    ]

    for drive in drives:
        for base in base_dirs:
            for ver in ae_versions:
                candidate = os.path.join(drive, base, sub.format(ver=ver))
                if os.path.isdir(candidate):
                    return candidate

    env_ae = os.environ.get("AE_SCRIPTUI_PANELS_DIR")
    if env_ae and os.path.isdir(env_ae):
        return env_ae

    known = [
        r"H:\Adobe After Effects 2020\Support Files\Scripts\ScriptUI Panels",
        r"I:\Adobe After Effects 2020\Support Files\Scripts\ScriptUI Panels",
        r"C:\Program Files\Adobe\Adobe After Effects 2024\Support Files\Scripts\ScriptUI Panels",
        r"C:\Program Files\Adobe\Adobe After Effects 2023\Support Files\Scripts\ScriptUI Panels",
        r"C:\Program Files\Adobe\Adobe After Effects 2022\Support Files\Scripts\ScriptUI Panels",
        r"C:\Program Files\Adobe\Adobe After Effects 2021\Support Files\Scripts\ScriptUI Panels",
        r"C:\Program Files\Adobe\Adobe After Effects 2020\Support Files\Scripts\ScriptUI Panels",
    ]
    for p in known:
        if os.path.isdir(p):
            return p

    return None


# ---------------------------------------------------------------------------
# DEMO / MOCK KEY MANAGER
# ---------------------------------------------------------------------------

class MockRoleKeyManager:
    """
    Drop-in replacement for RoleKeyManager that works with no API keys and
    no internet. Every call returns a realistic canned response so the full
    UI pipeline (Study Agent, Coding Agent, Quiz Generator, Video Editor)
    runs end-to-end for live demos.
    """

    SEARCH_POOL = "search"
    TOOL_POOL   = "tools"
    ALL_POOL    = "all"

    _CANNED = {
        "quiz": (
            "**📝 DEMO QUIZ — Python Basics**\n\n"
            "1. What does `len([1, 2, 3])` return?\n"
            "   A) 1   B) 2   **C) 3**   D) 4\n\n"
            "2. Which keyword is used to define a function in Python?\n"
            "   A) func   **B) def**   C) define   D) lambda\n\n"
            "*(🔵 DEMO MODE — connect OmniRoute or Gemini keys for live AI generation)*"
        ),
        "flashcards": (
            "**🃃 DEMO FLASHCARDS**\n\n"
            "Q: What is a variable?\nA: A named storage location that holds a value.\n\n"
            "Q: What is a loop?\nA: A control structure that repeats a block of code.\n\n"
            "*(🔵 DEMO MODE — connect OmniRoute or Gemini keys for live AI generation)*"
        ),
        "search": (
            "Great question! Based on verified sources:\n\n"
            "The topic you asked about is a foundational concept in computer science.\n\n"
            "*(🔵 DEMO MODE — connect OmniRoute or Gemini keys for live search-grounded answers)*"
        ),
        "coding": (
            "## Coding Agent Report (DEMO)\n\n"
            "**Plan:** Analysed the request and identified 3 implementation steps.\n\n"
            "*(🔵 DEMO MODE — connect OmniRoute or Gemini keys for live AI coding)*"
        ),
        "threat_intel_analyst": (
            "## Threat Intelligence Analysis (DEMO)\n\n"
            "**IOC:** 185.220.101.5\n"
            "**Classification:** C2 Beaconing / Tor Exit Node\n"
            "**Confidence:** HIGH (85%)\n"
            "**Attribution:** APT29 / Cozy Bear\n"
            "**Recommendation:** Block at perimeter, hunt for related IOCs.\n\n"
            "*(🔵 DEMO MODE — connect OmniRoute or Gemini keys for live threat intel)*"
        ),
        "malware_analyst": (
            "## Malware Analysis Report (DEMO)\n\n"
            "**Sample:** trojan.x64.ps1\n"
            "**Family:** Emotet / TrickBot\n"
            "**Behavior:** Process injection, credential dumping, registry persistence\n"
            "**Entropy:** 7.2 (HIGH — likely packed/encrypted)\n"
            "**IOCs:** \n"
            "  - C2: 192.168.1.250:443\n"
            "  - Mutex: Global\\Emotet_2026\n"
            "  - Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n\n"
            "*(🔵 DEMO MODE — connect OmniRoute or Gemini keys for live malware analysis)*"
        ),
        "network_defender": (
            "## Network Defense Assessment (DEMO)\n\n"
            "**Traffic Anomaly:** Unusual outbound volume to 185.220.101.0/24\n"
            "**Pattern:** Periodic callbacks every 300s (beaconing)\n"
            "**Affected Hosts:** 3 endpoints\n"
            "**Action:** Blocked at firewall, quarantined host HOST-42\n"
            "**Status:** CONTAINED\n\n"
            "*(🔵 DEMO MODE — connect OmniRoute or Gemini keys for live network defense)*"
        ),
        "incident_responder": (
            "## Incident Response Summary (DEMO)\n\n"
            "**Incident:** Ransomware outbreak\n"
            "**Severity:** CRITICAL (Threat Score: 9/10)\n"
            "**Affected Systems:** 12 endpoints, 2 servers\n"
            "**Actions Taken:**\n"
            "  1. Isolated affected hosts from network\n"
            "  2. Blocked C2 communication at firewall\n"
            "  3. Captured memory forensics for analysis\n"
            "  4. Initiated recovery from clean backups\n"
            "**Recommendation:** Rotate all credentials, review backup integrity\n\n"
            "*(🔵 DEMO MODE — connect OmniRoute or Gemini keys for live incident response)*"
        ),
        "forensic_investigator": (
            "## Forensic Investigation Report (DEMO)\n\n"
            "**Artifact:** temp_vulnerable.py\n"
            "**Finding:** Code injection vulnerability (CWE-94)\n"
            "**Line 3:** eval(user_input) — arbitrary code execution\n"
            "**Risk:** CRITICAL\n"
            "**Remediation:** Replace eval() with ast.literal_eval() or structured parsing\n"
            "**Evidence:** Preserved in audit_log.json with timestamp\n\n"
            "*(🔵 DEMO MODE — connect OmniRoute or Gemini keys for live forensics)*"
        ),
        "vulnerability_researcher": (
            "## Vulnerability Research (DEMO)\n\n"
            "**CVE-2026-XXXX:** Remote Code Execution in Apache HTTPD\n"
            "**CVSS:** 9.8 CRITICAL\n"
            "**Attack Vector:** Network\n"
            "**Exploit:** Public PoC available on GitHub\n"
            "**Affected Versions:** 2.4.58 and prior\n"
            "**Fix:** Upgrade to 2.4.59 or apply vendor patch\n"
            "**Workaround:** Disable mod_proxy module\n\n"
            "*(🔵 DEMO MODE — connect OmniRoute or Gemini keys for live vuln research)*"
        ),
        "default": (
            "This is a demo response. The AI Agents system is running in **Demo Mode**.\n\n"
            "In live mode, this would call OmniRoute (Antigravity) with smart provider routing.\n\n"
            "*(🔵 DEMO MODE — connect OmniRoute or Gemini keys for live AI responses)*"
        ),
    }

    class _FakePart:
        def __init__(self, text: str):
            self.text = text
        function_call = None

    class _FakeContent:
        def __init__(self, text: str):
            self.role = "model"
            self._text = text

        @property
        def parts(self):
            return [MockRoleKeyManager._FakePart(self._text)]

    class _FakeCandidate:
        def __init__(self, text: str):
            self.content = MockRoleKeyManager._FakeContent(text)

    class _FakeResponse:
        def __init__(self, text: str):
            self._text = text

        @property
        def candidates(self):
            return [MockRoleKeyManager._FakeCandidate(self._text)]

    def __init__(self):
        self._labels = [f"demo-key-{i}" for i in range(1, 6)]
        self._label_cycle = itertools.cycle(self._labels)
        self.models = self  # For compatibility with AiApi.chat()

    def _pick_canned(self, **kwargs) -> str:
        contents = kwargs.get("contents", [])
        role = kwargs.get("role", "")
        text = ""
        for c in contents:
            if isinstance(c, dict):
                parts = c.get("parts", [])
            else:
                parts = getattr(c, "parts", [])
            for p in parts:
                if isinstance(p, dict):
                    pt = p.get("text", "")
                else:
                    pt = getattr(p, "text", "")
                if pt:
                    text += pt.lower()
        
        import re
        # If a specific role was requested, return its canned response directly
        if role and role in self._CANNED:
            return self._CANNED[role]
        # Fallback to keyword matching
        if re.search(r'\bincident\b|\bresponse\b|\bcontain\b|\brecover\b', text):
            return self._CANNED.get("incident_responder", self._CANNED["default"])
        if re.search(r'\bthreat\b|\bioc\b|\bintel\b|\battribution\b', text):
            return self._CANNED.get("threat_intel_analyst", self._CANNED["default"])
        if re.search(r'\bmalware\b|\bransomware\b|\btrojan\b|\bsample\b|\bvirus\b', text):
            return self._CANNED.get("malware_analyst", self._CANNED["default"])
        if re.search(r'\bnetwork\b|\bfirewall\b|\bbeacon\b|\bc2\b|\btraffic\b', text):
            return self._CANNED.get("network_defender", self._CANNED["default"])
        if re.search(r'\bforensic\b|\bartifact\b|\binvestigate\b|\bevidence\b', text):
            return self._CANNED.get("forensic_investigator", self._CANNED["default"])
        if re.search(r'\bvulnerability\b|\bcve\b|\bexploit\b|\bpatch\b', text):
            return self._CANNED.get("vulnerability_researcher", self._CANNED["default"])
        if "quiz" in text or "question" in text:
            return self._CANNED["quiz"]
        if "flashcard" in text:
            return self._CANNED["flashcards"]
        if "code" in text or "build" in text or "write" in text:
            return self._CANNED["coding"]
        return self._CANNED["default"]

    def client_for_role(self, role_index: int):
        return self, self._labels[role_index % len(self._labels)]

    def generate(self, pool_name: str, **kwargs):
        label = next(self._label_cycle)
        time.sleep(0.6)
        canned = self._pick_canned(**kwargs)
        return self._FakeResponse(canned), label

    def generate_content(self, model=None, contents=None, config=None, **kwargs):
        """Compatibility with AiApi.chat() which calls client.models.generate_content()"""
        system = getattr(config, "system_instruction", "") if config else ""
        user_text = ""
        if contents:
            for c in contents:
                if hasattr(c, "parts"):
                    for p in c.parts:
                        if hasattr(p, "text") and p.text:
                            user_text += p.text + "\n"
                elif isinstance(c, dict) and c.get("parts"):
                    for p in c["parts"]:
                        if isinstance(p, dict):
                            if p.get("text"):
                                user_text += p["text"] + "\n"
                        elif hasattr(p, "text") and p.text:
                            user_text += p.text + "\n"
        combined = (system + "\n" + user_text).strip()
        # Create a simple object structure that _pick_canned can parse
        class _Content:
            def __init__(self, text):
                self.parts = [type('Part', (), {'text': text})()]
        # Pass role from kwargs for deterministic mock selection
        role = kwargs.get("role", "")
        canned = self._pick_canned(contents=[_Content(combined)], role=role)
        return self._FakeResponse(canned)

    def get_key(self, label: str) -> str:
        return "demo-key"

    def status(self) -> list:
        return [
            {"label": lbl, "available": True, "cooldown_seconds_left": 0, "failure_count": 0, "mode": "demo"}
            for lbl in self._labels
        ]


# ---------------------------------------------------------------------------
# UNIFIED AI API INTERFACE
# ---------------------------------------------------------------------------
# All agents should use this instead of importing RoleKeyManager directly.
# Usage:
#     from key_manager import AiApi
#     api = AiApi()
#     response = api.chat("You are a helpful assistant", "Hello!")
#     response = api.chat_with_role("coder", "Write a Python function", "Make it async")
# ---------------------------------------------------------------------------


class _SimpleMessage:
    """Simple message container for chat interface."""
    def __init__(self, role: str, content: str):
        self.role = role
        self.content = content


class _SimpleChoice:
    def __init__(self, message: _SimpleMessage):
        self.message = message


class _SimpleResponse:
    """Standardized response object matching OpenAI chat.completions format."""
    def __init__(self, text: str, model: str = "omniroute", role: str = "assistant"):
        self.choices = [_SimpleChoice(_SimpleMessage(role, text))]
        self.model = model
        self.usage = None


class AiApi:
    """
    Unified AI API interface for all agents.
    
    Abstracts away:
    - OmniRoute (primary) vs Gemini (fallback) 
    - Role-based key management (planner, designer, coder, reviewer, reporter)
    - Rate limiting, retries, fallback logic
    - Cybersecurity-specific roles (threat_intel, malware_analyst, network_defender, etc.)
    
    Usage:
        from key_manager import AiApi
        
        api = AiApi()
        
        # Simple chat
        resp = api.chat("You are a helpful assistant", "Hello!")
        print(resp.choices[0].message.content)
        
        # Role-based chat (uses dedicated role keys)
        resp = api.chat_with_role("threat_intel_analyst", "Analyze this IOC", "185.220.101.5")
        resp = api.chat_with_role("malware_analyst", "Analyze this behavior", "process injection detected")
        
        # Cybersecurity workflows
        resp = api.chat_with_role("incident_responder", "Respond to this incident", "Ransomware detected on endpoint")
        resp = api.chat_with_role("forensic_investigator", "Investigate this artifact", "Suspicious registry key")
    """

    _ROLE_MAP = {
        "planner": 0,
        "designer": 1,
        "coder": 2,
        "reviewer": 3,
        "reporter": 4,
        "analyst": 5,
        "investigator": 0,
        "threat_intel_analyst": 0,
        "malware_analyst": 1,
        "network_defender": 2,
        "incident_responder": 3,
        "forensic_investigator": 4,
        "vulnerability_researcher": 5,
    }

    def __init__(self, use_mock: bool = False):
        """
        Initialize the API client.
        
        Args:
            use_mock: If True, use MockRoleKeyManager for offline demos.
        """
        if use_mock:
            from key_manager import MockRoleKeyManager
            self._km = MockRoleKeyManager()
        else:
            from key_manager import RoleKeyManager
            self._km = RoleKeyManager()
        
        self._vision_supported = True  # Will be set to False if vision fails

    def _get_client_for_role(self, role: str):
        """Get client for a specific role."""
        role_idx = self._ROLE_MAP.get(role.lower(), 0)
        return self._km.client_for_role(role_idx)

    def _select_model(self, client, model: Optional[str], fallback: str = OMNIROUTE_MODEL) -> str:
        """Select the correct model name based on client type."""
        if model:
            return model
        if hasattr(client, 'models') and hasattr(client.models, '_pick_canned'):
            return OMNIROUTE_MODEL
        if _GENAI_AVAILABLE and _genai is not None:
            try:
                if isinstance(client, _genai.Client):
                    return GEMINI_MODEL
            except Exception:
                pass
        return fallback

    def _build_contents(self, system: str, user: str, vision_parts: Optional[List] = None):
        """Build contents array compatible with both OmniRoute shim and Gemini."""
        if vision_parts is None:
            vision_parts = []
        
        parts = []
        for vp in vision_parts:
            parts.append(vp)
        parts.append(_SimplePart(text=user))
        
        contents = [{"role": "user", "parts": parts}]
        return contents

    def chat(self, system: str, user: str, model: str = None, temperature: float = 0.3, 
             top_p: float = 0.9, max_retries: int = 3) -> _SimpleResponse:
        """
        Simple chat completion - uses the default role (coder) or pool.
        
        Args:
            system: System prompt
            user: User prompt
            model: Model override (ignored, uses OMNIROUTE_MODEL)
            temperature: Sampling temperature
            top_p: Top-p sampling
            max_retries: Max retry attempts
            
        Returns:
            _SimpleResponse with .choices[0].message.content
        """
        client, label = self._get_client_for_role("coder")
        
        # Build proper Gemini config
        if _GENAI_AVAILABLE:
            config = _genai_types.GenerateContentConfig(
                system_instruction=system,
                temperature=temperature,
                top_p=top_p,
                tools=None,
            )
        else:
            class _Cfg:
                def __init__(self, system_instruction, temperature, top_p):
                    self.system_instruction = system_instruction
                    self.temperature = temperature
                    self.top_p = top_p
                    self.tools = None
                    self.model_copy = None
            config = _Cfg(system, temperature, top_p)
        contents = self._build_contents(system, user)
        
        last_error = None
        backoff = 1.0
        
        for attempt in range(max_retries):
            try:
                response = client.models.generate_content(
                    model=self._select_model(client, model),
                    contents=contents,
                    config=config
                )
                text = "".join(p.text or "" for p in response.candidates[0].content.parts)
                if not text.strip():
                    text = "[The model returned an empty response. Please rephrase your request.]"
                return _SimpleResponse(text, model=label)
            except Exception as e:
                last_error = e
                error_code = getattr(e, "code", None) or getattr(e, "status_code", None)
                is_rate_limit = error_code == 429 or "429" in str(e) or "rate" in str(e).lower()
                
                if is_rate_limit and attempt < max_retries - 1:
                    time.sleep(min(backoff, 32))
                    backoff *= 2
                    continue
                raise
        
        raise RuntimeError(f"All retries exhausted: {last_error}")

    def chat_with_role(self, role: str, system: str, user: str, 
                       temperature: float = 0.3, top_p: float = 0.9,
                       max_retries: int = 3) -> _SimpleResponse:
        """
        Chat completion with a specific role (planner, designer, coder, reviewer, reporter, analyst).
        
        Each role uses its dedicated API key for consistent behavior and quota isolation.
        
        Args:
            role: One of "planner", "designer", "coder", "reviewer", "reporter", "analyst"
            system: System prompt
            user: User prompt
            temperature: Sampling temperature
            top_p: Top-p sampling
            max_retries: Max retry attempts
        """
        client, label = self._get_client_for_role(role)
        
        if _GENAI_AVAILABLE:
            config = _genai_types.GenerateContentConfig(
                system_instruction=system,
                temperature=temperature,
                top_p=top_p,
                tools=None,
            )
        else:
            class _Cfg:
                def __init__(self, system_instruction, temperature, top_p):
                    self.system_instruction = system_instruction
                    self.temperature = temperature
                    self.top_p = top_p
                    self.tools = None
                    self.model_copy = None
            config = _Cfg(system, temperature, top_p)
        contents = self._build_contents(system, user)
        
        last_error = None
        backoff = 1.0
        
        for attempt in range(max_retries):
            try:
                response = client.models.generate_content(
                    model=self._select_model(client, None),
                    contents=contents,
                    config=config
                )
                text = "".join(p.text or "" for p in response.candidates[0].content.parts)
                if not text.strip():
                    text = "[The model returned an empty response. Please rephrase your request.]"
                return _SimpleResponse(text, model=label)
            except Exception as e:
                last_error = e
                err_str = str(e)
                # Gemini-specific: model returned no content — don't retry, return gracefully
                if "model output" in err_str.lower() or "output text" in err_str.lower():
                    return _SimpleResponse(
                        "[The model returned an empty response — the prompt may have triggered a safety filter. "
                        "Try rephrasing your request.]",
                        model=label,
                    )
                error_code = getattr(e, "code", None) or getattr(e, "status_code", None)
                is_rate_limit = error_code == 429 or "429" in err_str or "rate" in err_str.lower()
                
                if is_rate_limit and attempt < max_retries - 1:
                    time.sleep(min(backoff, 32))
                    backoff *= 2
                    continue
                raise
        
        raise RuntimeError(f"All retries exhausted for role {role}: {last_error}")

    def chat_vision(self, system: str, user: str, image_bytes: bytes, 
                    mime_type: str = "image/png", temperature: float = 0.3,
                    max_retries: int = 3) -> _SimpleResponse:
        """
        Vision/multimodal chat completion.
        
        Args:
            system: System prompt
            user: User prompt
            image_bytes: Raw image bytes
            mime_type: MIME type (image/png, image/jpeg, etc.)
            temperature: Sampling temperature
            max_retries: Max retry attempts
        """
        client, label = self._get_client_for_role("coder")  # Vision uses coder role
        
        vision_part = _make_vision_part(image_bytes, mime_type)
        
        if _GENAI_AVAILABLE:
            config = _genai_types.GenerateContentConfig(
                system_instruction=system,
                temperature=temperature,
                top_p=0.9,
                tools=None,
            )
        else:
            class _Cfg:
                def __init__(self, system_instruction, temperature, top_p):
                    self.system_instruction = system_instruction
                    self.temperature = temperature
                    self.top_p = top_p
                    self.tools = None
                    self.model_copy = None
            config = _Cfg(system, temperature, 0.9)
        contents = self._build_contents(system, user, [vision_part])
        
        last_error = None
        backoff = 1.0
        
        for attempt in range(max_retries):
            try:
                response = client.models.generate_content(
                    model=self._select_model(client, None),
                    contents=contents,
                    config=config
                )
                text = "".join(p.text or "" for p in response.candidates[0].content.parts)
                return _SimpleResponse(text, model=label)
            except Exception as e:
                last_error = e
                error_code = getattr(e, "code", None) or getattr(e, "status_code", None)
                is_rate_limit = error_code == 429 or "429" in str(e) or "rate" in str(e).lower()
                
                if is_rate_limit and attempt < max_retries - 1:
                    time.sleep(min(backoff, 32))
                    backoff *= 2
                    continue
                # If vision fails, mark as unsupported and raise
                self._vision_supported = False
                raise
        
        raise RuntimeError(f"Vision request failed after retries: {last_error}")

    def chat_json(self, system: str, user: str, schema: dict = None,
                  role: str = "coder", temperature: float = 0.1) -> _SimpleResponse:
        """
        Chat completion that expects JSON output.
        
        Args:
            system: System prompt (should instruct JSON output)
            user: User prompt
            schema: Optional JSON schema for validation
            role: Role to use
            temperature: Low temperature for deterministic JSON
        """
        # Add JSON instruction to system prompt
        json_instruction = "\n\nRespond ONLY with valid JSON. No markdown, no explanation."
        if schema:
            import json
            json_instruction += f"\nSchema: {json.dumps(schema)}"
        
        return self.chat_with_role(role, system + json_instruction, user, temperature=temperature)

    def get_status(self) -> dict:
        """Get status of all keys (OmniRoute + Gemini fallback)."""
        return {
            "keys": self._km.status(),
            "omniroute_available": any(k.get("label") == "omniroute" and k.get("available") for k in self._km.status()),
            "mode": "omniroute" if any(k.get("label") == "omniroute" for k in self._km.status()) else "gemini_fallback"
        }

    @staticmethod
    def create_mock() -> "AiApi":
        """Create an AiApi instance in demo/mock mode (no API keys needed)."""
        return AiApi(use_mock=True)


# Backward compatibility - simple function interface
def quick_chat(prompt: str, system: str = "You are a helpful assistant.") -> str:
    """Quick one-liner for simple prompts. Returns text directly."""
    api = AiApi()
    resp = api.chat(system, prompt)
    return resp.choices[0].message.content


def quick_code(prompt: str, system: str = "You are an expert programmer.") -> str:
    """Quick code generation using coder role."""
    api = AiApi()
    resp = api.chat_with_role("coder", system, prompt)
    return resp.choices[0].message.content


def quick_plan(prompt: str, system: str = "You are a strategic planner.") -> str:
    """Quick planning using planner role."""
    api = AiApi()
    resp = api.chat_with_role("planner", system, prompt)
    return resp.choices[0].message.content
