# Project Memory

## Architecture
- Python-based cybersecurity AI / SOC engine
- Main entry: `cyber_main.py`, agents in `cyber_agent.py`
- Tools: `cyber_tools.py`, `cyber_tools_toolresult.py`
- Threat intel: `cyber_threat_intel.py`
- Key manager: `key_manager.py`
- UI layer: `ui/`
- Tests: `tests/`, `cyber_main_test.py`, `test_*.py`

## Key Conventions
- Use existing Python patterns; do not introduce new frameworks without discussion
- Never hardcode secrets — use `key_manager.py` or environment variables
- All new features require tests in `tests/`
- Follow PEP 8; run linting before committing

## Known Decisions
- OmniRoute proxy runs on `localhost:20128`
- OpenCode is the primary AI coding tool (not Claude Code CLI)
- ECC harness installed globally at `~/.config/opencode/`

## Active Agents (via ECC)
- `build` — primary coding agent
- `planner` — use before implementing complex features
- `tdd-guide` — use when adding new logic
- `security-reviewer` — use after touching auth/API/input code
