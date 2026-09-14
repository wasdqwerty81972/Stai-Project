# HackerAI → SVS-Cyber Migration Summary

## Objective
Integrate HackerAI's Next.js agent UI/chat implementation into SVS-Cyber's Python-based architecture at `ui/hackerai`.

## Important Details
- HackerAI Next.js frontend at `ui/hackerai/` (App Router structure: app/layout.tsx, app/(chat), components, contexts, hooks, styling)
- Canonical backend: SVS FastAPI server at `ui/api_server.py` provides WebSocket + REST endpoints on port 8000
- Next.js rewrites `/api/*` and `/ws` to `http://127.0.0.1:8000`
- SVS-Cyber is the core intelligence (CyberAgent, ToolRegistry, DoomLoopDetector, Subagents, Policy Engine)

## Work State
### Completed
- Integrated HackerAI Next.js App Router frontend directly at `ui/hackerai`
- Connected HackerAI Next.js chat to SVS-Cyber FastAPI server (`ui/api_server.py`) via Next.js proxy rewrites
- Preserved all 200+ SVS-Cyber tools, subagent framework (13 specialists), policy engine, and approval engine
- Removed obsolete `web/` directory references and ensured `ui/hackerai` is the canonical frontend

## Relevant Files
- I:/STAI 2/ui/hackerai/ - Canonical HackerAI Next.js App Router frontend
- I:/STAI 2/cyber_agent.py - Main orchestrator, publishes context, model, and tool events
- I:/STAI 2/ui/api_server.py - FastAPI WebSocket + REST endpoints (port 8000)
- I:/STAI 2/cyber_main.py - Primary SVS-Cyber launcher