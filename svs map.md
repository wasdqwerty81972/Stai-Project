# HackerAI Frontend Migration Map

`D:\STAI 2\HackerAI-Source` is the read-only reference checkout. The active STAI-2 frontend is
`ui/hackerai`; the Python intelligence layer remains in the repository root and
`ui/api_server.py`.

| HackerAI source | Purpose | STAI-2 destination | Action |
| --- | --- | --- | --- |
| `app/layout.tsx` | App Router root layout and providers | `ui/hackerai/app/layout.tsx` | Keep the App Router shell, remove WorkOS/Convex-only providers as each boundary is adapted |
| `app/(chat)/layout.tsx` | Shared chat route shell | `ui/hackerai/app/(chat)/layout.tsx` | Preserve route structure and responsive shell; replace Convex auth state |
| `app/(chat)/page.tsx` and `c/[id]/page.tsx` | New and existing chat routes | `ui/hackerai/app/(chat)/` | Keep routes; connect history and streaming to STAI-2 |
| `app/components/ChatLayout.tsx`, `Sidebar.tsx` | Sidebar, navigation, responsive layout | `ui/hackerai/app/components/` | Preserve UI behavior; remove billing and hosted-service dependencies |
| `app/components/chat.tsx`, `ChatInput/`, `Messages.tsx` | Composer, messages, streaming presentation | `ui/hackerai/app/components/` | Preserve presentation; use the STAI-2 API client and application events |
| `app/contexts/` | Chat, approval, todo, and stream state | `ui/hackerai/app/contexts/` | Keep only state required by SVS-Cyber and adapt auth/data providers |
| `app/hooks/` | Responsive, streaming, reconnect, and interaction behavior | `ui/hackerai/app/hooks/` | Reuse where backend-neutral; replace Convex-specific hooks |
| `components/ui/` | Radix/shadcn UI primitives | `ui/hackerai/components/ui/` | Keep required primitives; do not copy product-specific infrastructure |
| `app/globals.css` | Theme and application styling | `ui/hackerai/app/globals.css` | Preserve HackerAI-derived styling and adapt product identity only where needed |
| `next.config.ts` | Rewrites and build configuration | `ui/hackerai/next.config.ts` | Route `/api/*` and `/ws` to `NEXT_PUBLIC_BACKEND_ORIGIN` |
| `app/api/chat/**`, `lib/api/chat-handler.ts` | HackerAI AI/Convex backend | `ui/api_server.py` plus a thin frontend adapter | Replace; do not retain OpenRouter/Convex chat execution |
| HackerAI billing, Stripe, WorkOS, Convex, Trigger, hosted analytics | SaaS infrastructure | None | Exclude from the STAI-2 runtime surface |
| HackerAI desktop sandbox relay | Hosted desktop/sandbox service | `cyber_main.py` service manager | Replace with local FastAPI and Next.js process management |

## Runtime Contract

```text
Python desktop/launcher
  -> ui/api_server.py (FastAPI, /health, /api/*, /ws)
  -> CyberAgent, tools, approvals, investigations, event_bus
  -> ui/hackerai (Next.js App Router)
```

The frontend must treat application-level events as public data: agent status,
tool progress/results, approvals, findings, errors, and completion. Private model
chain-of-thought is never rendered. The backend currently emits lifecycle and tool
events but not token deltas; completed responses are rendered as completed output,
never simulated as streaming text. Provider routing is backend-owned, so the model
control exposes only the supported `auto` mode.
