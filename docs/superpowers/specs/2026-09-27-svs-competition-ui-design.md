# SVS-Cyber Competition UI Design

## Intent and scope

SVS-Cyber should feel as polished as the HackerAI reference while being clearer for a live school competition demonstration in Oman. Assume judges may type their own prompts. The primary surface is the local chat workspace: landing state, investigation history, conversation, agent activity, tool evidence, approvals, and a focused right panel. Preserve SVS-Cyber branding and its defensive-security purpose. HackerAI's billing, account, team, cloud sandbox, and hosted analytics screens are outside this scope.

`HackerAI-Source/` remains a read-only visual and interaction reference. All shipped code belongs under `ui/hackerai/` or the SVS Python backend. Do not introduce runtime imports or paths into either reference checkout. Preserve the current dirty worktree's unrelated changes and leave `.kilocode` alone.

## Experience

The landing view uses HackerAI's visual language: dark neutral theme, restrained typography, spacious central content, glass composer, compact controls, responsive left sidebar, and smooth but subtle transitions. Distinctive SVS elements make the security workflow easier to understand: a clear connection indicator, evidence-oriented tool cards, human approval cards, and a concise investigation summary. The ordinary chat state prioritizes readable user and assistant messages and keeps agent activity available without drowning the answer.

Controls must state what they actually do. The backend currently supports automatic model routing only; the selector must show only that executable choice. A file attachment control stays disabled until an upload API exists. Ask and Agent modes must not imply separate behavior unless the backend implements it. Cancellation, approvals, session history, search, and tool details must use real API state. No simulated token streaming: the backend emits progress events through WebSocket and a completed response through HTTP/WebSocket.

## Architecture and data flow

The Next.js chat routes remain `/` and `/c/[id]`. `StaiChatWorkspace` owns session state and coordinates the SVS API client, while presentation is split into focused sidebar, header, and transcript components. The API client uses `NEXT_PUBLIC_BACKEND_ORIGIN` for HTTP and `/ws` for events. The FastAPI server wraps `CyberAgent`, records conversations, forwards the event bus, and handles cancellation and approval responses. Event identifiers and session identifiers prevent duplicate or cross-session rendering.

The UI keeps the existing HackerAI-derived primitives and styling already copied into `ui/hackerai`; it does not copy the reference tree wholesale. The backend remains the source of truth for supported capabilities, tool execution, approvals, findings, and run status. Components receive normalized view models rather than importing Python concepts or hosted HackerAI services.

## Reliability and accessibility

The workspace must handle backend disconnected, slow response, empty history, approval pending, tool failure, and cancellation clearly. Reconnect should not duplicate messages. Keyboard send and stop must work without hijacking text copying. Sidebar and panels must remain usable on mobile and narrow desktop windows. Status and error messages use accessible labels; motion respects reduced-motion settings.

## Verification

Use focused tests for event/session/cancellation contracts and presentation state, then run frontend lint/typecheck and relevant Python tests. Launch the local stack and inspect the landing, chat, mobile layout, agent activity, approval, tool failure, and disconnect states visually where practical. Never claim an execution occurred based on UI animation alone.
