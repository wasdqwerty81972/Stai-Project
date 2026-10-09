# stai_messaging — multi-channel messaging bridge (Idea #10)

Lets the owner message the SVS-Cyber/STAI SOC agent from a chat app and get
replies back. Records research: OpenClaw (`openclaw/openclaw`) ships the channel
adapters as **TypeScript plugins** under `extensions/<channel>/` built on its own
`gateway-protocol`; STAI's backend is Python. So OpenClaw is a **reference**, not
drop-in code — we build thin Python adapters against one shared seam.

## The seam

Every channel normalizes an inbound message into `InboundMessage`, and the bridge:

1. **default-deny allow-list** on `(channel, sender_id)` — unknown senders never reach the agent;
2. maps `(channel, thread)` -> a stable STAI `session_id` (via `session_id_for`);
3. forwards the text to the STAI agent through a `ChatClient` (Phase 2 default:
   `HttpChatClient`, which POSTs to the running UI's `POST /api/chat`);
4. relays the reply back through the channel's `ChannelAdapter`.

This reuses STAI's existing agent, approvals, and safety gating unchanged.

```
platform webhook ──▶ InboundMessage ──▶ MessageBridge ──▶ ChatClient ──▶ STAI agent
                                          │  (allow-list)                  │
                                          ◀──────────── OutboundReply ◀────┘
                                          ▼
                                    ChannelAdapter.send()
```

## Phase 1 (this — shipped, offline)

- `contracts.py` — `InboundMessage`, `OutboundReply`, `ChatClient`, `ChannelAdapter`.
- `bridge.py` — `AllowList` (default-deny, explicit `*` opt-in), `session_id_for`, `MessageBridge`.
- `adapters/mock.py` — `MockChannelAdapter` (records, no I/O).
- `http_chat_client.py` — `HttpChatClient` (stdlib `urllib`; the live `ChatClient`).

No credentials, no listening socket, **no new dependencies**.

## Phase 2+ (owner-secrets-gated — NOT enabled)

One adapter per channel. Recommended order: **Telegram** (free, simplest API) →
**Discord** → **SMS (Twilio)** → **WhatsApp** (Business API, hardest). Each needs
owner-provided secrets, kept out of git and logs; inbound text is **untrusted** and
must never auto-execute a tool (STAI's approval gating stays in force).

## Usage

```python
from stai_messaging import AllowList, InboundMessage, MessageBridge
from stai_messaging.http_chat_client import HttpChatClient

bridge = MessageBridge(
    chat_client=HttpChatClient("http://127.0.0.1:8000"),
    allow_list=AllowList({"telegram": ["<your-telegram-user-id>"]}),
)
# Phase 2 adapter feeds this and delivers the returned OutboundReply:
bridge.handle(InboundMessage("telegram", "<sender>" , "scan 10.0.0.1", thread_id="<chat-id>"), adapter)
```
