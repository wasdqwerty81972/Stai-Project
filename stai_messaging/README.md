# SVS-Cyber Communications Gateway

The communications gateway extends the existing Python `CyberAgent` through one
authorized inbound path and the application's existing `AgentEventBus`. It does
not create another assistant or agent runtime. The OpenClaw repository was used
as a behavior reference (account-aware adapters, sender authorization, session
identity, and channel-specific delivery). Its TypeScript plugins and gateway
runtime were not copied into this Python application.

## Current support

- **Discord:** implemented as a `discord.py` slash-command bot. It requests no
  privileged message-content intent. Direct messages only.
- **Telegram:** implemented with `python-telegram-bot` asynchronous polling.
  Private chats only; a public webhook mode is not included.
- **Slack and WhatsApp:** not implemented and not advertised as supported.
- **Groups and channels:** disabled to avoid broadcasting one person's
  investigation results to other members.
- **Attachments:** not forwarded to CyberAgent. Unsupported attachments are
  rejected at the gateway.

The adapters and event-routing path have automated mock tests. Live Discord and
Telegram authentication and delivery have not been run because no bot tokens
were supplied.

## Install and configure

Install these optional dependencies into the same Python environment used to
start `ui.api_server:app`:

```powershell
python -m pip install -r requirements-communications.txt
```

Create a Discord application and bot, or create a Telegram bot with BotFather.
Start SVS-Cyber on its default local-only address, open the active SVS-Cyber
workspace, and select the settings gear. Paste each bot token, save it, and
enable its connector. The backend stores tokens through the operating-system
credential vault and never returns them from an API. If no secure vault is
available, credential saving fails rather than writing a plaintext token.

In the bot's private chat, use `/pair`. The request expires after ten minutes.
Review it in Communications settings and approve as **Viewer** or **Analyst**.
Viewers can use `/status` and `/help`; Analysts can send natural-language
messages to the existing CyberAgent. Revoke access from the same settings view.
All message sessions are isolated by platform, bot account, sender, destination,
and thread. Replayed platform message IDs are deduplicated across restarts.

Discord uses `/svs <message>`. Telegram supports `/svs <message>` and ordinary
private-chat text. Existing CyberAgent policy and approval handling remain in
force. Remote messages cannot approve pending actions; approval alerts direct
the user to the local SVS-Cyber UI.

## Notifications

Enable event types and select paired personal destinations in Communications
settings. The gateway listens to the application's real event bus and queues
small generic summaries for incidents, findings, approval requests, agent
errors, and completed investigations. It does not send event details or
hostnames. Delivery runs through a bounded asynchronous queue and retries
transient failures three times; recent delivery state is stored under
`.sessions/` and shown in the settings panel.

Sensor notifications arrive only when the relevant sensor is running and
publishes an event to `ui.event_bus.event_bus`. The API server does not claim that
all sensor engines are active merely because a connector is online.

## Runtime and security

The FastAPI lifecycle starts and stops the optional connectors without delaying
API readiness. Missing credentials or connector dependencies do not prevent the
local application from starting. Discord and Telegram adapters reconnect using
their SDK behavior; the manager retries failed initial connections. The
communications administration endpoints accept loopback clients only. Keep the
SVS-Cyber API bound to `127.0.0.1`; the gateway does not expose a public listener.

Remote messaging works only while the SVS-Cyber host and its network connection
are available. When it is shut down, asleep, or disconnected, bots cannot reach
the local agent. The local agent continues independently if a messaging service
is unavailable. Polling is used for Telegram, so no inbound public webhook or
publicly exposed development server is required.

Delivery status is persisted, while inbound idempotency and identity state are
stored in `.sessions/communications_pairings.json`. Bot tokens are held by the
OS credential vault, not these JSON files. Notification text is intentionally
generic; the local application remains the place to inspect findings and
approve actions.
