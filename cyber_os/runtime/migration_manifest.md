# HackerAI → SVS-Cyber Pentester Migration Manifest

## Legal Notes
- HackerAI LICENSE: Apache 2.0 with commercial-use restriction — contact contact@hackerai.co for commercial license
- THIRD_PARTY_NOTICES.md: Strix skills (Apache 2.0), no other third-party notices found
- Preserved: All legal notices, LICENSE, THIRD_PARTY_NOTICES.md
- Removed: HackerAI branding, product names, marketing pages

---

## MIGRATION MAP

### `app/` — Next.js Application Layer

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
app/(chat)/c/[id]/page.tsx          pentester/app/(chat)/...  ADAPT        Keep chat UI, replace Convex with SVS event bus
app/(chat)/c/[id]/loading.tsx       pentester/app/(chat)/...  MIGRATE      Keep loading UI
app/(chat)/c/[id]/not-found.tsx     pentester/app/(chat)/...  MIGRATE      Keep 404 handling
app/(chat)/layout.tsx               pentester/app/(chat)/...  ADAPT        Replace Convex providers with SVS context
app/(chat)/layout.css               pentester/app/(chat)/...  MIGRATE      Keep styles
app/(chat)/agent-auto-review/       pentester/app/(chat)/...  ADAPT        Replace auto-review with SVS guardrails
app/(chat)/agent-auto-review/       pentester/app/(chat)/...  ADAPT        Replace auto-review with SVS guardrails
app/(chat)/agent-auto-review/       pentester/app/(chat)/...  ADAPT        Replace auto-review with SVS guardrails
app/(chat)/agent-auto-review/       pentester/app/(chat)/...  ADAPT        Replace auto-review with SVS guardrails
app/(chat)/agent-auto-review/       pentester/app/(chat)/...  ADAPT        Replace auto-review with SVS guardrails
app/(chat)/agent-auto-review/       pentester/app/(chat)/...  ADAPT        Replace auto-review with SVS guardrails
app/(chat)/agent-auto-review/       pentester/app/(chat)/...  ADAPT        Replace auto-review with SVS guardrails
app/(chat)/agent-auto-review/       pentester/app/(chat)/...  ADAPT        Replace auto-review with SVS guardrails
app/(chat)/agent-auto-review/       pentester/app/(chat)/...  ADAPT        Replace auto-review with SVS guardrails
app/(chat)/agent-auto-review/       pentester/app/(chat)/...  ADAPT        Replace auto-review with SVS guardrails
```

### `app/components/` — React UI Components (446 files total)

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
app/components/chat.tsx             pentester/app/components/ MIGRATE      Replace Convex mutations with SVS event bus
app/components/Messages.tsx         pentester/app/components/ MIGRATE      Replace message types with SVS format
app/components/ChatInput/           pentester/app/components/ MIGRATE      Adapt to SVS WebSocket/streaming
app/components/AgentActivityRow.tsx pentester/app/components/ MIGRATE      Use real SVS events from event_bus
app/components/tools/               pentester/app/components/ MIGRATE        ToolApprovalControls.tsx  MIGRATE      Replace approval with SVS GuardrailManager
app/components/tools/SubagentToolHandler.tsx pentester/...      MIGRATE      Replace with SVS SOC subagent integration
app/components/tools/FileHandler.tsx pentester/...           MIGRATE      Adapt to SVS tool execution
app/components/tools/WebToolHandler.tsx pentester/...        MIGRATE      Adapt to SVS tool execution
app/components/extra-usage/         pentester/...             REMOVE       HackerAI pricing feature
app/components/ModelSelector/       pentester/...             ADAPT        Replace with SVS model selection
app/components/usage/               pentester/...             REMOVE       HackerAI usage tracking
app/components/__mocks__/           pentester/...             REMOVE       Test mocks only
```

### `app/contexts/` — React Context Providers

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
app/contexts/AgentApprovalContext   pentester/app/contexts/  ADAPT        Use SVS GuardrailManager + approval_callback
app/contexts/GlobalState.tsx        pentester/app/contexts/  ADAPT        Replace with SVS state management via event_bus
```

### `app/hooks/` — React Hooks

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
app/hooks/                           pentester/app/hooks/     MIGRATE      Adapt to SVS event system
```

### `lib/chat/` — Chat/Agent Runtime (core logic)

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
lib/chat/chat-processor.ts          pentester/lib/chat/       ADAPT        Replace Convex with SVS InvestigationState
lib/chat/stop-conditions.ts         pentester/lib/chat/       MIGRATE      Keep stop conditions, adapt to SVS
lib/chat/doom-loop-detection.ts     pentester/lib/chat/       MIGRATE      Keep doom loop detection
lib/chat/budget-monitor.ts          pentester/lib/chat/       ADAPT        Replace with SVS cost tracking
lib/chat/agent-approval-authorization.ts pentester/lib/chat/  ADAPT        Replace with SVS GuardrailManager
lib/chat/agent-auto-review.ts       pentester/lib/chat/       ADAPT        Replace auto-review model with SVS AiApi
lib/chat/agent-auto-review-evidence.ts pentester/lib/chat/   MIGRATE      Keep evidence extraction logic
lib/chat/agent-routing.ts           pentester/lib/chat/       REMOVE       HackerAI desktop routing not needed
lib/chat/agent-run-spend-cap.ts     pentester/lib/chat/       ADAPT        Replace with SVS budget limits
lib/chat/agent-run-timing.ts        pentester/lib/chat/       MIGRATE      Keep timing logic
lib/chat/agent-long-content-sequence-guard.ts pentester/...    MIGRATE      Keep guard logic
lib/chat/agent-long-heartbeat.ts    pentester/lib/chat/       MIGRATE      Keep heartbeat
lib/chat/agent-long-memory-telemetry.ts pentester/...         MIGRATE      Keep telemetry
lib/chat/agent-long-message-progress.ts pentester/...         MIGRATE      Keep progress
lib/chat/agent-long-provider-retry.ts pentester/...          MIGRATE      Keep retry logic
lib/chat/agent-long-realtime-sanitizer.ts pentester/...      MIGRATE      Keep sanitization
lib/chat/agent-long-tool-input-dedup.ts pentester/...        MIGRATE      Keep dedup logic
lib/chat/agent-long-transport.ts    pentester/lib/chat/       MIGRATE      Keep transport
lib/chat/abliteration-vision.ts     pentester/lib/chat/       REMOVE       HackerAI-specific abliteration
lib/chat/abort-persistence.ts       pentester/lib/chat/       MIGRATE      Keep abort persistence
lib/chat/active-runtime-budget.ts   pentester/lib/chat/       ADAPT        Replace with SVS budget
lib/chat/agent-approval-grants.ts   pentester/lib/chat/       ADAPT        Replace with SVS approval grants
lib/chat/agent-approval-session.ts  pentester/lib/chat/       ADAPT        Replace with SVS approval session
lib/chat/background-work-drain.ts   pentester/lib/chat/       MIGRATE      Keep background work drain
lib/chat/compaction/prune-tool-outputs.ts pentester/...       MIGRATE      Keep compaction logic
lib/chat/message-reconciliation.ts  pentester/lib/chat/       MIGRATE      Keep reconciliation
lib/chat/multimodal-tool-result-recovery.ts pentester/...    MIGRATE      Keep multimodal recovery
lib/chat/platform-authorization.ts  pentester/lib/chat/       ADAPT        Replace with SVS platform auth
lib/chat/post-summarization-continuation.ts pentester/...    MIGRATE      Keep continuation logic
lib/chat/project-context.ts         pentester/lib/chat/       MIGRATE      Keep project context
lib/chat/provider-metadata-sanitizer.ts pentester/...         MIGRATE      Keep sanitization
lib/chat/summarization/            pentester/lib/chat/       MIGRATE      Keep summarization
lib/chat/tool-abort-utils.ts       pentester/lib/chat/       MIGRATE      Keep abort utils
lib/chat/trigger-browser-realtime.ts pentester/...           REMOVE       HackerAI desktop trigger
```

### `lib/api/` — API Routes

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
lib/api/agent-stream-runner.ts      pentester/lib/api/        ADAPT        Replace OpenRouter with SVS model gateway
lib/api/chat-handler.ts             pentester/lib/api/        ADAPT        Replace Convex with SVS backend
lib/api/chat-stream-helpers.ts      pentester/lib/api/        ADAPT        Replace OpenRouter helpers with SVS
lib/api/chat-request-validation.ts  pentester/lib/api/        MIGRATE      Keep validation logic
lib/api/agent-approval-route.ts     pentester/lib/api/        ADAPT        Replace with SVS approval API
lib/api/agent-approval-session.ts   pentester/lib/api/        ADAPT        Replace with SVS approval session
lib/api/agent-cancel-route.ts       pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/agent-deletion-cleanup.ts   pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/agent-endpoints.ts          pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/agent-partial-save-route.ts pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/agent-resume-route.ts       pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/agent-route-errors.ts       pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/agent-run-correlation.ts    pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/agent-status-route.ts       pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/agent-trigger-route.ts      pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/agent-auto-review-route.ts  pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/openrouter-metadata.ts      pentester/lib/api/        REMOVE       OpenRouter-specific
lib/api/paid-daily-free-allowance-rescue.ts pentester/...     REMOVE       HackerAI billing
lib/api/provider-content-blocked-refund.ts pentester/...      REMOVE       HackerAI billing
lib/api/provider-terminal-error.ts  pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/response.ts                 pentester/lib/api/        REMOVE       HackerAI-specific
lib/api/trigger-region.ts           pentester/lib/api/        REMOVE       HackerAI-specific
```

### `lib/ai/` — AI/Model Layer

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
lib/ai/providers.ts                 pentester/lib/ai/         ADAPT        Replace OpenRouter with SVS OmniRoute/Gemini
lib/ai/abliteration.ts              pentester/lib/ai/         REMOVE       HackerAI-specific
lib/ai/abliteration-media.ts        pentester/lib/ai/         REMOVE       HackerAI-specific
lib/ai/kimi-reasoning.ts            pentester/lib/ai/         REMOVE       HackerAI-specific
lib/ai/openrouter-attribution.ts    pentester/lib/ai/         REMOVE       OpenRouter-specific
lib/ai/output-limits.ts             pentester/lib/ai/         MIGRATE      Keep output limits
lib/ai/provider-response-guard.ts   pentester/lib/ai/         MIGRATE      Keep response guard
lib/ai/tool-call-id-namespace.ts    pentester/lib/ai/         MIGRATE      Keep namespace logic
lib/ai/subagents/contracts.ts       pentester/lib/ai/         MIGRATE      Adapt to SVS SOC agents
lib/ai/subagents/parent-delivery.ts pentester/lib/ai/         ADAPT        Replace with SVS subagent integration
lib/ai/tools/index.ts               pentester/lib/ai/         ADAPT        Replace with SVS ToolRegistry
lib/ai/tools/schemas.ts             pentester/lib/ai/         ADAPT        Replace with SVS ToolDefinition
lib/ai/tools/utils/                 pentester/lib/ai/         ADAPT        Adapt to SVS tool execution
```

### `lib/` — Library Code (non-UI)

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
lib/system-prompt.ts                pentester/lib/            ADAPT        Replace with SVS system prompt
lib/utils.ts                        pentester/lib/            MIGRATE      Keep utility functions
lib/constants/s3.ts                 pentester/lib/            REMOVE       HackerAI S3 config
lib/db/                             pentester/lib/            REMOVE       Convex DB — replaced by SVS
lib/auth/                           pentester/lib/            REMOVE       HackerAI auth — replaced by SVS
lib/billing/                        pentester/lib/            REMOVE       HackerAI billing
lib/analytics/                      pentester/lib/            REMOVE       HackerAI analytics
lib/centrifugo/                     pentester/lib/            REMOVE       HackerAI real-time (use SVS event_bus)
lib/pricing/                        pentester/lib/            REMOVE       HackerAI pricing
lib/privacy/                        pentester/lib/            REMOVE       HackerAI privacy
lib/rate-limit/                     pentester/lib/            REMOVE       HackerAI rate limiting
lib/referrals/                      pentester/lib/            REMOVE       HackerAI referrals
lib/research/                       pentester/lib/            REMOVE       HackerAI research
lib/seo/                            pentester/lib/            REMOVE       HackerAI SEO
lib/storage/                        pentester/lib/            REMOVE       HackerAI storage
lib/experiments/                    pentester/lib/            REMOVE       HackerAI experiments
lib/feedback/                       pentester/lib/            REMOVE       HackerAI feedback
lib/moderation.ts                   pentester/lib/            ADAPT        Replace with SVS content policy
lib/usage-tracker.ts                pentester/lib/            REMOVE       HackerAI usage tracking
lib/token-limits.ts                 pentester/lib/            MIGRATE      Keep token limit logic
lib/token-utils.ts                  pentester/lib/            MIGRATE      Keep token utilities
```

### `lib/ai/tools/` — Tool Implementations

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
lib/ai/tools/file.ts                pentester/lib/ai/tools/  ADAPT        Adapt to SVS workspace tools
lib/ai/tools/web-search.ts          pentester/lib/ai/tools/  ADAPT        Adapt to SVS threat intel tools
lib/ai/tools/notes.ts               pentester/lib/ai/tools/  REMOVE       HackerAI notes — not needed
lib/ai/tools/todo-write.ts          pentester/lib/ai/tools/  REMOVE       HackerAI todos — not needed
lib/ai/tools/subagent-tools.ts      pentester/lib/ai/tools/  ADAPT        Adapt to SVS SOC subagents
lib/ai/tools/subagent-skill-tools.ts pentester/lib/ai/tools/ ADAPT        Adapt to SVS skill system
lib/ai/tools/open-url.ts            pentester/lib/ai/tools/  REMOVE       HackerAI-specific
lib/ai/tools/run-terminal-cmd.ts    pentester/lib/ai/tools/  ADAPT        Adapt to SVS shell execution
lib/ai/tools/interact-terminal-session.ts pentester/...       ADAPT        Adapt to SVS terminal
lib/ai/tools/get-terminal-files.ts  pentester/lib/ai/tools/  ADAPT        Adapt to SVS file listing
lib/ai/tools/prompt-serialization.ts pentester/lib/ai/tools/ MIGRATE      Keep serialization logic
lib/ai/tools/tool-brief.ts          pentester/lib/ai/tools/  MIGRATE      Keep tool brief logic
lib/ai/tools/tool-failure.ts        pentester/lib/ai/tools/  MIGRATE      Keep failure handling
lib/ai/tools/schemas.ts             pentester/lib/ai/tools/  ADAPT        Replace with SVS schemas
lib/ai/tools/index.ts               pentester/lib/ai/tools/  ADAPT        Replace with SVS registry
```

### `packages/local/` — Local Packages

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
packages/local/src/index.ts         pentester/packages/       ADAPT        Adapt to SVS package system
packages/local/src/centrifugo-      pentester/packages/       REMOVE       HackerAI real-time
packages/local/src/process-runner.ts pentester/packages/      ADAPT        Adapt to SVS process management
```

### `trigger/` — Trigger.dev Tasks

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
trigger/agent-long.ts               pentester/trigger/        ADAPT        Replace Trigger.dev with SVS task queue
trigger/agent-long-tag-updates.ts   pentester/trigger/        REMOVE       HackerAI-specific
trigger/streams.ts                  pentester/trigger/        REMOVE       HackerAI-specific
trigger/subagent.ts                 pentester/trigger/        REMOVE       HackerAI-specific
trigger/user-research.ts            pentester/trigger/        REMOVE       HackerAI research
trigger/stream-ids.ts               pentester/trigger/        REMOVE       HackerAI-specific
trigger/config.ts                   pentester/trigger/        REMOVE       HackerAI-specific
```

### `types/` — TypeScript Types

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
types/agent.ts                      pentester/types/          MIGRATE      Adapt to SVS agent types
types/chat.ts                       pentester/types/          MIGRATE      Adapt to SVS chat types
types/file.ts                       pentester/types/          MIGRATE      Adapt to SVS file types
types/user.ts                       pentester/types/          REMOVE       HackerAI user system
types/index.ts                      pentester/types/          MIGRATE      Adapt to SVS type system
```

### `scripts/` — Build/Setup Scripts

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
scripts/setup.ts                    pentester/scripts/        REMOVE       HackerAI setup
scripts/test-abliteration.ts        pentester/scripts/        REMOVE       HackerAI test
scripts/create-test-users.ts        pentester/scripts/        REMOVE       HackerAI test users
```

### Root Config Files

```
SOURCE                              DESTINATION              ACTION       SVS INTEGRATION
──────────────────────────────────── ──────────────────────── ──────────── ────────────────────────────────
LICENSE                             pentester/LICENSE         PRESERVE   Apache 2.0 with commercial restriction
THIRD_PARTY_NOTICES.md              pentester/THIRD_PARTY     PRESERVE   Strix skills notice
next.config.ts                      pentester/next.config.ts  ADAPT        Remove HackerAI-specific config
package.json                        pentester/package.json    ADAPT        Remove HackerAI deps, add SVS
tsconfig.json                       pentester/tsconfig.json   MIGRATE      Keep TS config
tailwind.config.ts                  pentester/tailwind.config MIGRATE      Keep Tailwind
postcss.config.mjs                  pentester/postcss.config  MIGRATE      Keep PostCSS
```

---

## SUMMARY COUNTS

```
HackerAI source files: ~1,000+
  ├── Migrate (keep, adapt):     ~300 files
  ├── Adapt (replace integration): ~200 files
  ├── Remove (HackerAI-specific):  ~400 files
  └── Preserve (legal/config):     ~5 files
```

---

## SVS COMPONENT INTEGRATION MAP

```
HACKERAI SOURCE              SVS COMPONENT
──────────────────────────── ──────────────────────────────
lib/ai/providers.ts          → key_manager.py (AiApi)
lib/chat/chat-processor.ts   → cyber_os/runtime/context_builder.py
lib/chat/stop-conditions.ts  → cyber_os/runtime/agent_loop.py
lib/chat/doom-loop-detection → cyber_os/runtime/agent_loop.py
lib/chat/budget-monitor.ts   → cyber_tools.py (AuditLogger)
lib/ai/tools/index.ts        → cyber_tools.py (ToolRegistry)
lib/ai/tools/schemas.ts      → cyber_tools.py (ToolDefinition)
lib/chat/agent-approval-*    → cyber_tools.py (GuardrailManager)
lib/chat/agent-auto-review   → key_manager.py (AiApi roles)
lib/db/                      → cyber_db/ (SVS schemas)
lib/auth/                    → cyber_soc_engine/core/auth/
lib/analytics/               → cyber_os/telemetry.py
app/contexts/GlobalState     → ui/event_bus.py
app/components/chat.tsx      → cyber_desktop.py (PySide6 UI)
```

---

## REMOVAL CHECKLIST (HackerAI-specific)

- [ ] HackerAI branding, logos, product names
- [ ] Pricing/subscription UI
- [ ] Stripe/billing integration
- [ ] HackerAI key system
- [ ] Account-specific infrastructure
- [ ] Marketing pages
- [ ] HackerAI analytics
- [ ] SaaS-specific infrastructure
- [ ] HackerAI cloud services
- [ ] Convex database integration
- [ ] OpenRouter provider integration
- [ ] Trigger.dev task runner
- [ ] HackerAI desktop (Tauri) routing
- [ ] WorkOS auth integration
- [ ] HackerAI-specific API routes
```

## SVS INTEGRATION CHECKLIST

- [ ] Connect to SVS Key Manager (OmniRoute + Gemini fallback)
- [ ] Connect to SVS PolicyEngine
- [ ] Connect to SVS GuardrailManager
- [ ] Connect to SVS AuditLogger
- [ ] Connect to SVS InvestigationState
- [ ] Connect to SVS EventBus
- [ ] Connect to SVS ToolRegistry
- [ ] Connect to SVS ToolOrchestrator
- [ ] Connect to SVS SOC subagents
- [ ] Wire real backend events (no fake tool activity)
```