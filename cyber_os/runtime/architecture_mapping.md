# HackerAI → SVS-Cyber Architecture Mapping

## Purpose
Maps HackerAI's agent loop, context system, tool architecture, and UI patterns to SVS-Cyber equivalents for migration to `I:\STAI 2\pentester`.

## Legal Status
- HackerAI LICENSE: Apache 2.0 with commercial-use restriction (requires commercial license from HackerAI, LLC for paid services)
- THIRD_PARTY_NOTICES.md: Not yet inspected
- Migration for internal/authorized use only; commercial redistribution prohibited

---

## Component Mapping

### 1. Agent Loop
| HackerAI | SVS-Cyber | Notes |
|----------|-----------|-------|
| `lib/api/agent-stream-runner.ts` - `createAgentStream()` | `cyber_os/runtime/agent_loop.py` - `AgentLoop` | Both implement multi-step tool loop with stop conditions |
| `streamText()` from AI SDK | `CyberAgent.process_chat_command()` | SVS uses direct model calls, not streaming SDK |
| `prepareStep` callback | `AgentLoop.prepare_step()` | Both handle context prep before each model call |
| `onStepFinish` callback | `AgentLoop.on_step_finish()` | Both handle post-step processing |
| `experimental_onStepStart` | `AgentLoop.on_step_start()` | Hook for step lifecycle |

### 2. Stop Conditions
| HackerAI | SVS-Cyber | Notes |
|----------|-----------|-------|
| `lib/chat/stop-conditions.ts` | `cyber_os/runtime/agent_loop.py` - stop checks | Doom loop, token exhaustion, elapsed timeout, budget |
| `stepLimitReached()` | `AgentLoop._check_step_limit()` | 500 steps agent mode |
| `tokenExhaustedAfterSummarization()` | `AgentLoop._check_token_exhaustion()` | Context window management |
| `elapsedTimeExceeds()` | `AgentLoop._check_elapsed_timeout()` | 10-minute max stream duration |
| `doomLoopDetected()` | `AgentLoop._check_doom_loop()` | Consecutive repetitive tool calls |
| `BUDGET_EXHAUSTION_FINISH_REASON` | `AgentLoop._check_budget()` | Cost tracking per run |
| `AGENT_RUN_SPEND_CAP_FINISH_REASON` | `AgentLoop._check_spend_cap()` | Per-run spend limit |

### 3. Context Construction
| HackerAI | SVS-Cyber | Notes |
|----------|-----------|-------|
| `lib/chat/chat-processor.ts` - `processChatMessages()` | `cyber_os/runtime/context_builder.py` - `ContextBuilder` | Both build model-ready message arrays |
| `fixIncompleteMessageParts()` | `ContextBuilder.fix_incomplete_parts()` | Handle interrupted streams |
| `stripOriginalContentFromMessages()` | `ContextBuilder.strip_large_outputs()` | Remove bulky file edit outputs |
| `limitImageParts()` | `ContextBuilder.limit_images()` | Cap image attachments |
| `removeDuplicateToolParts()` | `ContextBuilder.dedup_tool_parts()` | Prevent duplicate tool calls |
| `stripProviderMetadata()` | `ContextBuilder.sanitize_anthropic()` | Remove cross-model signature issues |
| `filterUIOnlyParts()` | `ContextBuilder.filter_ui_parts()` | Remove internal data parts |

### 4. Tool System
| HackerAI | SVS-Cyber | Notes |
|----------|-----------|-------|
| `lib/ai/tools/index.ts` - Tool registry | `cyber_tools.py` - `ToolRegistry` | Both register tools by name |
| `ToolDefinition` (schemas.ts) | `ToolDefinition` (cyber_tools.py) | Both have name, description, risk_level |
| `tool-file`, `tool-shell`, `tool-web_search` | `workspace_list_files`, `shell_exec`, `nmap_scan` | SVS has more pentest-specific tools |
| `run_terminal_cmd` | `shell_exec` | Terminal command execution |
| `interact_terminal_session` | `shell_exec` (interactive) | PTY-style interaction |
| `read_file`/`write_file` | `workspace_read_file`/`workspace_list_files` | File operations |
| Subagent tools | `cyber_soc_engine` agents | SVS has built-in SOC agents |

### 5. Approval System
| HackerAI | SVS-Cyber | Notes |
|----------|-----------|-------|
| `lib/chat/agent-approval-authorization.ts` | `cyber_tools.py` - `GuardrailManager` | Both gate sensitive operations |
| `AgentApprovalContext` (React context) | `GuardrailManager.request_approval()` | SVS uses callback-based approval |
| `ToolApprovalControls.tsx` | `cyber_desktop.py` - `ApprovalRequestDialog` | GUI approval dialogs |
| `shouldAutoReviewAgentToolAction()` | `GuardrailManager.auto_approve_read_only` | Auto-approve read-only |
| `AgentAutoReviewDenialTracker` | `AutomatedGuardrailManager` | Track denials, auto-deny after threshold |
| `agentAutoReviewOutputSchema` (Zod) | `GuardrailManager` + policy engine | SVS uses LLM-based review via key_manager |

### 6. System Prompt
| HackerAI | SVS-Cyber | Notes |
|----------|-----------|-------|
| `lib/system-prompt.ts` | `cyber_os/cyber_os_ai.py` - `CyberOSAI` | Both generate role-specific prompts |
| `buildSystemPrompt()` | `CyberOSAI.analyze_threat()` | SVS has cybersecurity-specific templates |
| System prompt injection | `CyberOSAI._analyze_with_template()` | Template-based fallback |

### 7. UI Components
| HackerAI | SVS-Cyber | Notes |
|----------|-----------|-------|
| `app/components/chat.tsx` | `cyber_desktop.py` - `CyberMain` | Both are main chat interfaces |
| `app/components/Messages.tsx` | `cyber_desktop.py` - `ThreadCard` | Message display components |
| `app/components/ChatInput/` | `cyber_desktop.py` - `PromptEdit` | Input area with send button |
| `app/components/AgentActivityRow.tsx` | `cyber_desktop.py` - `_add_activity()` | Activity feed entries |
| `app/components/tools/ToolApprovalControls.tsx` | `cyber_desktop.py` - `_show_approval_dialog()` | Approval UI |
| `app/contexts/AgentApprovalContext.tsx` | `cyber_tools.py` - `GuardrailManager` | State management for approvals |
| `app/contexts/GlobalState.tsx` | `ui/event_bus.py` - `event_bus` | Global state/events |
| `lib/centrifugo/` | `ui/event_bus.py` | Real-time event broadcasting |

### 8. Key Manager / API Keys
| HackerAI | SVS-Cyber | Notes |
|----------|-----------|-------|
| `lib/ai/providers.ts` - `myProvider` | `key_manager.py` - `RoleKeyManager` | Both manage model provider keys |
| OpenRouter routing | OmniRoute primary + Gemini fallback | SVS has explicit fallback chain |
| Model selection (tier-based) | `AiApi._select_model()` | SVS uses role-based model routing |
| `GROK_4_5_SLUG`, `DEEPSEEK_V4_FLASH_SLUG` | `OMNIROUTE_MODEL`, `GEMINI_MODEL` | Model identifier constants |

### 9. Analytics / Telemetry
| HackerAI | SVS-Cyber | Notes |
|----------|-----------|-------|
| `lib/analytics/` - PostHog analytics | `cyber_os/telemetry.py` | Both track agent behavior |
| `agent-step-limit-telemetry` | `cyber_os/telemetry.py` - step metrics | Performance tracking |
| `agent-performance-diagnostics` | `cyber_os/telemetry.py` - diagnostics | Latency tracking |

### 10. Evidence / Audit
| HackerAI | SVS-Cyber | Notes |
|----------|-----------|-------|
| `lib/chat/agent-auto-review-evidence.ts` | `cyber_tools.py` - `AuditLogger` | Both log actions for review |
| `AgentAutoReviewDenialTracker` | `AuditLogger` + `GuardrailManager` | Denial tracking for compliance |
| `agent-auto-review.ts` - REVIEWER_SYSTEM_PROMPT | `cyber_os_ai.py` - incident analysis | SVS uses AI for evidence analysis |

---

## Execution Flow Comparison

### HackerAI Flow
```
User Message → ChatProcessor.processChatMessages()
  → Model Selection (selectModel)
  → Moderation Check
  → streamText() with prepareStep/onStepFinish
    → AgentStreamRunner.createAgentStream()
      → prepareStep: pruneToolOutputs, doomLoopDetection, summarization
      → Provider Call (OpenRouter)
      → onStepFinish: update state, check stop conditions
    → toUIMessageStream
  → UI Update (Messages.tsx)
```

### SVS Flow
```
User Query → CyberMain._submit_prompt()
  → AgentWorker (QRunnable)
    → CyberAgent.process_chat_command()
      → _route_query() → tool execution
      → GuardrailManager.request_approval()
      → event_bus.publish(AgentEvent)
  → UI Update (ThreadCard, timeline)
```

---

## Migration Phases

### Phase 1: Discovery ✓
- [x] HackerAI file inventory
- [x] SVS-Cyber file inventory
- [x] Execution path mapping
- [x] Legal review (LICENSE inspected)

### Phase 2: Architecture Mapping ✓
- [x] Component mapping document
- [x] Execution flow comparison

### Phase 3: Destination Setup (I:\STAI 2\pentester)
- [ ] Create pentester workspace directory
- [ ] Set up core modules (agent loop, context, tools)
- [ ] Integrate SVS Key Manager
- [ ] Integrate PolicyEngine
- [ ] Integrate GuardrailManager
- [ ] Integrate AuditLogger
- [ ] Adapt HackerAI agent loop to SVS
- [ ] Adapt HackerAI context system to SVS
- [ ] Adapt HackerAI UI components to SVS
- [ ] Wire real backend events (event_bus)
- [ ] Approval system with HackerAI features

### Phase 4: Implementation
- [ ] Agent loop with stop conditions
- [ ] Context builder with message sanitization
- [ ] Tool registry with SVS tools
- [ ] Approval gate with auto-review
- [ ] Streaming UI with event bus
- [ ] Key manager integration
- [ ] Audit logging

### Phase 5: Testing & Validation
- [ ] Agent loop tests
- [ ] Tool execution tests
- [ ] Approval flow tests
- [ ] UI event tests
- [ ] Integration tests

---

## Critical Design Decisions

1. **UI Style**: Use HackerAI's chat-centric design, not NVIDIA Agent Toolkit
2. **Backend**: Real SVS backend with event_bus, not fake tool activity
3. **Approval**: HackerAI-style approval gates with SVS guardrails
4. **Keys**: SVS Key Manager (OmniRoute + Gemini fallback), not OpenRouter
5. **Tools**: SVS ToolRegistry with pentest tools, not HackerAI's dev tools
6. **Models**: SVS role-based model routing via AiApi, not HackerAI tier-based
7. **Legal**: Apache 2.0 with commercial restriction - need commercial license for production use