# SVS-Cyber / STAI — Master QA Checklist

Living engineering asset maintained by the autonomous daily engineering routine.
Each item records: what is tested, how, expected result, current status, last-verified date, relevant test/file.

- **Baseline established:** 2026-09-29
- **Last routine run:** 2026-10-08 — **No production or test source changed since the 2026-10-07 run** (verified by mtime: newest tracked source is the routine's own `scripts/run-tests.py` @ 2026-10-07; owner production files frozen @ 2026-10-01, messaging bridge @ 2026-10-06), so no change-aware regression work was due. **Tooling-drift check:** all three routine self-tests green — `scripts/select-pytest.selftest.py` (all mapping assertions), `scripts/run-tests.selftest.py` (32/32), `scripts/test-frontend-changed.selftest.mjs` (all mapping assertions). **Security hardening (verified fix, not a refactor):** hardened the Phase-1 messaging-bridge `AllowList` default-deny boundary against a plausible single-user misconfig — `AllowList({"discord": "myid"})` (a bare string instead of a list) previously expanded via `frozenset("myid")` to a *per-character* set, which both **denied the intended operator** and **allowed any single-character sender id**; now a bare `str` is coerced to a single id (`stai_messaging/bridge.py` `AllowList.__init__`, +1 effective line + comment). **Zero production blast radius** — the seam is not wired to any live channel (Phase 1 offline) and every existing caller passes a list (identical behavior). Added **3 regression tests** (bare-string ⇒ one id not characters; list-form unaffected by the guard; empty-string thread ⇒ per-sender session). Verified: `tests/test_messaging_bridge.py` + `tests/test_http_chat_client.py` **26 passed**; **full Python suite 408 passed / 287 subtests, 0 failed (46.2s)** — no regressions (the +3 vs. 2026-10-07's 405 are exactly the new tests). Frontend Jest gate **not due** (no `ui/hackerai` change since 2026-10-07, green then — 5 suites / 13 tests). Independent review delegated to `ecc:security-reviewer` **failed with the recurring 503 gateway error** (`无可用渠道` for `claude-sonnet-5-5` on agentrouter.org — same infra issue as 2026-10-02 / 2026-10-06); substituted a documented manual self-review (change strictly *narrows* the allow set in the misconfig case — tightens, never widens; no `is_allowed` path changed; list/wildcard/empty forms byte-identical). Two follow-up hardening candidates recorded as **IDEAS #11** (strict id validation / fail-loud option; seam-level inbound payload size+type guards).
- **Prior routine run:** 2026-10-07 — **Uncommitted production work appeared since 2026-10-06** (created by the owner's interactive session 2026-10-06 16:05–16:07, *after* the last routine run): the **Idea #10 Phase 1** offline messaging seam (`stai_messaging/` package + `tests/test_messaging_bridge.py`) plus a large uncommitted production diff (796 insertions / 10 core files: `cyber_agent.py`, `cyber_main.py`, `cyber_os/{agent_runtime,subagents/*,tool_orchestrator}.py`, `ui/api_server.py`, `key_manager.py`). Change-aware selector correctly widened to **FULL suite**. Verified green: **full Python suite 397 passed / 287 subtests, 0 failed (64.7s)**; messaging bridge in isolation **15 passed**; frontend gate **5 suites / 13 tests green** (exit 0). **Added regression coverage** `tests/test_http_chat_client.py` (**8 tests green**) pinning the live `HttpChatClient`↔`POST /api/chat` contract — the bridge's Phase-2 `ChatClient`, which its own docstring admitted was "not exercised by the offline unit tests" (request method/URL/Content-Type/JSON body, success `message` extraction, `{"status":"error"}` → `RuntimeError` never masquerading as a reply, non-dict/empty bodies → `""`). **Implemented IDEAS #6** (unified test entrypoint): `scripts/run-tests.py` + `scripts/run-tests.selftest.py` (**32/32 checks green**) — runs both change-aware gates with one aggregate exit status (0 pass / 1 fail / 2 launch-error), forwarding `--files`/`--since` to both so they can never disagree about the input. Verified end-to-end: dry-run prints both plans; real run → `python PASS, frontend PASS, overall PASS`, exit 0. Additive only (no production code touched). Production-diff review delegated to a subagent this run (the `python-reviewer`-style gateway that was 503-dead in prior runs); findings recorded in the daily report.
- **Prior routine run:** 2026-10-06 — **No production source changed since 2026-10-05** (verified by mtime; newest modified tracked source is `tests/test_pytest_configuration.py` @ 2026-10-03), so no change-aware regression work was due. Re-verified the Python security/safety/regression subset green (**159 passed / 75 subtests, 36.7s**: test_defensive_swarm + test_subagent_tool_contract + test_command_classifier + test_tool_call_regressions) — stable, no drift vs the 2026-10-05 run. **Implemented IDEAS #9** (change-aware *Python* test selector): `scripts/select-pytest.py` + `scripts/select-pytest.selftest.py` (**43 assertions green**), the Python mirror of the #1 frontend gate — encodes this file's change→test mapping so per-run selection is reproducible instead of hand-done. Fail-safe: shared/core (`contracts.py`, `pytest.ini`, `conftest.py`, `requirements*.txt`, `tests/__init__.py`) + any unmapped `.py` widen to the FULL suite; frontend/`.stai`/reference-trees/docs are ignored; read-only by default (`--run` executes). Verified: self-test 43/43; `--files`/widen/ignore CLI paths correct; real working-tree plan widened to FULL and named the 4 forcing files. Frontend selector self-test re-run green (no drift). Additive scripts only; no production code touched. Review subagent (python-reviewer) still **503-dead** on the agentrouter.org gateway (same as 2026-10-02) — substituted own verification + the 43-assertion self-test. Also **flagged an undefined, off-mission "Idea #10 multi-channel messaging bridge" next-run note for owner clarification** (see IDEAS.md banner) and did NOT build it (undefined spec + off-mission for a defensive-security SOC tool + pre-deadline attack-surface risk).
- **Prior routine run:** 2026-10-05 — No source changed since 2026-10-03, so no change-aware regression work was due. Re-verified the Python security/safety/regression subset green (**159 passed / 75 subtests, 31.8s**: test_defensive_swarm + test_subagent_tool_contract + test_command_classifier + test_tool_call_regressions). **Implemented the change-aware frontend Jest gate** (`scripts/test-frontend-changed.mjs` + `scripts/test-frontend-changed.selftest.mjs`) — IDEAS #1, the long-standing #1 known gap — and verified it end-to-end (mapping self-test **19/19**; dry-run selected the right 3 patterns from 8 changed files; failure path returns **exit 1**; real run **5 SVS suites / 13 tests green**, exit 0), which also re-verified the frontend baseline. **Profiled** the slow `cyber_tools` import (IDEAS #8) to a precise root cause — eager `openai`/`google.genai` SDK imports at `key_manager.py:86–101`, ~17s, used only at client construction — and recorded a concrete post-deadline lazy-import plan. No production code touched; additive scripts only.
- **Earlier run:** 2026-10-03 — full Python suite surfaced **1 failed, 379 passed, 283 subtests passed** (620s, heavy machine load). Root-caused & fixed (test-only) the one failure: `test_pytest_configuration.py::test_default_collection_is_limited_to_the_project_suite` timed out at 30s because scoped collection legitimately takes ~45-60s (`import cyber_tools` alone is ~29s); scope itself is correct (382 items, 0 out-of-tree leakage). The test now asserts scope *directly* and demotes the timeout to a 240s hang-backstop — re-verified green (20.88s). Also added negative security-boundary coverage (`ScopedToolAllowlistBoundaryTests`): a tool outside a specialist profile's allowlist is never invoked (11 passed / 7 subtests). Both changes test-only; no production code touched. Slow `cyber_tools` import logged as IDEAS.md #8 (profiled 2026-10-05, deferred, pre-deadline).
- **Older run:** 2026-10-02 — full Python suite **379 passed, 283 subtests passed, 0 failed** (126s); frontend Jest scoped to the one changed component **SvsCyberComposer: 1 suite / 5 tests passed** (103s). **Infra issue (still open):** both review subagents (silent-failure-hunter, security-reviewer) failed on the agentrouter.org gateway with `503 … 无可用渠道` (no available channel); security-boundary review done manually.
- **Test runner:** `python -m pytest -q` (config: `pytest.ini`, `testpaths = tests`) · Frontend: `cd ui/hackerai && CI=true npx jest <pattern>`
- **Baseline result:** 334 passed, 277 subtests passed, 0 failed (46s)
- **Python:** 3.11.9 · **Node:** v24.14.1 / npm 11.11.0 (pnpm project, jest)

Status legend: ✅ verified passing · ⚠️ partial / known gap · ❌ failing · ⬜ not yet covered

---

## Environment / setup
| Item | How tested | Expected | Status | Last verified | Test |
|---|---|---|---|---|---|
| Root utility scripts import cleanly | pytest collects & imports root scripts | No ImportError | ✅ | 2026-09-29 | test_root_script_imports.py |
| Default collection stays scoped to `tests/` | Spawns `pytest --collect-only`; asserts an in-suite test is present AND no reference tree (ECC-source/HackerAI-Source/dataxyz/AEGIS_Test/cyber_soc_engine) leaks in | Scoped, 0 leakage; 240s hang-backstop (not a perf budget) | ✅ | 2026-10-03 | test_pytest_configuration.py (HARDENED 2026-10-03) |
| Launcher defaults correct | Regression on SVS-Cyber launcher | Expected defaults | ✅ | 2026-09-29 | test_cyber_main_launcher.py |
| Startup readiness probe (`_http_responded`) | 404/403/500 ⇒ listening; refused/timeout/DNS ⇒ not; frontend gate not on /robots.txt | Any HTTP status = "up"; launcher no longer polls to its 360s timeout | ✅ | 2026-10-02 | test_startup_readiness.py |

## Model loading / provider layer
| Item | How tested | Expected | Status | Last verified | Test |
|---|---|---|---|---|---|
| Gemini key failover on temp provider error | Fake key pool, 503 then success | Advances to next key, recovers | ✅ | 2026-09-29 | test_gemini_failover.py (FIXED 2026-09-29) |
| Provider → role mapping | Role index maps to correct client | Correct provider per role | ✅ | 2026-09-29 | test_provider_role_mapping.py |
| NeMo integration | NeMo provider paths | Expected responses | ✅ | 2026-09-29 | test_nemo_integration.py |
| `model_override` scoping | Set per serialized run, None = default | Attribute honored in chat_with_role | ✅ | 2026-09-29 | key_manager.py:844,993 |

## Core AI functionality / agent loop
| Item | How tested | Expected | Status | Last verified | Test |
|---|---|---|---|---|---|
| Multi-step agent loop behavior | 34 unit cases | Correct step transitions | ✅ | 2026-09-29 | test_agent_runtime_loop.py |
| Agent loop end-to-end | Produces usable investigation | Non-empty structured result | ✅ | 2026-09-29 | test_agent_loop_e2e.py |
| Agent foundation | Core agent construction | Builds & runs | ✅ | 2026-09-29 | test_agent_foundation.py |
| Endpoint pipeline | Endpoint processing path | Expected flow | ✅ | 2026-09-29 | test_endpoint_pipeline.py |

## Tool calling / registry
| Item | How tested | Expected | Status | Last verified | Test |
|---|---|---|---|---|---|
| Tool registry consistency (hardcoded names exist) | AST scan + live registry | Every hardcoded tool is registered | ✅ | 2026-09-29 | test_tool_registry_consistency.py |
| Profiles non-empty (except advisory-only) | Iterates profile allowlists | All have tools except NETWORK_CONTAINMENT_ADVISOR | ✅ | 2026-09-29 | test_tool_registry_consistency.py (FIXED 2026-09-29) |
| `register_all_default_tools` single definition | AST | Exactly one definition | ✅ | 2026-09-29 | test_tool_registry_consistency.py |
| Threat-intel tools survived dedup | Live registry lookup | abuseipdb/shodan/urlscan/vt present | ✅ | 2026-09-29 | test_tool_registry_consistency.py |
| Tool recognition | Agent sees all registered tools | All recognized | ✅ | 2026-09-29 | test_tool_recognition.py |
| Missing binary → fact not crash | Absent tool invocation | Graceful "not available" | ✅ | 2026-09-29 | test_tool_absence.py |
| execute_tool success propagation | Success flag flows to caller | Correct status | ✅ | 2026-09-29 | test_execute_tool_success_propagation.py |
| Unified shell_exec | 27 unit cases | Correct exec/parse/limits | ✅ | 2026-09-29 | test_shell_exec.py |
| Path extraction acts on named file | 14 cases | Uses the file the user named | ✅ | 2026-09-29 | test_path_extraction.py |

## Model-driven tool path (regressions)
| Item | How tested | Expected | Status | Last verified | Test |
|---|---|---|---|---|---|
| JSON decision extraction is brace/fence-robust | Prose/fenced/braces-in-prose/brace-in-string inputs | Correct object parsed; later object wins; never raises | ✅ | 2026-10-02 | test_tool_call_regressions.py + cyber_os/llm_json.py |
| Provider-failure marker never published as the report | `[AI ERROR]`/`[LLM error]`/`[LLM unavailable]` as the LLM reply | Falls back to "Investigation Report (offline)"; marker never shown to user | ✅ | 2026-10-02 | test_tool_call_regressions.py |
| Heuristic steps name only registered tools | malware/defender requests via heuristic path | Proposed tool is registry-valid (defender ⇒ shell_exec preset) | ✅ | 2026-10-02 | test_tool_call_regressions.py |
| Tool findings reach the run result | Stub + real tool returning findings | findings hoisted onto the investigation result | ✅ | 2026-10-02 | test_tool_call_regressions.py + test_execute_tool_success_propagation.py |
| Cancelled run abandons pending approval | cancel_event set during approval wait | `_wait_for_approval` returns False, does not block | ✅ | 2026-10-02 | test_tool_call_regressions.py |

## Subagent framework / coordination
| Item | How tested | Expected | Status | Last verified | Test |
|---|---|---|---|---|---|
| Subagent integration | Delegation, results | Structured results returned | ✅ | 2026-09-29 | test_svs_subagents_integration.py |
| Subagent tool contract | Scoped-tool arg names (VT: file_hash/ip_address), finding propagation, session-stamp inheritance in the thread pool | Correct arg names; findings reach result; children inherit the parent session stamp | ✅ | 2026-10-02 | test_subagent_tool_contract.py |
| Allowlist boundary (negative) | Profile with emptied/narrowed `allowed_tools`: assert a tool outside the allowlist is never invoked, and a disallowed tool is skipped while an allowed sibling in the same branch still runs | No out-of-allowlist tool executes; `tool_calls_count` counts only allowed calls | ✅ | 2026-10-03 | test_subagent_tool_contract.py::ScopedToolAllowlistBoundaryTests (ADDED 2026-10-03) |
| Defensive swarm planning (credit-free) | Keyword/requested profile selection | Deterministic, ≥2 domains or none | ✅ | 2026-09-29 | test_defensive_swarm.py |
| Swarm execution — success path | Monkeypatched delegate_task, real ThreadPool fan-out | Each specialist delegated once, completed_count correct | ✅ | 2026-10-01 | test_defensive_swarm.py::...delegates_each_planned_specialist_once |
| Swarm execution — failure isolation | One specialist raises inside the pool | Captured as FAILED w/ root cause; peers' evidence preserved; failed_count=1 | ✅ | 2026-10-01 | test_defensive_swarm.py (ADDED 2026-10-01) |
| Swarm evidence merge — mixed outcomes incl. FAILED child | Reducer over CONFIRMED + INCONCLUSIVE + FAILED | Confirmed evidence kept; failure attributed in failed_profiles; coverage "incomplete"; both generic + root-cause limitations surface | ✅ | 2026-10-02 | test_defensive_swarm.py::...records_a_failed_specialist... (ADDED 2026-10-02) |
| Network Containment Advisor read-only | Profile inspection | allowed_tools == [], approval-gated prompt | ✅ | 2026-09-29 | test_defensive_swarm.py:127 |
| Agent bus compatibility layer | 12 regression cases | Legacy bus API intact | ✅ | 2026-09-29 | test_agent_bus_compat.py |

## Command classification / routing
| Item | How tested | Expected | Status | Last verified | Test |
|---|---|---|---|---|---|
| READ_ONLY vs action classification | 113-case corpus | Correct safety label | ✅ | 2026-09-29 | test_command_classifier.py |

## Observability / audit
| Item | How tested | Expected | Status | Last verified | Test |
|---|---|---|---|---|---|
| Audit logger loses no records | 16 cases | Forensic trail complete | ✅ | 2026-09-29 | test_audit_logger.py |
| Incident report evidence integrity | 8 cases | No invented evidence | ✅ | 2026-09-29 | test_incident_report_evidence.py |
| Asset frontmatter survives BOM | 9 cases | Parses with BOM | ✅ | 2026-09-29 | test_asset_frontmatter.py |

## UI / API layer
| Item | How tested | Expected | Status | Last verified | Test |
|---|---|---|---|---|---|
| SVS chat bridge contract | 11 contract cases | Request/response shape stable | ✅ | 2026-09-29 | test_ui_api_contract.py |
| HackerAI UI ↔ API integration | 4 cases | Frontend/backend agree | ✅ | 2026-09-29 | test_hackerai_integration.py |
| Frontend SVS/Stai components (change-aware gate) | `node scripts/test-frontend-changed.mjs` auto-selects the affected SVS/Stai Jest suites from changed `ui/hackerai` files and runs scoped `CI=true npx jest`; `--dry-run` prints the selection | Correct suite selection; passes when green; non-zero exit on failure | ✅ | 2026-10-05 | scripts/test-frontend-changed.mjs (+ test-frontend-changed.selftest.mjs); ui/hackerai/app/components/__tests__/*, ui/hackerai/lib/__tests__/* |
| Change-aware frontend selector mapping | `node scripts/test-frontend-changed.selftest.mjs` (pure, no Jest/git) | 19/19 path→pattern assertions pass | ✅ | 2026-10-05 | scripts/test-frontend-changed.selftest.mjs |
| Change-aware **Python** selector mapping | `python scripts/select-pytest.selftest.py` (pure, no pytest/git) | 43/43 path→target assertions; shared/core + any unmapped `.py` widen to FULL suite; frontend/`.stai`/reference-trees/docs ignored | ✅ | 2026-10-06 | scripts/select-pytest.py (+ select-pytest.selftest.py) |
| Unified test entrypoint (IDEAS #6) | `python scripts/run-tests.py` runs both change-aware gates (python + frontend) and aggregates one exit status; `--dry-run`/`--python-only`/`--frontend-only`/`--files`/`--since`; aggregation is unit-tested | Both gates run, single aggregate status (0 pass / 1 fail / 2 launch-error); `--files`/`--since` forwarded to both | ✅ | 2026-10-07 | scripts/run-tests.py (+ run-tests.selftest.py, 32/32 checks) |

## Messaging bridge (Idea #10, Phase 1 — offline seam)
| Item | How tested | Expected | Status | Last verified | Test |
|---|---|---|---|---|---|
| Inbound normalization + default-deny allow-list | `InboundMessage` validation/frozenness; `AllowList` empty⇒deny-all, unknown channel/sender deny, `*` wildcard scoped to one channel; **bare-string value coerced to one id (never per-character)** | Unknown senders never reach the agent; a single-user misconfig can't deny the operator or open the channel | ✅ | 2026-10-08 | tests/test_messaging_bridge.py (bare-string guard ADDED 2026-10-08) |
| Thread→session mapping + bridge relay | `session_id_for` (thread, else sender; stable per thread); allowed msg reaches `ChatClient` and reply is relayed via the adapter; denied msg invokes neither | Sessions do not bleed across people/channels; denied msgs dropped silently | ✅ | 2026-10-07 | tests/test_messaging_bridge.py |
| Live `HttpChatClient` ↔ `POST /api/chat` contract | Faked `urllib.request.urlopen`; asserts method/URL/Content-Type/JSON body; success extracts `message`; `{"status":"error"}` ⇒ `RuntimeError` (never returned as a reply); non-dict/empty body ⇒ `""` | Request/response shape matches `ui/api_server.py:166`; errors surface, not swallowed | ✅ | 2026-10-07 | tests/test_http_chat_client.py (ADDED 2026-10-07) |

---

## Known gaps / next-cycle targets
- **JS/TS frontend tests** — now AUTOMATED via `scripts/test-frontend-changed.mjs` (IDEAS #1, implemented 2026-10-05): the routine runs `node scripts/test-frontend-changed.mjs` to auto-select and run the SVS/Stai Jest suites affected by changed `ui/hackerai` files (verified 2026-10-05: 5 suites / 13 tests green, correct selection, non-zero on failure). The *full* HackerAI Jest suite is still not run by this routine (large upstream app; needs env/convex) — scoping to our SVS/Stai surface remains the policy. Not yet wired into a blocking git hook (deferred to owner sign-off per IDEAS #1).
- **`delegate_swarm` execution** (manager.py:261) — success path, the per-future failure-isolation branch (manager.py:309-319), AND the `merge_swarm_evidence` reducer under both conflicting verdicts and a FAILED child (the exact state the isolation branch emits) are now all covered (test_defensive_swarm.py). Closed IDEAS.md #4 this run.
- **Deprecation warnings:** FastAPI `on_event("startup")` is deprecated (ui/api_server.py:770). Non-blocking; migrate to lifespan handlers eventually.
- **Slow `cyber_tools` import (~29s) → slow collection (~45-60s):** measured 2026-10-03; direct top-level imports are light, so the cost is transitive/module-level. Every test run and `--collect-only` pays it up front. Tracked as IDEAS.md #8 (deferred pre-deadline — core-module perf refactor). The collection-scope test was hardened this run so the cost no longer produces a spurious failure.
- **ESLint (minor, 0 errors):** `SvsCyberComposer.tsx:100` — `matchingCommands` could be wrapped in `useMemo` (react-hooks/exhaustive-deps perf hint). Deferred intentionally: heavily-worked uncommitted UI, not a correctness bug; revisit when the UI changes settle.

## Change → test mapping (for change-aware runs)
- `key_manager.py` → test_gemini_failover, test_provider_role_mapping, test_nemo_integration, test_ui_api_contract
- `cyber_os/subagents/**` → test_defensive_swarm, test_subagent_tool_contract, test_svs_subagents_integration, test_tool_registry_consistency
- `cyber_tools*.py` / tool registry → test_tool_registry_consistency, test_tool_recognition, test_tool_absence, test_shell_exec, test_execute_tool_success_propagation
- `cyber_os/agent_runtime.py` / `cyber_os/llm_json.py` / agent loop → test_agent_runtime_loop, test_tool_call_regressions, test_agent_loop_e2e, test_agent_foundation, test_agent_bus_compat
- `cyber_main.py` (launcher / startup readiness) → test_startup_readiness, test_cyber_main_launcher
- `ui/api_server.py` → test_ui_api_contract, test_hackerai_integration
- `ui/hackerai/**` (SVS/Stai surface) → `node scripts/test-frontend-changed.mjs` (auto-selects the StaiChatWorkspace / SvsCyberComposer / stai-api Jest suites from the changed files; the path→pattern mapping itself is covered by `scripts/test-frontend-changed.selftest.mjs`)
- Command classification → test_command_classifier
- **Shared/core change (contracts.py, registry, config, agent loop)** → run FULL suite
- **This mapping is now ENCODED + unit-tested** in `scripts/select-pytest.py` (IDEAS #9, 2026-10-06): run `python scripts/select-pytest.py` to print the affected targets for the current working tree (or `--files a,b,c` / `--since <ref>`), `--run` to execute. Keep this table and the script's mapping in lock-step — this table remains the human-readable source of truth; the script's `scripts/select-pytest.selftest.py` (43 assertions) pins the behavior.
