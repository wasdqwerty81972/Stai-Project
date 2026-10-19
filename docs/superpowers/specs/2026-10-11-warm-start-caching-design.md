# SVS-Cyber warm-start caching design

**Status:** Draft for review  
**Date:** 2026-10-11

## Goal

Make repeat launches of SVS-Cyber faster across the local web UI and Python backend. The first launch may do more preparation and save reusable artifacts. Later launches should reuse valid artifacts and refresh live security state before presenting it as current.

## Current behavior

- `cyber_main.py` starts Uvicorn and launches the HackerAI frontend with `next dev --turbopack` on every launch. The frontend is built and compiled in development mode rather than started from a reusable production build.
- `ui/api_server.py` intentionally keeps `/health` lightweight. `_get_agent()` creates one process-local `CyberAgent` only when an agent-backed request arrives. Construction registers tools, initializes agent/runtime components, and constructs CyberOS.
- The browser UI and API run as separate processes. A Python agent object cannot be serialized and restored as a live object between process launches.
- Conversation history already persists under `.sessions/ui_conversations.json`; sensor queue/checkpoints persist in SQLite. These are separate from a startup artifact cache.

## Proposed design

### 1. Reusable frontend build

The normal `cyber_main.py` launch path will use the Next.js production server. If no usable build exists, or its cache key is stale, the launcher builds the frontend once and then starts `next start`. A developer mode will retain the current `next dev` workflow.

The build cache key will cover frontend source and public assets, Next.js/package configuration, the dependency lockfile, and build-time public configuration such as the backend origin. Generated directories (`node_modules`, `.next`, caches) will not be recursively included in the source fingerprint. An unchanged key reuses the build; a changed key requires a new build. Build failures will stop startup with a clear error rather than silently labeling an old build current.

Hashed Next.js assets can use the browser's normal immutable asset caching. No service worker is required for the initial implementation.

### 2. Backend warmup and persistent derived cache

Keep `/health` as an API-liveness probe. Add a small startup-status surface for cache/build state and agent warmup state. The backend will initialize the singleton `CyberAgent` in a background worker while the frontend build or server is starting, so the first user request does not pay all construction cost. Requests arriving during warmup will receive a clear retryable state rather than creating a second agent.

Only deterministic, derived startup artifacts may be persisted, such as validated registry/index manifests, keyed by application version and source-content digest. Cache loading must validate schema and digest before use; a miss or invalid entry rebuilds the cache. The live `CyberAgent`, tool objects, threads, and sockets remain process-local and are recreated once per launch.

### 3. UI freshness and security data

Persisted frontend assets are safe to reuse because they are content-versioned. Any cached display snapshot added later must be explicitly marked as cached and refreshed in the background. Sensor status, findings, alerts, pending approvals, and connector health must come from the live API before the UI presents them as current or enables an action. Credentials and secrets are never included in caches.

Existing conversation persistence remains unchanged. The startup cache will not become a second source of truth for sessions or operational records.

## Startup flow

1. Launcher computes the frontend cache key and starts the backend.
2. Backend reports API liveness immediately and initializes the agent asynchronously.
3. Launcher reuses or builds the frontend bundle, then starts the production server; developer mode can start `next dev` instead.
4. UI renders its shell, reads startup status, and shows agent warmup progress if needed.
5. Once the agent is ready, the UI requests live dashboard and security state.
6. On subsequent launches, an unchanged frontend key and valid derived caches are reused; the agent object is initialized once again for the new process.

## Failure handling

- Missing or corrupt cache: rebuild the derived artifact and continue.
- Source or dependency fingerprint change: rebuild the frontend and derived indexes before marking them current.
- Agent warmup failure: keep the API process available, report the failure through startup status, and return a retryable service error for agent-backed routes.
- Frontend build failure: surface the build error and preserve diagnostic output; do not claim the cached bundle matches current source.
- Two launches racing to create the same cache: use a single-writer lock and validate the completed artifact before reuse.

## Scope and non-goals

- Includes the canonical local launcher, local API startup, the HackerAI frontend, and small versioned derived-data caches.
- Does not cache hosted model weights or promise additional model usage. It does not change model/provider configuration.
- Does not make cached findings, sensor state, or approvals authoritative.
- Does not replace the existing `.sessions` conversation store or sensor SQLite queue.
- Does not change the standalone `--web` backend-only workflow beyond optional backend prewarming.

## Acceptance criteria

- A clean first launch can build and save the frontend artifact; a second launch with unchanged inputs skips the build.
- A frontend source, lockfile, or build-time backend-origin change invalidates the cached build.
- The regular launcher starts the production UI; developer mode still starts Next.js development mode.
- `/health` remains fast and independent of agent readiness. Startup status reports agent state without exposing sensitive data.
- Exactly one `CyberAgent` instance is created per backend process, and the UI can render while agent warmup runs.
- Cached artifacts never supply stale sensor status, findings, alerts, approvals, or secrets as current data.
- Cold and warm startup durations are measured separately for API readiness, agent readiness, frontend readiness, and first UI render.

## Risks and decisions to confirm

- Production build caching changes the default launcher from development mode; developer mode must remain easy to select.
- Fingerprinting source on every launch adds some work. It must exclude generated/dependency trees and be measured against build time saved.
- Agent warmup may compete with frontend build for CPU and disk. The implementation should start both concurrently and report their readiness independently.
- Persistent caches need clear ownership and cleanup rules. Build output stays in Next.js's ignored `.next` directory; small backend cache files stay under the existing ignored `.sessions` data directory.
- The existing project has substantial unrelated working-tree changes. Implementation and any eventual commit must isolate only files for this feature.
