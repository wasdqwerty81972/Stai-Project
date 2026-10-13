# Local protection service pipe contract

The Windows Tauri bridge is a client for the local named pipe
`\\.\pipe\STAI.Protection.v1`. The Python Windows service implements the
bounded server and a restrictive per-user security descriptor. The elevated
installer that registers the user SID and installs the service and driver is
still pending. Until installation configures that endpoint, dashboard requests
return `protection service unavailable`; this bridge does not provide sample
or fallback protection data.

## Framing

Each request and response is a four-byte unsigned little-endian byte length
followed by one UTF-8 JSON document. Frames must be 1 to 65,536 bytes. A client
request times out after three seconds. The bridge generates a unique `request_id`
for each request.

```json
{
  "version": 1,
  "request_id": "unique-request-id",
  "operation": "get_status",
  "payload": {}
}
```

The response uses the same framing and correlation identifier:

```json
{
  "version": 1,
  "request_id": "unique-request-id",
  "ok": true,
  "data": {}
}
```

On failure, `ok` is `false` and `error` contains a safe error message. A service
must reject unsupported protocol versions, mismatched request IDs, unknown
operations, malformed payloads, and oversized frames. The bridge treats pipe
connect/read/write failures and malformed responses as unavailable or invalid
service responses.

## Allowlisted operations

Operation names are snake case. Payloads are limited to these typed forms:

| Operation | Payload |
| --- | --- |
| `get_status` | `{}` |
| `start_scan` | `{ "scope": "quick" | "system" }` |
| `get_scan`, `cancel_scan` | `{ "job_id": "..." }` |
| `get_scan_schedule` | `{}` |
| `set_scan_schedule` | `{ "enabled": boolean, "frequency": "daily" | "weekly", "scope": "quick" | "system", "local_time": "HH:MM", "weekday": 0..6 | null }` |
| `list_threats`, `list_quarantine` | `{}` |
| `get_triage`, `request_triage` | `{ "detection_id": "..." }` |
| `get_agent_history` | `{ "session_id": "..." }` |
| `send_agent_message` | `{ "session_id": "...", "message": "...", "detection_id": "..." | null }` |
| `restore_quarantine` | `{ "item_id": "..." }` |

Responses must follow the dashboard records in `src/protection-api.ts`. For
`get_triage` and `request_triage`, the service may return the persisted row
(`detection_id`, `status`, nullable `summary`, nullable `error`, and timestamps).
The Rust bridge maps `detection_id` to the stable `triage_id`, maps `status` to
the dashboard `state`, and supplies an empty recommendations list because the
store does not persist recommendations. A null summary must not be replaced
with fabricated analysis. `blocked` totals describe confirmed denied file
operations; a rule match alone is not proof that an operation was denied.

## Required service hardening before shipping

The service creates the pipe with a restrictive DACL for the installed client
SID and rejects remote pipe clients. The installer must register the intended
interactive dashboard user's SID. The service must
validate every request independently, avoid accepting paths or shell commands
from the dashboard, and make scan/quarantine operations idempotent where
possible. Quarantine restore must rescan the item before returning it. This
contract is implemented by the dashboard bridge and service host, but does not
claim that the driver, scanner, or service currently provides a production
antivirus boundary. Production activation remains gated on a trusted rules key,
signed rules, the signed driver, and end-to-end Windows VM validation.
