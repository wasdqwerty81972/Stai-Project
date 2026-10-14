# Read-only WFP network event bridge

This is an optional user-mode observer for Windows Filtering Platform classify
allow and classify drop events. It opens a dynamic engine session and subscribes
through `FwpmNetEventSubscribe3`; it does not add filters, change engine options,
enable event collection, change auditing, or block traffic. The callback copies
supported fields into a fixed 256-record queue and drops immediately when the
queue is full or busy.

The bridge uses Windows SDK headers and libraries only. No WDK or kernel driver
is needed for this event-subscription prototype. The exported Python API is
`cyber_os.network_telemetry.wfp_events.WfpNetEventMonitor`, with `start()`,
`stop(timeout=...)`, `get_status()`, and `snapshot()`. It does not load the DLL
until `start()`; a missing DLL, unsupported OS, or insufficient WFP permission
is reported as an unavailable/failed capability without raising from `start()`.
Set `STAI_WFP_EVENT_BRIDGE` to the built DLL path, or pass `dll_path=` when
constructing the monitor. `process_id` remains unknown because this WFP event
version does not include a process ID.

## Build and synthetic tests

From the repository root in PowerShell:

```powershell
& .\windows_protection\wfp\native\build.ps1
```

The script locates MSVC Build Tools and a Windows 10 SDK, writes output beneath
`$env:TEMP\svs-wfp-event-bridge-build`, builds the DLL and a native synthetic
test executable, and runs only those synthetic tests. The test executable calls
normalization and queue test hooks; it does not call `SvsWfpStart()` and does not
subscribe to the host's live WFP event stream. To run the Python wrapper tests:

```powershell
python -m pytest tests\test_wfp_events.py -q
```

The event subscription has not been exercised against the live Windows Filtering
Platform in this repository workflow. Deployment/service integration and
runtime permissions should be validated separately in a controlled Windows VM.
