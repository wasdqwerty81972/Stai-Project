# SVS-Cyber Sensor Coverage

Audit date: 2026-10-13  
Canonical sources: `cyber_os/sensors/sensor_registry_data.json`, `cyber_os/sensors/sensor_registry.py`, `cyber_os/sensors/windows_sensor_service.py`.

## Catalogue and status counts

The canonical catalogue has 256 stable IDs, grouped into 32 categories of eight capabilities each. The registry produces metadata for every entry: ID, key/name, category, platform support, proposed telemetry source, shared collector, permissions, normalized event schema, collection method, operational status, estimated cost, test references, and coverage notes.

| Measure | Count | Meaning |
|---|---:|---|
| Catalogue capabilities | 256 | Capability definitions; not running collectors |
| Source status `implemented` | 2 | Process creation and parent/process lifecycle mappings in the first Windows phase |
| Source status `partial` | 12 | Event-log or selected-folder coverage with documented limitations |
| Source status `registered_only` | 242 | Metadata/source proposal without an implemented collector |
| Active on inspected host | 0 | No STAI protection service was installed or running during this audit |

The Windows event-log service exposes 14 logical capability mappings (the two implemented and twelve partial entries above). Multiple logical sensors share event-log channels; they do not represent 14 independent collectors. Windows sensor health is attached separately from static catalogue metadata. The runtime status contains channel/capability state, queue depth/capacity, dropped, deduplicated and backpressure counts, last event time, last error, and privacy settings. It does not currently provide per-entry event frequency, a durable last event per sensor, or a complete per-sensor processed count.

## Current Windows mappings

`_PHASE1_STATUS` in `sensor_registry.py` is the authoritative source list for the 14 mapped IDs. The Windows service maps those logical capabilities to shared Security, operational, DNS, and Defender/System event channels. Mapping to an event ID does not prove that Windows audit policy is enabled or that an event was observed. `windows_sensor_service.py` reports channel availability and permission failures, and its module explicitly does not change audit policy.

The selected-folder file watcher is another source. It uses `ReadDirectoryChangesW` for enrolled-user Downloads, Desktop, and Local Temp and emits post-write file events. The watcher now labels create/modify events with canonical file-activity sensor IDs 49/50; a regression test pins this mapping. It remains post-write monitoring for selected roots.

## Event routing and gaps

Current path:

```text
Windows Event Log / selected-folder watcher
  → normalization and durable bounded sensor queue
  → SensorResponseCoordinator rules and file scanner
  → durable sensor warning
  → existing AI warning worker (analysis only for containment)
```

The selected file watcher scans observed files through the custom signature engine. Event-log events are normalized and queued with deduplication/backpressure metrics. The full prompt's intended pipeline is not yet present: there is no general event broker that routes all operational sensors through a durable evidence-correlating case engine, no broad process/network/persistence event correlation, and no per-sensor health/event-rate dashboard evidence. AI investigation is not connected to specialist agents with a shared case budget and structured result aggregation.

The catalogue intentionally includes Windows, Linux, macOS, Android, cloud, and network-infrastructure capabilities. Those platforms require separate adapters and permissions. Their entries remain declarations until a matching adapter runs and health evidence proves collection.

## Runtime verification rules

- Count a sensor as active only when the collector is running and has passed its health check for the current host.
- Count an event only after ingestion, normalization, and durable queue/persistence acknowledgement as applicable.
- Keep unavailable, permission-denied, partial, stopped, and unsupported states distinct.
- Do not infer that no event means no threat when a provider is disabled or unavailable.
- Update this inventory after controlled benign event tests; do not infer live collection from source definitions or mocked unit tests.
