# Android host foundation

This Android host is part of the isolated Flutter application. It uses package/application ID `com.svscyber.mobile`, minimum SDK 29, and compile/target SDK 36.

## Toolchain configuration

- Android Gradle Plugin: 8.10.1
- Gradle wrapper distribution: 8.11.1
- Kotlin Gradle Plugin: 2.2.20
- JDK: 17
- Android SDK Platform 36 and Build Tools 35.0.0 or later required by the selected AGP setup

These versions are pinned for API 36. [AGP 8.10 requires Gradle 8.11.1 and JDK 17](https://developer.android.com/build/releases/agp-8-10-0-release-notes); [Kotlin 2.2.20 supports this Gradle/AGP range](https://kotlinlang.org/docs/gradle-configure-project.html). A local `android/local.properties` must point `flutter.sdk` at the installed Flutter SDK and `sdk.dir` at the Android SDK; that machine-specific file is intentionally not committed. The repository environment inspected for this change has Java 8 and no Flutter, Dart, Android SDK, Gradle, or Kotlin compiler commands available, so this host has not been built here. The Flutter SDK must generate or supply `gradlew`, `gradlew.bat`, and `gradle-wrapper.jar` before wrapper-based builds; those generated launcher files are intentionally not hand-authored. Preserve the custom host sources and build files when obtaining launcher files from a Flutter-generated Android project.

Two Android build flavors are defined: `internal` uses application ID `com.svscyber.mobile.internal`, and `play` uses `com.svscyber.mobile`. Their app-private files, preferences, and Keystore entries are isolated by Android's per-app identity. Release signing and policy-specific configuration remain future release setup; the flavor name does not establish Play policy compliance.

After installing the above toolchain and wrapper launchers, run from `mobile/`: `flutter pub get`, `flutter analyze`, `flutter test`, `flutter build apk --debug --flavor internal`, and `flutter build apk --debug --flavor play`. Android-only checks from `mobile/android/` are `./gradlew.bat :app:lintInternalDebug :app:lintPlayDebug`. Verify the channels and encrypted journal on an API 29+ emulator/device; the repository currently has no native Android test harness. Source inspection and XML parsing do not establish that Kotlin compiles or that Android Keystore works on a device.

## Native bridge contract v1

Method channel: `svs_cyber/mobile/platform/v1`

Event channel: `svs_cyber/mobile/events/v1`

Methods:

- `getContract()` returns the contract version, channel names, supported methods, and `continuousMonitoring: false`.
- `collectDeviceBaseline()` performs a point-in-time, permission-free baseline collection. It persists each event before returning it or forwarding it to an active event listener.
- `readEvents({afterEpochMs?, limit?})` reads persisted events after the optional timestamp. `limit` is clamped to 1–500 (default 100).
- `getJournalStatus()` returns availability, count, current size, encryption status, retention, capacity, and a warning if the journal is near capacity or unavailable.

Every event has `contractVersion`, `eventId`, `capabilityId`, `eventType`, `occurredAtEpochMs`, `observedAtEpochMs`, `availability`, `operation`, `freshness`, `continuous: false`, and an `evidence` map. Availability and operation are separate: an unsupported or temporarily unavailable reading is not reported as a successful observation.

Missing services, empty security-patch values, and invalid battery readings emit `temporarily_unavailable`, `failed`, and `unknown` freshness. An API requirement that is unmet emits `unsupported`; successful observations use `available`, `completed`, and `fresh`. All readings describe the collection time, including sticky battery state; they do not identify when an underlying device value originally changed. Journal replay retains each record's original observation timestamp and freshness label; consumers must use that timestamp to assess present-day staleness.

The v1 baseline collects Android release/API level (`AND-001`), security patch date (`AND-002`), manufacturer (`AND-003`), model (`AND-004`), configured secure lock (`AND-008`), battery level (`AND-113`), app-data-volume free space (`AND-116`), and thermal status where supported (`AND-115`). Values are local observations only; they do not claim device integrity or continuous monitoring.

## Credential vault contract v1

Method channel: `com.svscyber.mobile/credential_vault.v1`

- `storeKey({providerId, secret})` stores a new credential and returns `{providerId, configured, updatedAtEpochMs}`. It fails if the provider already has a credential.
- `replaceKey({providerId, secret})` replaces an existing credential and returns the same metadata shape. It fails if no credential exists.
- `deleteKey({providerId})` deletes a credential and returns `{deleted}`.
- `listKeyMetadata()` returns an array of `{providerId, configured, updatedAtEpochMs}`. It never returns secret values.

Secrets are encrypted with AES-GCM using a separate Android Keystore key and held in app-private preferences; writes use synchronous `commit()` so success means the encrypted record was persisted. Listing authenticates each encrypted record locally before reporting it configured; missing/unusable keys or malformed ciphertext produce `configured: false`, and no plaintext crosses the bridge. Provider identifiers are validated, input size is bounded, and error messages never include the submitted value. This vault only stores, replaces, deletes, and lists metadata; it makes no provider API calls. BYOK direct provider use is an internal-testing feature pending a safe public distribution design. Keystore protection is at-rest protection and does not prevent a determined user/device owner from extracting an embedded or runtime secret from a client app.

Application backup is disabled, and Android cloud-backup and device-transfer rules exclude app files and shared preferences so encrypted credentials/events are not separated from their non-exportable Keystore keys.

## First-run privacy setup contract v1

Method channel: `com.svscyber.mobile/privacy_setup.v1`

- `isPrivacySetupComplete()` reads the local completion marker.
- `completePrivacySetup()` durably stores that the local-only privacy introduction was acknowledged.

The marker is a non-sensitive boolean in app-private SharedPreferences. This channel requests no Android permissions and does not start a collector. App backup and device-transfer backup are disabled for the preferences.

## Event storage

Events are stored as encrypted JSON Lines in internal app-private storage. Each record uses AES-GCM with a random IV and an AES key held by Android Keystore. The journal applies a 30-day retention policy, removes expired records on the first append/read/status operation and then at most every six hours of active use, and also compacts when approaching its 8 MiB limit. Physical deletion is driven by these operations; no background timer deletes data while the app is inactive. It reports capacity/Keystore issues instead of forwarding an event that was not durably written. If the Keystore key is missing while an existing journal exists, the implementation fails closed rather than generating a replacement key that would make existing records appear recoverable.

Reads exclude events older than 30 days even between compactions. Status authenticates and validates all records rather than only counting lines. Retained records are preserved when capacity is exhausted; older retained records are not silently evicted. Encountered corrupt records, including a partial final record after an interrupted write, make a read/compaction fail and make status unavailable; they are not silently discarded. Each append is flushed and synced; a baseline persists its events sequentially, so a failed batch can leave a saved prefix available for later replay. The v1 timestamp-only `afterEpochMs` cursor is strictly exclusive; callers should deduplicate by `eventId` when overlapping replay windows so observations sharing one millisecond are not lost.

The bridge uses one process-wide storage worker to serialize operations across engine recreation. Accepted operations may finish after detach, and their callbacks are suppressed for that engine. The EventChannel delivers new, persisted observations to an active listener; it does not replay records automatically, run a background collector, or announce persistent monitoring.

No VPN, package inventory, enterprise control, background collector, network permission, or destructive operation is included in this foundation.
