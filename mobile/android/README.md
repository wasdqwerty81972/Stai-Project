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

## Visible application snapshot

`collectVisibleApplicationInventory({limit})` is available through the v1 method channel and caps results at 200 apps and 32 permission names per app. The manifest declares a `MAIN` + `LAUNCHER` intent query; it does not request `QUERY_ALL_PACKAGES`. Android package visibility can filter other installed packages, so results are explicitly scoped to launchable packages visible to this app. The snapshot reads package name, label, version, installer metadata where exposed, system-app flags, declared permission names, and PackageManager grant state for those declarations. It does not establish whether an app used a permission. The user must confirm the scan in the app before collection starts.

The collector journals `AND-012`, `AND-013`, `AND-016`, `AND-025`, and `AND-026` observations before returning the snapshot. `AND-012` retains the bounded app metadata needed to restore the snapshot from the encrypted journal. Package races and inaccessible entries are counted, and the affected events report degraded operation rather than claiming a complete result.

## User-selected file and APK inspection

`selectAndInspectFile({apk})` opens `ACTION_OPEN_DOCUMENT` for one user-selected item with a temporary read grant. The app does not request broad storage access or persist the URI grant. Android's picker can expose cloud storage providers, which may download the chosen document according to their own behavior; SVS-Cyber itself does not upload it. The app streams no more than 64 MiB plus one byte to detect an over-limit document, computes SHA-256 only for a complete bounded read, and returns a bounded status for complete, unsupported, over-limit, or timed-out work. Generic file inspection reports the content type Android exposes, size when complete, and digest. APK inspection also parses package/version, requested permissions, and signer certificate fingerprints with `PackageManager` against a temporary app-cache copy; that file is deleted in `finally`. APK bytes are treated as inert input: they are never installed, loaded, executed, extracted, or uploaded. A digest or signer fingerprint is not a trust verdict. The parser is a synchronous public API and cannot be forcibly interrupted; the request times out outwardly and keeps the inspection slot occupied until cleanup finishes.

The local URL structure check and visible-app permission review are implemented in Dart. URL parsing does not resolve or fetch the host and exposes only the origin in its normalized field, excluding credentials, path, query, and fragment. Permission review reports declared-permission groups and preserves unknown/special-access, visibility, and truncation caveats. These tools do not create malicious/safe verdicts or run device-changing actions.

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

## Tor VPN prototype status (internal flavor only)

The Android VPN integration is still a consent/status scaffold. The `internal` flavor exposes the platform consent flow; the `play` flavor remains unavailable. `requestVpnConsent()` only asks Android for VPN authorization after an explicit user action. Authorization is not a running VPN and does not mean any traffic is routed.

`getVpnStatus()` and `requestVpnConsent()` return this truthful status contract:

- `contractVersion`: `1`
- `enabledForBuild`: true only for the internal flavor
- `consentGranted`: freshly read from `VpnService.prepare()`
- `state`: `unavailable`, `consent_required`, or `backend_unavailable`
- `torState`: `unavailable`
- `bridgeReady`, `dnsReady`, `tunnelActive`, `monitoringActive`: always false at this milestone
- `coverage`: `none`
- `reasonCode`: `vpn_not_enabled_for_build`, `consent_unavailable`, `user_denied`, or `tor_data_plane_not_integrated` when applicable

No Tor, tun2socks, or DNS dependency is packaged yet. Candidate upstreams were reviewed: Guardian Project's `tor-android` (BSD-3-Clause; example coordinate `info.guardianproject:tor-android:0.4.9.13.2`) and `heiher/hev-socks5-tunnel` 2.18.0 (MIT; its Android AAR exports JNI `TProxyStartService(config_path, fd)`, `TProxyStopService()`, and status/stats methods). These do not yet establish a complete safe integration. Before creating a route, the Tor process's upstream sockets need a verified bypass from this app's Android VPN; the bridge needs an explicit and verified UDP drop mode because Tor SOCKS does not transport arbitrary UDP; and DNS needs a local handler that uses Tor remote resolution with no Android-resolver fallback. No checked-in implementation currently satisfies or device-validates those requirements. Until it does, all routes remain absent and the UI must describe the feature as unavailable.

Upstream references: [tor-android](https://github.com/guardianproject/tor-android), [hev-socks5-tunnel releases](https://github.com/heiher/hev-socks5-tunnel/releases), [hev Android JNI contract](https://github.com/heiher/hev-socks5-tunnel#api), and [Tor SOCKS extensions](https://spec.torproject.org/socks-extensions). Their exact transitive binary notices and checksums must be recorded before dependencies are added to a distributable build.

## Event storage

Events are stored as encrypted JSON Lines in internal app-private storage. Each record uses AES-GCM with a random IV and an AES key held by Android Keystore. The journal applies a 30-day retention policy, removes expired records on the first append/read/status operation and then at most every six hours of active use, and also compacts when approaching its 8 MiB limit. Physical deletion is driven by these operations; no background timer deletes data while the app is inactive. It reports capacity/Keystore issues instead of forwarding an event that was not durably written. If the Keystore key is missing while an existing journal exists, the implementation fails closed rather than generating a replacement key that would make existing records appear recoverable.

Reads exclude events older than 30 days even between compactions. Status authenticates and validates all records rather than only counting lines. Retained records are preserved when capacity is exhausted; older retained records are not silently evicted. Encountered corrupt records, including a partial final record after an interrupted write, make a read/compaction fail and make status unavailable; they are not silently discarded. Each append is flushed and synced; a baseline persists its events sequentially, so a failed batch can leave a saved prefix available for later replay. The v1 timestamp-only `afterEpochMs` cursor is strictly exclusive; callers should deduplicate by `eventId` when overlapping replay windows so observations sharing one millisecond are not lost.

The bridge uses one process-wide storage worker to serialize operations across engine recreation. Accepted operations may finish after detach, and their callbacks are suppressed for that engine. The EventChannel delivers new, persisted observations to an active listener; it does not replay records automatically, run a background collector, or announce persistent monitoring.

No active VPN data plane, all-installed-package inventory, enterprise control, background collector, network permission, or destructive operation is included in this foundation.
