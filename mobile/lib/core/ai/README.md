# Mobile credential vault boundary

The Dart API in `credential_vault.dart` stores, replaces, deletes, and lists
metadata for user-supplied Gemini and OpenAI-compatible credentials through
the versioned Android MethodChannel
`com.svscyber.mobile/credential_vault.v1`. Stored values are never returned to
Dart. The contract does not invoke providers or send evidence.

The Android implementation must encrypt credential values at rest with a key
protected by Android Keystore. Keystore-backed storage protects data at rest;
it cannot make a client-side BYOK credential secret from a compromised device,
rooted environment, or runtime-instrumented app. A credential can be exposed
while it is entered or used by the client. Direct provider use therefore stays
internal-testing-only until a mobile-only proxy or a suitable on-device model is
selected.

Any future external AI request must be a separate flow. The user selects the
exact evidence, sees the destination provider and submission preview, and gives
explicit consent for that request. AI remains advisory and has no device-action
executor.

Callers should avoid retaining credential strings, must never log arguments or
native payloads, and should clear their input controller immediately after a
store/replace attempt. Dart strings cannot be reliably zeroized; this is another
reason this BYOK path is limited to internal use.
