# Protection maintenance — 2026-10-15

This maintenance pass covers the existing antivirus scanner, quarantine restore,
AI triage transport, threat-intelligence fetches, and rule-package builder.
It does not establish antivirus detection-rate parity or production readiness.

## Scanner

- A broken YARA source no longer lets an unmatched file be called clean.
- An observation match cannot hide incomplete blocking-rule coverage. Incomplete
  analysis returns unknown unless a verified high-confidence block exists.
- Signed YARA sources cannot include unsigned files from the local filesystem.
- Invalid, boolean, NaN, and infinite budgets are rejected.
- Compilation and matching consume the remaining scan budget; fallback
  compilation stops launching more work after expiry. Native compilation and
  synchronous OS reads remain nonpreemptible. YARA matching uses whole-second
  timeouts, and late results are rejected rather than accepted as complete.

## Quarantine restoration

- Unknown scan results refuse restore; removed or corrected rules can be retried
  after a previous refusal.
- Restore checks that the item is directly inside the configured quarantine
  directory, validates its expected filename, and rejects symbolic-link/junction
  components.
- Existing destination files are preserved, including concurrent creations and
  files whose contents cannot be read.
- Execute denial is released only after verifying restored bytes.
- Failed quarantine operations also refuse to overwrite a concurrently recreated
  original file during rollback.

Path checks do not eliminate concurrent ancestor-directory replacement races.
Full protection against that race requires platform-specific handle operations.
Cross-volume quarantine and crash recovery remain separate release work.

## Privacy and external inputs

- Gemini history uses its documented `model` role for assistant responses.
- Outbound chat reapplies existing redaction at the network boundary. File hashes,
  quoted secret assignments, and Bearer credentials are redacted as well.
  Pattern filtering reduces accidental disclosure; it is not a universal secret
  detector. Cloud triage continues to require explicit consent.
- Feed and reputation requests refuse redirects that could forward credentials.
- Fetch errors redact credentials before logging, returning, or storing them.
- Downloads and decompression use explicit limits. Requested ZIP members must
  exist exactly once and must be files.
- The rule builder hashes a bounded spool and decompresses those same verified
  bytes, preventing archive replacement between verification and use. Builder
  validation disables filesystem includes, matching runtime scanner behavior.

## Detection content and examples

`cyber_os/protection/rule_candidates/truebot-reference-20261015` contains five
historical exact SHA-256 indicators attributed to CISA advisories
[AA23-187A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-187a)
and [AA23-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-131a).
Publication dates are preserved and no current sightings are claimed.

The candidates use the existing manifest format with `observe` / `medium`.
They are unsigned, are not automatically loaded, and require the existing
review and external signing process before activation. Installed public keys,
existing signed packages, and signatures are unchanged.

`examples/reference-rules` provides three original, harmless YARA examples and
positive/negative text fixtures. These are educational examples, not malware
intelligence. No malware samples were downloaded or executed.

## Verification scope

Final command: `python -m pytest -q`.

Result: **1,123 passed, 6 skipped, 303 subtests passed**, exit code 0, in
224.22 seconds. The run reported 17 FastAPI/Starlette deprecation warnings.
The full captured output is `output/protection-hardening-pytest-20261015.log`.
All 47 new hardening regressions are included in the full run. A final
read-only review found no remaining important defects in this maintenance scope.

Regression tests reproduce the fixed defects using inert files, real YARA,
temporary databases, and controlled network transports. No live provider
requests, driver installation, or Windows security-policy changes were needed.
Windows driver enforcement, signing, installer recovery, and independent
false-positive/performance evaluation remain unverified by this maintenance pass.
These are source changes; an installed frozen service needs a rebuilt, properly
signed release before it can use them.
