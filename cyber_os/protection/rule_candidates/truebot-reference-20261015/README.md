# Historical Truebot reference hashes

Five real SHA-256 indicators from the linked CISA advisories are supplied as
an **unsigned review candidate**, using the existing rule manifest schema.
See `provenance.json` for the source, table, publication date, and rule mapping.
No malware samples are included or needed. These are historical exact file
indicators, with no claim of current sightings, complete family coverage,
or detection of changed files. The 2026 review date is not a last-seen date.

All entries use `observe` / `medium`: after proper signing and activation,
matches report evidence without automatically blocking or quarantining.
The existing service does not load this directory. `RulePackage.load` requires
an independently trusted public key and a detached Ed25519 signature; this
candidate has no signature and cannot bypass that requirement.

To release it, review the hashes and source scope, incorporate the approved
entries into the release manifest, validate it with the existing parser and
scanner tests, then sign its exact UTF-8 bytes through the separately controlled
Ed25519 release process. Preserve the installed trust anchor. Stage and validate
the signed package using the existing installer/update process before rollout.
Do not replace `demo-manifest.json`, reuse a test key for production, or treat
the neighbouring provenance document as authenticated by a manifest signature.
Release provenance should be included in an authenticated release record.

The CISA publications are attribution for the hash facts, not endorsement of
STAI. No upstream YARA is copied. Broader, licensed detection remains provided
by the existing signed YARA Forge packages; this small catalogue supplements
their coverage after review and signing.
