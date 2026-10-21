# Historical SharePoint ToolShell reference hashes

Four SHA-256 facts from CISA MAR-251132.c1.v1 identify the report's encoded
payload, DLL, PowerShell dropper, and decoded ASPX webshell. Attribution and
individual rule mappings are recorded in `provenance.json`. These historical
indicators cover only exact file contents, with no claim of current sightings
or coverage of changed payloads. No malware samples or upstream YARA are included.

This directory is an unsigned review candidate. It is not loaded by the service
and adds zero active blocking rules. Every proposed rule uses `observe` and
`medium`, so even a signed release reports evidence without automatic blocking.

Release requires independent source review, incorporation into the release
manifest, schema validation, and signing the exact manifest bytes using the
existing independently controlled Ed25519 release process. Preserve the trusted
public key and use the existing installer/update path; do not use a generated
test key or replace a production trust anchor. The neighbouring provenance file
is not authenticated by signing the manifest and should be included in the
authenticated release record. See the adjacent Truebot candidate for the same
release workflow.
