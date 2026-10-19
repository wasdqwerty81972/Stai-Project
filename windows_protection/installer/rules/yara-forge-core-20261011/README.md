# SVS Cyber YARA Forge core rules

This is a locally signed SVS Cyber package built from the YARA Forge core
release dated 2026-10-11. The import contains 898 YARA rules from sources
whose release metadata includes an explicit redistribution license:

- DitekSHen Detection — 2-Clause BSD
- ESET malware-ioc — BSD terms included in the source header
- Google Cloud Threat Intelligence — Apache-2.0
- Trellix Advanced Research Center — Apache-2.0
- elceef yara-rulz — MIT
- WithSecure Labs IOCs — BSD-2-Clause
- LOLDrivers — Apache-2.0

The source blocks in `manifest.json` retain the upstream source URL, rule
author, rule metadata, and license text. Sources without a redistribution
license and sources under non-commercial or unknown terms are excluded.

The upstream core archive was downloaded from the official YARA Forge GitHub
release. Its SHA-256 is recorded in `package-source.json` and was checked
against GitHub's release API digest before import. The selected rules compiled
successfully with yara-python 4.5.4 before this package was signed.

SVS Cyber's detached Ed25519 signature authenticates this local package to a
service build that embeds `trusted-rules.pub.pem`. It is a local development
trust anchor, not a signature from YARA Forge, the rule authors, Microsoft, or
an antivirus vendor. The private development key is kept outside this
repository at `%LOCALAPPDATA%\SVS-Cyber\signing\yara-forge-local.pem` and must
not be committed or distributed.

All imported YARA rules use `observe` / `medium` behavior. A match is recorded
for review and does not automatically block, terminate, or quarantine a file.
The bundle provides additional file-scan coverage; it does not supply a kernel
minifilter, real-time file-open blocking, or a vendor malware reputation
service.
