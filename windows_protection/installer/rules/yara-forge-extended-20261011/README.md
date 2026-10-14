# SVS Cyber YARA Forge extended rules

This package contains **8,583 compiled YARA rules** selected
from the YARA Forge extended release `20261011`. The upstream release lists
10,812 rules for this tier; this package contains only source groups
with an explicit redistribution license marker. Groups with missing, unknown,
or restricted terms are omitted. See `package-source.json` for the exact
archive digest, included sources, and license identifiers.

## Included source groups and licenses

- ReversingLabs: MIT
- CAPE: GPL-3.0
- BinaryAlert: Apache-2.0
- ESET: LicenseRef-ESET-Malware-IOC
- FireEye-RT: BSD-2-Clause
- GCTI: Apache-2.0
- Trellix ARC: Apache-2.0
- Volexity: BSD-2-Clause
- JPCERTCC: BSD-3-Clause
- Dr4k0nia: DRL-1.1
- Elceef: MIT
- Cod3nym: DRL-1.1
- craiu: GPL-3.0
- DitekSHen: BSD-2-Clause
- WithSecureLabs: BSD-2-Clause
- LOLDrivers: Apache-2.0
- SEKOIA: DRL-1.1
- Synacktiv: DRL-1.1
- Signature Base: DRL-1.1

Upstream source headers and license notices are kept in the signed manifest.
DRL 1.1 matches include their `author` metadata in the reported rule ID.

All imported rules use `observe` / `medium` behavior. A match is recorded for
review; it does not automatically block, terminate, or quarantine a file. The
bundle provides additional file-scan coverage, not real-time file-open
blocking or a vendor malware-reputation service.

The detached Ed25519 signature authenticates this package to a service build
that embeds the matching public key. It uses a local development trust anchor,
not a signature from YARA Forge, its upstream rule authors, Microsoft, or an
antivirus vendor. The private development key stays outside this repository
and must not be committed or distributed.
