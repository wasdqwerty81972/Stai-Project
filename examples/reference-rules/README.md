# Inert rule examples

This unsigned candidate manifest contains three original STAI YARA examples.
Each detects explicit harmless text: a marker anywhere in a small file, a pair
of markers, or a header at offset zero. These are educational fixtures, **not
malware signatures**, and do not improve real threat coverage.

Expected results after using the normal signed-package test harness:

| Fixture | Rule | Action |
| --- | --- | --- |
| benign.txt | none | allow |
| marker-text.txt | example-marker-text | observe / allow |
| marker-pair.txt | example-marker-pair | observe / allow |
| marker-header.txt | example-marker-header | observe / allow |

All rules require files smaller than 4 KiB. One pair marker alone must not
match the pair rule. Prefixing the header with another byte must prevent the
header rule from matching. No fixture executes code or needs administrator
access. An unavailable YARA runtime must report unknown coverage.

The service does not load unsigned examples. Tests may sign with an ephemeral
key in a temporary directory; installed services must retain their existing
trusted signing key. Keep these fixtures outside production intelligence.
