"""Import metadata feeds into the indicator store used by protection detection.

Defaults to a local database. To update another database, explicitly pass its
path with --db. Existing sources are merged; database files are never copied
over a running service's database (which may have uncheckpointed WAL data).
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from cyber_os.protection.store import ThreatIntelStore
from cyber_threat_intel import FREE_METADATA_FEEDS, ingest_feed

LOCAL_DB = Path("threat-intel.db")


def import_feed(
    database: Path,
    *,
    feed: str = "abusech_malwarebazaar",
    api_key: str | None = None,
    fetcher: Any = None,
) -> dict[str, Any]:
    """Merge a validated feed into the current detection schema.

    Feed provenance, confidence ceilings, and block eligibility are derived by
    the shared ingestion/store implementation. Network and parse failures keep
    the existing indicators available and are recorded in feed run history.
    """
    store = ThreatIntelStore(Path(database))
    try:
        return ingest_feed(feed, store, auth_key=api_key, fetcher=fetcher)
    finally:
        store.close()


def download_and_import_malwarebazaar(api_key: str | None = None) -> bool:
    """Compatibility entry point for callers of the old local importer."""
    result = import_feed(LOCAL_DB, api_key=api_key)
    print(json.dumps(result, sort_keys=True))
    return result.get("status") == "success"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=LOCAL_DB,
                        help="Destination indicator database (default: local threat-intel.db)")
    parser.add_argument("--feed", choices=sorted(FREE_METADATA_FEEDS),
                        default="abusech_malwarebazaar_recent",
                        help="Metadata feed; recent CSV avoids loading the full hash catalogue")
    args = parser.parse_args(argv)
    try:
        result = import_feed(args.db, feed=args.feed,
                             api_key=os.getenv("ABUSECH_AUTH_KEY") or os.getenv("ABUSE_CH_KEY"))
    except (OSError, ValueError) as exc:
        # Never echo provider headers or credential-bearing exception bodies.
        print(json.dumps({"status": "import_failed", "error_type": type(exc).__name__}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
