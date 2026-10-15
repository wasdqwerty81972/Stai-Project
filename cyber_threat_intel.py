"""Threat intelligence enrichment via VirusTotal and AlienVault OTX.

Provides the real implementations behind the `virustotal_*` and `otx_*` tools in
cyber_tools.py. Every lookup is a read-only outbound GET.

Two invariants matter here, because this module feeds verdicts to an agent that
acts on them:

1. A lookup that did not happen never returns a benign-looking result. Missing
   keys, network errors, rate limits and validation failures all surface
   ``verdict="unknown"`` so a caller cannot mistake them for "clean".
2. Artifact values are validated before they reach a URL. They arrive from
   untrusted telemetry and are interpolated into request paths.

Configuration:
    VIRUSTOTAL_API_KEY  https://www.virustotal.com/gui/my-apikey
    OTX_API_KEY         https://otx.alienvault.com/api

Note that lookups disclose the artifact to a third party. An IP or hash from a
monitored environment leaves the network when these run.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import threading
import time
from typing import Any, Dict, Iterator, Optional

logger = logging.getLogger(__name__)

VERDICT_UNKNOWN = "unknown"

# VirusTotal's free tier allows 4 requests/minute and 500/day, so a single
# multi-IOC investigation will trip it without throttling. OTX is far more
# permissive but still benefits from the cache.
_MIN_REQUEST_INTERVAL = {"virustotal": 15.0, "otx": 1.0}
_CACHE_TTL_SECONDS = 3600.0
_REQUEST_TIMEOUT = 10.0

# Hex digest lengths for md5 / sha1 / sha256, the identifiers VirusTotal accepts.
_HASH_PATTERN = re.compile(r"\A(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\Z")

_cache: Dict[str, tuple[float, Dict[str, Any]]] = {}
_last_request: Dict[str, float] = {}
_lock = threading.Lock()


def _unknown(status: str, message: str, **extra: Any) -> Dict[str, Any]:
    """Build a result that cannot be misread as a clean verdict."""
    return {"status": status, "verdict": VERDICT_UNKNOWN, "message": message, **extra}


def _scrub(text: str, *secrets: Optional[str], limit: int = 300) -> str:
    """Truncate a provider error body and strip any API key echoed back in it."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    text = " ".join(text.split())
    return text[:limit] + ("..." if len(text) > limit else "")


def _validate_ip(value: str) -> Optional[str]:
    """Return a normalised IP string, or None if it is not a bare IP address."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _validate_hash(value: str) -> Optional[str]:
    """Return a lowercased hex digest, or None if it is not an md5/sha1/sha256."""
    candidate = str(value).strip()
    return candidate.lower() if _HASH_PATTERN.match(candidate) else None


def _cached(key: str) -> Optional[Dict[str, Any]]:
    with _lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        stored_at, payload = entry
        if time.monotonic() - stored_at > _CACHE_TTL_SECONDS:
            del _cache[key]
            return None
    return {**payload, "cached": True}


def _store(key: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    # Only successful answers are worth caching; transient failures should retry.
    if payload.get("status") == "success":
        with _lock:
            _cache[key] = (time.monotonic(), payload)
    return payload


def _throttle(provider: str) -> None:
    """Block until this provider's minimum inter-request interval has elapsed."""
    interval = _MIN_REQUEST_INTERVAL.get(provider, 1.0)
    now = time.monotonic()
    with _lock:
        slot = _last_request.get(provider)
        if slot is None or now - slot >= interval:
            _last_request[provider] = now
            return
        # Reserve the next slot so concurrent callers queue behind it instead of colliding.
        _last_request[provider] = slot + interval
        wait = slot + interval - now
    logger.debug("Throttling %s for %.1fs", provider, wait)
    time.sleep(wait)


def _get(provider: str, url: str, headers: Dict[str, str], api_key: str) -> Dict[str, Any]:
    """Perform a throttled GET, returning either the parsed body or an unknown-verdict result."""
    try:
        import requests  # Imported lazily to match cyber_tools.py and keep import cheap.
    except ImportError:
        return _unknown("dependency_missing", "The 'requests' package is not installed.")

    _throttle(provider)
    try:
        response = requests.get(url, headers=headers, timeout=_REQUEST_TIMEOUT, allow_redirects=False)
    except Exception as exc:  # network failure, DNS, TLS, timeout
        error = _scrub(str(exc), api_key, *headers.values())
        logger.error("%s request failed: %s", provider, error)
        return _unknown("request_failed", f"{provider} request failed: {error}")

    if response.status_code == 200:
        try:
            return {"status": "success", "body": response.json()}
        except ValueError:
            return _unknown("bad_response", f"{provider} returned a non-JSON body.")
    if response.status_code == 404:
        # Not an error: the provider simply has no record of this artifact.
        return {"status": "not_found"}
    if response.status_code == 429:
        return _unknown("rate_limited", f"{provider} rate limit exceeded; retry later.")
    if response.status_code in (401, 403):
        return _unknown("auth_failed", f"{provider} rejected the API key ({response.status_code}).")
    return _unknown(
        "http_error",
        f"{provider} returned HTTP {response.status_code}: {_scrub(response.text, api_key)}",
        code=response.status_code,
    )


def _verdict_from_vt_stats(stats: Dict[str, Any]) -> str:
    """Derive a verdict from VirusTotal's last_analysis_stats."""
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    if int(stats.get("harmless", 0) or 0) or int(stats.get("undetected", 0) or 0):
        return "benign"
    return VERDICT_UNKNOWN


class ThreatIntelManager:
    """Unified threat intelligence lookups across VirusTotal and AlienVault OTX."""

    def __init__(self, vt_api_key: Optional[str] = None, otx_api_key: Optional[str] = None):
        self.vt_api_key = vt_api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.otx_api_key = otx_api_key or os.getenv("OTX_API_KEY")

    @property
    def configured_providers(self) -> list[str]:
        providers = []
        if self.vt_api_key:
            providers.append("virustotal")
        if self.otx_api_key:
            providers.append("otx")
        return providers

    def lookup_ip_virustotal(self, ip_address: str) -> Dict[str, Any]:
        if not self.vt_api_key:
            return _unknown("not_configured", "VIRUSTOTAL_API_KEY is not set.", ip=ip_address)
        ip = _validate_ip(ip_address)
        if ip is None:
            return _unknown("invalid_input", f"Not a valid IP address: {ip_address!r}")

        cache_key = f"vt:ip:{ip}"
        hit = _cached(cache_key)
        if hit is not None:
            return hit

        result = _get(
            "virustotal",
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            {"x-apikey": self.vt_api_key},
            self.vt_api_key,
        )
        if result["status"] == "not_found":
            return _unknown("not_found", "VirusTotal has no record of this IP.", ip=ip)
        if result["status"] != "success":
            return {**result, "ip": ip}

        attributes = result["body"].get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {}) or {}
        return _store(cache_key, {
            "status": "success",
            "source": "virustotal",
            "ip": ip,
            "verdict": _verdict_from_vt_stats(stats),
            "stats": stats,
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "reputation": attributes.get("reputation"),
        })

    def lookup_hash_virustotal(self, file_hash: str) -> Dict[str, Any]:
        if not self.vt_api_key:
            return _unknown("not_configured", "VIRUSTOTAL_API_KEY is not set.", hash=file_hash)
        digest = _validate_hash(file_hash)
        if digest is None:
            return _unknown(
                "invalid_input",
                f"Not a valid md5/sha1/sha256 hex digest: {file_hash!r}",
            )

        cache_key = f"vt:hash:{digest}"
        hit = _cached(cache_key)
        if hit is not None:
            return hit

        result = _get(
            "virustotal",
            f"https://www.virustotal.com/api/v3/files/{digest}",
            {"x-apikey": self.vt_api_key},
            self.vt_api_key,
        )
        if result["status"] == "not_found":
            # A genuine answer, but absence of a record is not evidence of safety.
            return _unknown("not_found", "VirusTotal has no record of this hash.", hash=digest)
        if result["status"] != "success":
            return {**result, "hash": digest}

        attributes = result["body"].get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {}) or {}
        return _store(cache_key, {
            "status": "success",
            "source": "virustotal",
            "hash": digest,
            "verdict": _verdict_from_vt_stats(stats),
            "stats": stats,
            "meaningful_name": attributes.get("meaningful_name"),
            "type_description": attributes.get("type_description"),
            "popular_threat_label": (
                attributes.get("popular_threat_classification", {}).get("suggested_threat_label")
            ),
        })

    def lookup_ip_otx(self, ip_address: str) -> Dict[str, Any]:
        if not self.otx_api_key:
            return _unknown("not_configured", "OTX_API_KEY is not set.", ip=ip_address)
        ip = _validate_ip(ip_address)
        if ip is None:
            return _unknown("invalid_input", f"Not a valid IP address: {ip_address!r}")

        version = 6 if ipaddress.ip_address(ip).version == 6 else 4
        cache_key = f"otx:ip:{ip}"
        hit = _cached(cache_key)
        if hit is not None:
            return hit

        result = _get(
            "otx",
            f"https://otx.alienvault.com/api/v1/indicators/IPv{version}/{ip}/general",
            {"X-OTX-API-KEY": self.otx_api_key},
            self.otx_api_key,
        )
        if result["status"] == "not_found":
            return _unknown("not_found", "OTX has no record of this IP.", ip=ip)
        if result["status"] != "success":
            return {**result, "ip": ip}

        body = result["body"]
        pulse_info = body.get("pulse_info", {}) or {}
        pulse_count = int(pulse_info.get("count", 0) or 0)
        return _store(cache_key, {
            "status": "success",
            "source": "otx",
            "ip": ip,
            # Pulse membership means someone reported it, not that it is confirmed bad.
            "verdict": "suspicious" if pulse_count > 0 else VERDICT_UNKNOWN,
            "pulse_count": pulse_count,
            "pulse_names": [p.get("name") for p in (pulse_info.get("pulses") or [])[:5]],
            "country": body.get("country_name"),
            "asn": body.get("asn"),
        })

    def enrich_artifact(self, artifact_type: str, value: str) -> Dict[str, Any]:
        """Enrich one artifact across every configured provider.

        artifact_type: 'ip' or 'hash'. This is the main entry point for cyber_agent.py.
        """
        artifact_type = str(artifact_type).strip().lower()
        enrichment: Dict[str, Any] = {
            "artifact": value,
            "type": artifact_type,
            "verdict": VERDICT_UNKNOWN,
            "results": {},
        }

        if artifact_type not in ("ip", "hash"):
            return {**enrichment, "status": "invalid_input",
                    "message": f"artifact_type must be 'ip' or 'hash', got {artifact_type!r}"}

        if not self.configured_providers:
            return {**enrichment, "status": "not_configured",
                    "message": "No threat intel API keys are set (VIRUSTOTAL_API_KEY, OTX_API_KEY)."}

        if artifact_type == "ip":
            if self.vt_api_key:
                enrichment["results"]["virustotal"] = self.lookup_ip_virustotal(value)
            if self.otx_api_key:
                enrichment["results"]["otx"] = self.lookup_ip_otx(value)
        else:
            if self.vt_api_key:
                enrichment["results"]["virustotal"] = self.lookup_hash_virustotal(value)
            if self.otx_api_key:
                enrichment["results"]["otx"] = _unknown(
                    "unsupported", "OTX file-hash lookup is not implemented."
                )

        verdicts = [r.get("verdict") for r in enrichment["results"].values()]
        # Escalate to the most severe verdict any provider returned.
        for level in ("malicious", "suspicious", "benign"):
            if level in verdicts:
                enrichment["verdict"] = level
                break

        succeeded = [r for r in enrichment["results"].values() if r.get("status") == "success"]
        enrichment["status"] = "success" if succeeded else "no_data"
        if not succeeded:
            enrichment["message"] = "No provider returned data; verdict is unknown, not clean."
        return enrichment


def clear_cache() -> None:
    """Drop all cached lookups. Intended for tests."""
    with _lock:
        _cache.clear()
        _last_request.clear()


# ---------------------------------------------------------------------------
# Bulk feed ingestion (metadata only)
#
# HARD CONSTRAINT: nothing here downloads an executable sample. Every endpoint
# below returns JSON or text listings of hashes, URLs, and IPs. MalwareBazaar's
# ``/download/`` endpoint -- the one that returns a zipped live sample -- is
# never constructed, and ``_assert_metadata_only`` refuses any URL that looks
# like a sample fetch before a request is made.
# ---------------------------------------------------------------------------

from dataclasses import dataclass  # noqa: E402  (grouped with the feed code)

# Fragments that indicate a sample payload rather than metadata. A feed
# definition containing any of these is a bug, and is rejected at call time
# rather than trusted to be harmless.
_SAMPLE_DOWNLOAD_MARKERS = (
    "/download/",
    "download_file",
    "get_file",
    "/sample/",
    "payload.zip",
    "/downloads/malware",
)

#: Feeds that need no credential. Verified reachable 2026-10-14; see the
#: ``licence`` field for redistribution terms.
FREE_METADATA_FEEDS: Dict[str, Dict[str, str]] = {
    "abusech_malwarebazaar": {
        # The bulk SHA-256 export: one hex digest per line, zipped. This is a
        # list of identifiers, not samples -- 1.15M lines of 64 hex chars. The
        # MalwareBazaar *query* API (mb-api.abuse.ch) does require an Auth-Key,
        # but these /export/ paths do not.
        "url": "https://bazaar.abuse.ch/export/txt/sha256/full/",
        "format": "malwarebazaar_sha256_txt",
        "indicator_types": "sha256",
        "licence": "CC0 1.0 Universal (public domain dedication)",
        "auth": "none",
        "zip_member": "full_sha256.txt",
    },
    "abusech_malwarebazaar_recent": {
        # The recent CSV carries the family label (``signature``) and the
        # sibling md5/sha1 digests that the hash-only export omits.
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "format": "malwarebazaar_csv",
        "indicator_types": "sha256,sha1,md5",
        "licence": "CC0 1.0 Universal (public domain dedication)",
        "auth": "none",
    },
    "abusech_feodotracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "format": "feodo_json",
        "indicator_types": "ip",
        "licence": "CC0 1.0 Universal (public domain dedication)",
        "auth": "none",
    },
    "abusech_threatfox": {
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "format": "threatfox_json",
        "indicator_types": "sha256,md5,domain,ip,url",
        "licence": "CC0 1.0 Universal (public domain dedication)",
        "auth": "none",
    },
    "abusech_urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text_recent/",
        "format": "urlhaus_text",
        "indicator_types": "url",
        "licence": "CC0 1.0 Universal (public domain dedication)",
        "auth": "none",
    },
}

#: Feeds that require a credential this environment does not have.
CREDENTIALED_METADATA_FEEDS: Dict[str, Dict[str, str]] = {
    "abusech_malwarebazaar_api": {
        # The per-hash query API. Returns richer metadata (file type, tags,
        # vendor verdicts) for one sample at a time, but needs a free account's
        # Auth-Key: an unauthenticated POST returns HTTP 401.
        "url": "https://mb-api.abuse.ch/api/v1/",
        "format": "malwarebazaar_api",
        "indicator_types": "sha256",
        "licence": "CC0 1.0 Universal (public domain dedication)",
        "auth": "Auth-Key header (free abuse.ch account)",
        "env_var": "ABUSECH_AUTH_KEY",
    },
}


class SampleDownloadRefused(RuntimeError):
    """A feed URL looked like a malware sample fetch and was refused."""


def _assert_metadata_only(url: str) -> None:
    lowered = str(url).lower()
    for marker in _SAMPLE_DOWNLOAD_MARKERS:
        if marker in lowered:
            raise SampleDownloadRefused(
                f"refusing to fetch {url!r}: matches sample-download marker {marker!r}. "
                "This ingestion path handles hashes and metadata only."
            )


@dataclass(frozen=True)
class FeedRecord:
    """One indicator parsed out of a feed, before trust is applied.

    ``verification`` and ``confidence`` here are what the *feed* claims. The
    store re-derives both from its own trust registry, so a parser cannot
    promote its source.
    """

    indicator_type: str
    indicator_value: str
    source: str
    claimed_confidence: Optional[int] = None
    threat_family: Optional[str] = None
    source_timestamp: Optional[str] = None
    sha256: Optional[str] = None
    sha1: Optional[str] = None
    md5: Optional[str] = None
    severity: str = "medium"
    claimed_verification: str = "reported"


def _hash_type(value: str) -> Optional[str]:
    candidate = str(value).strip().lower()
    length = len(candidate)
    if length not in (32, 40, 64):
        return None
    try:
        int(candidate, 16)
    except ValueError:
        return None
    return {32: "md5", 40: "sha1", 64: "sha256"}[length]


def parse_malwarebazaar_sha256_txt(
    payload: Any, source: str = "abusech_malwarebazaar"
) -> list[FeedRecord]:
    """Parse MalwareBazaar's hash-only bulk export (one sha256 per line).

    Yields a record per digest with no family label -- the hash-only export
    carries no metadata beyond the digest itself. Lines that are not valid
    sha256 digests are dropped rather than stored as indicators.
    """
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", "replace")
    records: list[FeedRecord] = []
    for line in str(payload).splitlines():
        digest = line.strip().strip('"').lower()
        if not digest or digest.startswith("#"):
            continue
        if _hash_type(digest) != "sha256":
            continue
        records.append(
            FeedRecord(
                indicator_type="sha256",
                indicator_value=digest,
                source=source,
                sha256=digest,
                severity="high",
                claimed_verification="confirmed",
            )
        )
    return records


def iter_malwarebazaar_sha256(lines: Any, source: str = "abusech_malwarebazaar") -> Iterator[str]:
    """Stream valid sha256 digests from an iterable of lines.

    Used by the bulk loader so a million-line export never has to be held in
    memory as a list of dataclasses.
    """
    for line in lines:
        if isinstance(line, bytes):
            line = line.decode("utf-8", "replace")
        digest = line.strip().strip('"').lower()
        if not digest or digest.startswith("#"):
            continue
        if _hash_type(digest) == "sha256":
            yield digest


def parse_feodo_json(payload: Any, source: str = "abusech_feodotracker") -> list[FeedRecord]:
    """Parse Feodo Tracker's botnet C2 IP blocklist."""
    if isinstance(payload, (bytes, str)):
        import json as _json

        payload = _json.loads(payload)
    records: list[FeedRecord] = []
    for entry in payload or []:
        if not isinstance(entry, dict):
            continue
        ip = str(entry.get("ip_address") or "").strip()
        if not ip or _validate_ip(ip) is None:
            continue
        records.append(
            FeedRecord(
                indicator_type="ip",
                indicator_value=ip,
                source=source,
                threat_family=entry.get("malware") or None,
                source_timestamp=entry.get("first_seen") or entry.get("last_online") or None,
                severity="high",
                # A C2 IP is a report about infrastructure, never a file
                # identity, so it stays at "reported" no matter how confident
                # the feed sounds.
                claimed_verification="reported",
            )
        )
    return records


def parse_threatfox_json(payload: Any, source: str = "abusech_threatfox") -> list[FeedRecord]:
    """Parse ThreatFox's recent-IOC export.

    The export is an object keyed by ThreatFox id, each holding a one-element
    list of IOC objects.
    """
    if isinstance(payload, (bytes, str)):
        import json as _json

        payload = _json.loads(payload)
    records: list[FeedRecord] = []
    if not isinstance(payload, dict):
        return records
    for entries in payload.values():
        for entry in entries if isinstance(entries, list) else [entries]:
            if not isinstance(entry, dict):
                continue
            raw_value = str(entry.get("ioc_value") or "").strip()
            if not raw_value:
                continue
            ioc_type = str(entry.get("ioc_type") or "").strip().lower()
            family = entry.get("malware_printable") or entry.get("malware") or None
            timestamp = entry.get("first_seen_utc") or entry.get("last_seen_utc") or None
            claimed = entry.get("confidence_level")
            try:
                claimed = int(claimed) if claimed is not None else None
            except (TypeError, ValueError):
                claimed = None

            hash_kind = _hash_type(raw_value)
            if ioc_type in ("sha256_hash", "md5_hash", "sha1_hash") or hash_kind:
                if hash_kind is None:
                    continue
                records.append(
                    FeedRecord(
                        indicator_type=hash_kind,
                        indicator_value=raw_value.lower(),
                        source=source,
                        claimed_confidence=claimed,
                        threat_family=family,
                        source_timestamp=timestamp,
                        severity="high",
                        claimed_verification="reported",
                    )
                )
                continue

            if ioc_type.startswith("domain"):
                indicator_type = "domain"
            elif ioc_type.startswith("url"):
                indicator_type = "url"
            elif ioc_type.startswith("ip"):
                # ThreatFox writes these as host:port.
                indicator_type = "ip"
                raw_value = raw_value.split(":", 1)[0]
                if _validate_ip(raw_value) is None:
                    continue
            else:
                continue
            records.append(
                FeedRecord(
                    indicator_type=indicator_type,
                    indicator_value=raw_value.lower(),
                    source=source,
                    claimed_confidence=claimed,
                    threat_family=family,
                    source_timestamp=timestamp,
                    severity="medium",
                    claimed_verification="reported",
                )
            )
    return records


def parse_urlhaus_text(payload: Any, source: str = "abusech_urlhaus") -> list[FeedRecord]:
    """Parse URLhaus's plain-text recent-URL listing (one URL per line)."""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", "replace")
    records: list[FeedRecord] = []
    for line in str(payload).splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        records.append(
            FeedRecord(
                indicator_type="url",
                indicator_value=url,
                source=source,
                severity="medium",
                claimed_verification="reported",
            )
        )
    return records


def parse_malwarebazaar_csv(
    payload: Any, source: str = "abusech_malwarebazaar"
) -> list[FeedRecord]:
    """Parse MalwareBazaar's full CSV hash export.

    Columns (quoted, comma separated, ``#``-prefixed comment header):
    first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name,
    file_type_guess, mime_type, signature, clamav, vtpercent, imphash, ...
    """
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", "replace")
    import csv as _csv
    import io as _io

    records: list[FeedRecord] = []
    stream = _io.StringIO(str(payload))
    reader = _csv.reader(
        (line for line in stream if line.strip() and not line.lstrip().startswith("#")),
        skipinitialspace=True,
    )
    for row in reader:
        if len(row) < 4:
            continue
        cells = [cell.strip().strip('"') for cell in row]
        first_seen, sha256, md5, sha1 = cells[0], cells[1].lower(), cells[2].lower(), cells[3].lower()
        if _hash_type(sha256) != "sha256":
            continue
        family = cells[8] if len(cells) > 8 and cells[8] not in ("", "n/a") else None
        records.append(
            FeedRecord(
                indicator_type="sha256",
                indicator_value=sha256,
                source=source,
                threat_family=family,
                source_timestamp=first_seen or None,
                sha256=sha256,
                sha1=sha1 if _hash_type(sha1) == "sha1" else None,
                md5=md5 if _hash_type(md5) == "md5" else None,
                severity="high",
                # MalwareBazaar holds and analyses the sample itself, so an
                # exact file hash from it is first-hand evidence.
                claimed_verification="confirmed",
            )
        )
    return records


_FEED_PARSERS = {
    "feodo_json": parse_feodo_json,
    "threatfox_json": parse_threatfox_json,
    "urlhaus_text": parse_urlhaus_text,
    "malwarebazaar_csv": parse_malwarebazaar_csv,
    "malwarebazaar_sha256_txt": parse_malwarebazaar_sha256_txt,
}


#: Uncompressed-size ceiling for a zipped feed member. A feed that claims to
#: expand past this is treated as hostile (zip bomb) rather than ingested.
_MAX_FEED_MEMBER_BYTES = 1024 * 1024 * 1024
_MAX_FEED_DOWNLOAD_BYTES = 256 * 1024 * 1024


def unzip_feed_member(raw: bytes, member: Optional[str] = None) -> bytes:
    """Return one member of a zipped feed, refusing implausible expansion.

    Only text is read out; nothing is written to disk and nothing is executed.
    """
    import io
    import zipfile

    if not raw[:2] == b"PK":
        return raw
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        if not infos:
            raise ValueError("zipped feed is empty")
        if member is not None:
            matches = [info for info in infos if info.filename == member]
            if len(matches) != 1:
                raise ValueError("zipped feed must contain exactly one requested member")
            info = matches[0]
        else:
            info = infos[0]
        if info.is_dir():
            raise ValueError("zipped feed member must be a file")
        if info.file_size > _MAX_FEED_MEMBER_BYTES:
            raise ValueError(
                f"zipped feed member {info.filename!r} expands to {info.file_size} bytes, "
                f"above the {_MAX_FEED_MEMBER_BYTES} ceiling"
            )
        # Bound the actual stream as well as the archive's advertised size.
        with archive.open(info) as stream:
            content = stream.read(_MAX_FEED_MEMBER_BYTES + 1)
        if len(content) > _MAX_FEED_MEMBER_BYTES:
            raise ValueError("zipped feed member exceeds the expansion ceiling")
        return content


def parse_feed(feed_format: str, payload: Any, source: str) -> list[FeedRecord]:
    """Dispatch to a feed parser. Pure function -- no network, fixture-testable."""
    parser = _FEED_PARSERS.get(feed_format)
    if parser is None:
        raise ValueError(f"unknown feed format: {feed_format!r}")
    return parser(payload, source)


def http_fetch(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 30.0) -> bytes:
    """Default fetcher: one read-only GET, refusing sample-download URLs."""
    _assert_metadata_only(url)
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, response_headers, newurl):
            # Custom Auth-Key headers must never follow a provider redirect.
            # Refusing all redirects also preserves the metadata-only URL check.
            return None

    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        content = response.read(_MAX_FEED_DOWNLOAD_BYTES + 1)
    if len(content) > _MAX_FEED_DOWNLOAD_BYTES:
        raise ValueError("feed download exceeds the compressed download ceiling")
    return content


def ingest_feed(
    feed_name: str,
    store: Any,
    *,
    fetcher: Optional[Any] = None,
    feed_definition: Optional[Dict[str, str]] = None,
    auth_key: Optional[str] = None,
    feed_version: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch, parse, and upsert one feed into a ``ThreatIntelStore``.

    ``fetcher`` is injectable so the whole path -- parse, trust ceiling,
    upsert, run bookkeeping -- is exercised offline against a fixture with no
    network at all. It is called as ``fetcher(url, headers)`` and must return
    the raw bytes.
    """
    definition = feed_definition or FREE_METADATA_FEEDS.get(feed_name) or \
        CREDENTIALED_METADATA_FEEDS.get(feed_name)
    if definition is None:
        return {"status": "unknown_feed", "feed": feed_name, "ingested": 0}

    url = definition["url"]
    _assert_metadata_only(url)

    headers: Dict[str, str] = {"User-Agent": "SVS-Cyber-ThreatIntel/1"}
    env_var = definition.get("env_var")
    if env_var:
        key = auth_key or os.getenv(env_var)
        if not key:
            # Report the gap rather than fetching and getting an opaque 401.
            return {
                "status": "credential_missing",
                "feed": feed_name,
                "ingested": 0,
                "message": f"{feed_name} requires {definition['auth']}; set {env_var}.",
            }
        headers["Auth-Key"] = key

    version = feed_version or f"{feed_name}-{time.strftime('%Y%m%dT%H%M%S')}"
    run_id = store.start_feed_run(feed_name, version)
    try:
        raw = (fetcher or http_fetch)(url, headers)
        if definition.get("zip_member") or (isinstance(raw, bytes) and raw[:2] == b"PK"):
            raw = unzip_feed_member(raw, definition.get("zip_member"))
        records = parse_feed(definition["format"], raw, feed_name)
    except SampleDownloadRefused:
        raise
    except Exception as exc:
        error = _scrub(str(exc), auth_key, *headers.values())
        logger.error("feed %s failed: %s", feed_name, error)
        store.finish_feed_run(run_id, status="failed", error=error)
        return {"status": "fetch_failed", "feed": feed_name, "ingested": 0, "error": error}

    indicators = [_to_indicator(record, version) for record in records]
    counters = store.upsert_indicators(indicators, feed_version=version)
    store.finish_feed_run(
        run_id,
        status="completed",
        inserted=counters["inserted"],
        updated=counters["updated"],
        rejected=counters["rejected"],
    )
    return {
        "status": "success",
        "feed": feed_name,
        "feed_version": version,
        "parsed": len(records),
        "licence": definition["licence"],
        **counters,
    }


def _to_indicator(record: FeedRecord, feed_version: str) -> Any:
    from cyber_os.protection.store import IndicatorRecord

    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    return IndicatorRecord(
        indicator_type=record.indicator_type,
        indicator_value=record.indicator_value,
        source=record.source,
        # The store clamps this against the source's trust tier; passing the
        # feed's own claim through unmodified is intentional so the clamp is
        # the single place trust is decided.
        confidence=record.claimed_confidence if record.claimed_confidence is not None else 100,
        severity=record.severity,
        verification=record.claimed_verification,
        feed_version=feed_version,
        first_seen=record.source_timestamp or now,
        last_seen=now,
        sha256=record.sha256,
        sha1=record.sha1,
        md5=record.md5,
        threat_family=record.threat_family,
        source_timestamp=record.source_timestamp,
    )


def feed_catalogue() -> Dict[str, Any]:
    """Report every known feed, its licence, and whether it needs a credential."""
    return {
        "free": {
            name: {**definition, "credential_required": False}
            for name, definition in FREE_METADATA_FEEDS.items()
        },
        "credentialed": {
            name: {
                **definition,
                "credential_required": True,
                "credential_present": bool(os.getenv(definition.get("env_var", ""))),
            }
            for name, definition in CREDENTIALED_METADATA_FEEDS.items()
        },
        "sample_downloads": "never; _assert_metadata_only refuses them before any request",
    }


if __name__ == "__main__":
    manager = ThreatIntelManager()
    configured = manager.configured_providers
    print(f"ThreatIntelManager initialized. Configured providers: {configured or 'none'}")
    if not configured:
        print("Set VIRUSTOTAL_API_KEY and/or OTX_API_KEY to enable lookups.")
