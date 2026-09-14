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
from typing import Any, Dict, Optional

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
        response = requests.get(url, headers=headers, timeout=_REQUEST_TIMEOUT)
    except Exception as exc:  # network failure, DNS, TLS, timeout
        logger.error("%s request failed: %s", provider, exc)
        return _unknown("request_failed", f"{provider} request failed: {exc}")

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


if __name__ == "__main__":
    manager = ThreatIntelManager()
    configured = manager.configured_providers
    print(f"ThreatIntelManager initialized. Configured providers: {configured or 'none'}")
    if not configured:
        print("Set VIRUSTOTAL_API_KEY and/or OTX_API_KEY to enable lookups.")
