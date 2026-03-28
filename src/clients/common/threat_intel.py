"""Threat intelligence enrichment providers.

Supports Shodan InternetDB (keyless), AbuseIPDB, VirusTotal, and ThreatFox.
Each provider is optional — missing API keys cause graceful skip, not errors.
"""

import ipaddress
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger("crowdsentinel.threat_intel")

# Provider timeouts and rate limits
REQUEST_TIMEOUT = 10
VT_RATE_LIMIT_DELAY = 15  # seconds between VirusTotal calls (4/min free tier)


@dataclass(frozen=True)
class EnrichmentResult:
    """Immutable enrichment result from a single provider."""

    provider: str
    ioc_type: str
    ioc_value: str
    is_malicious: bool | None = None
    confidence: float = 0.5
    context: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------------------
# Provider weights for verdict aggregation
# ---------------------------------------------------------------------------

PROVIDER_WEIGHTS = {
    "virustotal": 0.35,
    "abuseipdb": 0.25,
    "threatfox": 0.25,
    "shodan_internetdb": 0.15,
}


def aggregate_verdicts(results: list[EnrichmentResult]) -> tuple[bool | None, float]:
    """Weighted verdict aggregation across providers.

    Returns (is_malicious, confidence) where confidence is 0.0-1.0.
    """
    verdicts = [r for r in results if r.is_malicious is not None and r.error is None]
    if not verdicts:
        return None, 0.5

    weighted_score = sum(
        (1.0 if r.is_malicious else 0.0) * PROVIDER_WEIGHTS.get(r.provider, 0.1) * r.confidence for r in verdicts
    )
    total_weight = sum(PROVIDER_WEIGHTS.get(r.provider, 0.1) for r in verdicts)

    final_confidence = weighted_score / total_weight if total_weight > 0 else 0.5
    is_malicious = final_confidence >= 0.5

    return is_malicious, round(final_confidence, 3)


def is_private_ip(ip: str) -> bool:
    """Check whether an IP is RFC1918/link-local/loopback."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Shodan InternetDB (free, keyless)
# ---------------------------------------------------------------------------


def enrich_shodan_internetdb(ioc_value: str) -> EnrichmentResult:
    """Query Shodan InternetDB for IP context. No API key required."""
    if is_private_ip(ioc_value):
        return EnrichmentResult(
            provider="shodan_internetdb",
            ioc_type="ip",
            ioc_value=ioc_value,
            context={"note": "Private IP — not queryable via InternetDB"},
            tags=["private-ip"],
        )

    try:
        resp = httpx.get(f"https://internetdb.shodan.io/{ioc_value}", timeout=REQUEST_TIMEOUT)
        if resp.status_code == 404:
            return EnrichmentResult(
                provider="shodan_internetdb",
                ioc_type="ip",
                ioc_value=ioc_value,
                context={"note": "IP not found in InternetDB"},
            )
        resp.raise_for_status()
        data = resp.json()

        vulns = data.get("vulns", [])
        tags = data.get("tags", [])
        is_malicious = bool(vulns) or "compromised" in tags
        confidence = min(0.6 + 0.05 * len(vulns), 0.9) if vulns else 0.3

        return EnrichmentResult(
            provider="shodan_internetdb",
            ioc_type="ip",
            ioc_value=ioc_value,
            is_malicious=is_malicious if (vulns or tags) else None,
            confidence=confidence,
            context={
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "cpes": data.get("cpes", []),
                "vulns": vulns,
                "tags": tags,
            },
            tags=tags,
        )
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(
            provider="shodan_internetdb",
            ioc_type="ip",
            ioc_value=ioc_value,
            error=f"HTTP {exc.response.status_code}",
        )
    except (httpx.TimeoutException, httpx.ConnectError, OSError) as exc:
        return EnrichmentResult(
            provider="shodan_internetdb",
            ioc_type="ip",
            ioc_value=ioc_value,
            error=f"Connection error: {exc}",
        )


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------


def enrich_abuseipdb(ioc_value: str, api_key: str | None = None) -> EnrichmentResult | None:
    """Query AbuseIPDB for IP reputation. Returns None if no API key."""
    key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
    if not key:
        return None

    if is_private_ip(ioc_value):
        return EnrichmentResult(
            provider="abuseipdb",
            ioc_type="ip",
            ioc_value=ioc_value,
            context={"note": "Private IP — not queryable"},
            tags=["private-ip"],
        )

    try:
        resp = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ioc_value, "maxAgeInDays": "90"},
            headers={"Key": key, "Accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 429:
            return EnrichmentResult(
                provider="abuseipdb", ioc_type="ip", ioc_value=ioc_value, error="Rate limit exceeded"
            )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        score = data.get("abuseConfidenceScore", 0)
        is_malicious = score >= 50

        return EnrichmentResult(
            provider="abuseipdb",
            ioc_type="ip",
            ioc_value=ioc_value,
            is_malicious=is_malicious,
            confidence=score / 100.0,
            context={
                "abuse_confidence_score": score,
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "usage_type": data.get("usageType", ""),
                "domain": data.get("domain", ""),
                "is_whitelisted": data.get("isWhitelisted", False),
            },
            tags=["high-abuse"] if score >= 80 else (["moderate-abuse"] if score >= 50 else []),
        )
    except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.ConnectError, OSError) as exc:
        return EnrichmentResult(
            provider="abuseipdb", ioc_type="ip", ioc_value=ioc_value, error=str(exc)
        )


# ---------------------------------------------------------------------------
# VirusTotal v3
# ---------------------------------------------------------------------------

# Timestamp of last VT call for rate limiting
_vt_last_call: float = 0.0


def _detect_hash_algorithm(hash_value: str) -> str:
    """Determine hash algorithm from length."""
    length = len(hash_value)
    if length == 32:
        return "MD5"
    if length == 40:
        return "SHA-1"
    if length == 64:
        return "SHA-256"
    return "unknown"


def enrich_virustotal(ioc_type: str, ioc_value: str, api_key: str | None = None) -> EnrichmentResult | None:
    """Query VirusTotal v3 for IP/domain/hash/URL enrichment. Returns None if no API key."""
    global _vt_last_call

    key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not key:
        return None

    # Rate limiting: 4 requests/minute on free tier
    elapsed = time.time() - _vt_last_call
    if elapsed < VT_RATE_LIMIT_DELAY:
        time.sleep(VT_RATE_LIMIT_DELAY - elapsed)

    type_map = {
        "ip": "ip_addresses",
        "domain": "domains",
        "hash": "files",
        "url": "urls",
    }
    vt_type = type_map.get(ioc_type)
    if not vt_type:
        return EnrichmentResult(
            provider="virustotal",
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            error=f"Unsupported IoC type for VT: {ioc_type}",
        )

    # URL needs base64 encoding (no padding) for VT API
    lookup_value = ioc_value
    if ioc_type == "url":
        import base64

        lookup_value = base64.urlsafe_b64encode(ioc_value.encode()).rstrip(b"=").decode()

    try:
        resp = httpx.get(
            f"https://www.virustotal.com/api/v3/{vt_type}/{lookup_value}",
            headers={"x-apikey": key},
            timeout=REQUEST_TIMEOUT,
        )
        _vt_last_call = time.time()

        if resp.status_code == 404:
            return EnrichmentResult(
                provider="virustotal",
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                context={"note": "Not found in VirusTotal"},
            )
        if resp.status_code == 429:
            return EnrichmentResult(
                provider="virustotal", ioc_type=ioc_type, ioc_value=ioc_value, error="Rate limit exceeded"
            )
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})

        # Extract detection stats
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        is_mal = (malicious + suspicious) >= 3 if total > 0 else None
        confidence = (malicious + suspicious) / total if total > 0 else 0.0

        context: dict[str, Any] = {
            "detection_stats": stats,
            "reputation": data.get("reputation", 0),
        }

        # Type-specific context
        if ioc_type == "ip":
            context["as_owner"] = data.get("as_owner", "")
            context["country"] = data.get("country", "")
        elif ioc_type == "hash":
            context["type_description"] = data.get("type_description", "")
            context["size"] = data.get("size", 0)
            context["names"] = data.get("names", [])[:5]
            context["hash_algorithm"] = _detect_hash_algorithm(ioc_value)
        elif ioc_type == "domain":
            context["registrar"] = data.get("registrar", "")
            context["creation_date"] = data.get("creation_date", 0)

        return EnrichmentResult(
            provider="virustotal",
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            is_malicious=is_mal,
            confidence=round(confidence, 3),
            context=context,
            tags=["vt-malicious"] if malicious >= 3 else [],
        )
    except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.ConnectError, OSError) as exc:
        _vt_last_call = time.time()
        return EnrichmentResult(
            provider="virustotal", ioc_type=ioc_type, ioc_value=ioc_value, error=str(exc)
        )


# ---------------------------------------------------------------------------
# ThreatFox (abuse.ch)
# ---------------------------------------------------------------------------


def enrich_threatfox(ioc_type: str, ioc_value: str, api_key: str | None = None) -> EnrichmentResult | None:
    """Query ThreatFox for IoC-to-malware mapping. Returns None if no API key."""
    key = api_key or os.environ.get("THREATFOX_API_KEY", "")
    if not key:
        return None

    supported_types = ("ip", "domain", "url", "hash")
    if ioc_type not in supported_types:
        return None

    try:
        resp = httpx.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc_value},
            headers={"API-KEY": key},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 429:
            return EnrichmentResult(
                provider="threatfox", ioc_type=ioc_type, ioc_value=ioc_value, error="Rate limit exceeded"
            )
        resp.raise_for_status()
        data = resp.json()

        query_status = data.get("query_status", "")
        if query_status == "no_result":
            return EnrichmentResult(
                provider="threatfox",
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                context={"note": "No match in ThreatFox"},
            )

        results = data.get("data", [])
        if not results:
            return EnrichmentResult(
                provider="threatfox",
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                context={"note": "No match in ThreatFox"},
            )

        # Take the first (most recent) result
        match = results[0]
        malware = match.get("malware", "")
        malware_printable = match.get("malware_printable", malware)
        threat_type = match.get("threat_type", "")
        confidence_level = match.get("confidence_level", 0)

        mitre = []
        malware_malpedia = match.get("malware_malpedia")
        if malware_malpedia and isinstance(malware_malpedia, str):
            mitre.append(malware_malpedia)

        return EnrichmentResult(
            provider="threatfox",
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            is_malicious=True,
            confidence=min(confidence_level / 100.0, 1.0) if confidence_level else 0.85,
            context={
                "malware_family": malware_printable,
                "threat_type": threat_type,
                "first_seen": match.get("first_seen", ""),
                "last_seen": match.get("last_seen_utc", ""),
                "reporter": match.get("reporter", ""),
                "reference": match.get("reference", ""),
                "tags": match.get("tags", []),
            },
            tags=[f"malware:{malware_printable}", f"threat:{threat_type}"] if malware_printable else [],
            mitre_techniques=mitre,
        )
    except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.ConnectError, OSError) as exc:
        return EnrichmentResult(
            provider="threatfox", ioc_type=ioc_type, ioc_value=ioc_value, error=str(exc)
        )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

# Maps IoC type to the providers that can handle it
IOC_TYPE_PROVIDERS = {
    "ip": ["shodan_internetdb", "abuseipdb", "virustotal", "threatfox"],
    "domain": ["virustotal", "threatfox"],
    "hash": ["virustotal", "threatfox"],
    "url": ["virustotal", "threatfox"],
    "hostname": ["virustotal"],
    "email": [],
    "user": [],
    "process": [],
    "commandline": [],
    "file_path": [],
    "registry_key": [],
    "service": [],
    "scheduled_task": [],
    "other": [],
}


def get_configured_providers() -> dict[str, dict[str, Any]]:
    """Report which providers are configured and available."""
    return {
        "shodan_internetdb": {
            "configured": True,
            "requires_key": False,
            "key_set": True,
        },
        "abuseipdb": {
            "configured": bool(os.environ.get("ABUSEIPDB_API_KEY")),
            "requires_key": True,
            "key_set": bool(os.environ.get("ABUSEIPDB_API_KEY")),
        },
        "virustotal": {
            "configured": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
            "requires_key": True,
            "key_set": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
        },
        "threatfox": {
            "configured": bool(os.environ.get("THREATFOX_API_KEY")),
            "requires_key": True,
            "key_set": bool(os.environ.get("THREATFOX_API_KEY")),
        },
    }


def enrich_single_ioc(
    ioc_type: str,
    ioc_value: str,
    providers: list[str] | None = None,
) -> list[EnrichmentResult]:
    """Enrich a single IoC across all applicable (and configured) providers.

    Returns a list of EnrichmentResult objects, one per provider queried.
    """
    applicable = IOC_TYPE_PROVIDERS.get(ioc_type, [])
    if providers:
        applicable = [p for p in applicable if p in providers]

    results: list[EnrichmentResult] = []

    for provider_name in applicable:
        result: EnrichmentResult | None = None

        if provider_name == "shodan_internetdb" and ioc_type == "ip":
            result = enrich_shodan_internetdb(ioc_value)

        elif provider_name == "abuseipdb" and ioc_type == "ip":
            result = enrich_abuseipdb(ioc_value)

        elif provider_name == "virustotal":
            result = enrich_virustotal(ioc_type, ioc_value)

        elif provider_name == "threatfox":
            result = enrich_threatfox(ioc_type, ioc_value)

        if result is not None:
            results.append(result)

    return results
