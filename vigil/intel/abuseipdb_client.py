"""AbuseIPDB client — reputation lookup for IPv4/IPv6 indicators."""

from __future__ import annotations

import os
from typing import Optional

from .base import IntelError, IntelResult, RateLimiter, http_json

API_URL = "https://api.abuseipdb.com/api/v2/check"
# AbuseIPDB flags an address as worth escalating around this confidence.
ABUSE_THRESHOLD = 25


def _api_key(explicit: Optional[str]) -> Optional[str]:
    # Environment first, then the optional local store (see credentials.py).
    from ..credentials import get as _cred
    return explicit or _cred("ABUSEIPDB_API_KEY") or None


def lookup_ip(ip: str, ip_type: str = "ipv4", api_key: Optional[str] = None,
              limiter: Optional[RateLimiter] = None,
              max_age_days: int = 90) -> IntelResult:
    key = _api_key(api_key)
    if not key:
        return IntelResult("abuseipdb", ip, ip_type, "skipped",
                           note="no ABUSEIPDB_API_KEY configured")
    if limiter:
        limiter.acquire()
    try:
        status, body = http_json(
            "GET", API_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": str(max_age_days)},
        )
    except IntelError as exc:
        return IntelResult("abuseipdb", ip, ip_type, "error",
                           note=f"network error: {exc}")

    if status == 401:
        return IntelResult("abuseipdb", ip, ip_type, "error",
                           note="AbuseIPDB rejected the API key (401)")
    if status == 429:
        return IntelResult("abuseipdb", ip, ip_type, "error",
                           note="AbuseIPDB rate limit hit (429); try later")
    if status != 200:
        return IntelResult("abuseipdb", ip, ip_type, "error",
                           note=f"AbuseIPDB returned HTTP {status}")

    data = body.get("data", {})
    confidence = int(data.get("abuseConfidenceScore", 0))
    reports = int(data.get("totalReports", 0))
    return IntelResult(
        "abuseipdb", ip, ip_type,
        status="found" if confidence >= ABUSE_THRESHOLD else "clean",
        malicious=confidence >= ABUSE_THRESHOLD,
        score=confidence, total=100,
        detail={
            "totalReports": reports,
            "countryCode": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
        },
        note=f"abuse confidence {confidence}% from {reports} reports",
    )
