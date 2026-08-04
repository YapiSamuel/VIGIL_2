"""URLhaus (abuse.ch) client — malicious-URL / host lookup.

URLhaus does not require an API key for its lookup endpoints, so this client
works out of the box. It is still network access, so it lives here in the
intel package and degrades gracefully on any failure.
"""

from __future__ import annotations

import urllib.parse
from typing import Optional

from .base import IntelError, IntelResult, RateLimiter, http_json

URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"


def _post_form(endpoint: str, fields: dict) -> tuple[int, dict]:
    data = urllib.parse.urlencode(fields).encode()
    return http_json(
        "POST", endpoint,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data,
    )


def lookup_url(url: str, limiter: Optional[RateLimiter] = None) -> IntelResult:
    if limiter:
        limiter.acquire()
    try:
        status, body = _post_form(URL_ENDPOINT, {"url": url})
    except IntelError as exc:
        return IntelResult("urlhaus", url, "url", "error",
                           note=f"network error: {exc}")
    if status != 200:
        return IntelResult("urlhaus", url, "url", "error",
                           note=f"URLhaus returned HTTP {status}")

    query_status = body.get("query_status")
    if query_status == "no_results":
        return IntelResult("urlhaus", url, "url", "not_found",
                           note="URL unknown to URLhaus")
    if query_status != "ok":
        return IntelResult("urlhaus", url, "url", "error",
                           note=f"URLhaus query_status={query_status}")

    threat = body.get("threat", "")
    url_status = body.get("url_status", "")
    tags = body.get("tags") or []
    is_malicious = url_status != "offline" or bool(threat)
    return IntelResult(
        "urlhaus", url, "url",
        status="found",
        malicious=is_malicious,
        detail={"threat": threat, "url_status": url_status, "tags": tags},
        note=f"listed: {threat or 'malicious'} ({url_status or 'unknown'})",
    )


def lookup_host(host: str, host_type: str = "domain",
                limiter: Optional[RateLimiter] = None) -> IntelResult:
    if limiter:
        limiter.acquire()
    try:
        status, body = _post_form(HOST_ENDPOINT, {"host": host})
    except IntelError as exc:
        return IntelResult("urlhaus", host, host_type, "error",
                           note=f"network error: {exc}")
    if status != 200:
        return IntelResult("urlhaus", host, host_type, "error",
                           note=f"URLhaus returned HTTP {status}")

    query_status = body.get("query_status")
    if query_status == "no_results":
        return IntelResult("urlhaus", host, host_type, "not_found",
                           note="host unknown to URLhaus")
    if query_status != "ok":
        return IntelResult("urlhaus", host, host_type, "error",
                           note=f"URLhaus query_status={query_status}")

    count = int(body.get("url_count", 0) or 0)
    blacklists = body.get("blacklists") or {}
    return IntelResult(
        "urlhaus", host, host_type,
        status="found" if count else "clean",
        malicious=count > 0,
        score=count,
        detail={"url_count": count, "blacklists": blacklists},
        note=f"{count} malicious URLs seen on this host",
    )
