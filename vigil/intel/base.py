"""Shared plumbing for intel clients.

This is the network boundary of VIGIL. Together with the client modules in
this package, it is the *only* place that makes outbound connections — every
other module in the project is offline and pure. That is deliberate: the
safety story ("can this tool phone home / leak my sample?") is auditable by
reading this one package.

All HTTP goes through :func:`http_json`, which tests monkeypatch. Every
network failure is caught and turned into a degraded result with a note, so
a rate limit or dead link produces a partial report, never a crash.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

DEFAULT_TIMEOUT = 15  # seconds per request


@dataclass
class IntelResult:
    source: str            # "virustotal" | "abuseipdb" | "urlhaus"
    indicator: str         # the hash/ip/url queried
    indicator_type: str    # "hash" | "ipv4" | "ipv6" | "domain" | "url"
    status: str            # "found" | "clean" | "not_found" | "skipped" | "error"
    malicious: bool = False
    score: Optional[int] = None      # source-native score (e.g. VT positives)
    total: Optional[int] = None      # source-native denominator (e.g. VT engines)
    detail: dict = field(default_factory=dict)
    note: str = ""


class RateLimiter:
    """Simple thread-safe minimum-interval limiter.

    VT free tier is 4 requests/minute; a 15s minimum interval keeps us
    comfortably under it. Time and sleep are injected so tests don't wait on
    a wall clock.
    """

    def __init__(self, min_interval: float, clock=time.monotonic, sleep=time.sleep):
        self.min_interval = min_interval
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._last = 0.0

    def acquire(self) -> None:
        with self._lock:
            now = self._clock()
            wait = self.min_interval - (now - self._last)
            if wait > 0:
                self._sleep(wait)
                now = self._clock()
            self._last = now


class IntelError(Exception):
    pass


def http_json(method: str, url: str, headers: Optional[dict] = None,
              params: Optional[dict] = None, data: Optional[bytes] = None,
              timeout: int = DEFAULT_TIMEOUT) -> tuple[int, dict]:
    """Perform an HTTP request and parse a JSON response.

    Returns (status_code, parsed_json). Raises IntelError on transport
    failure. This function is the single seam tests monkeypatch to avoid
    real network calls.
    """
    if params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            status = resp.getcode()
    except urllib.error.HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        status = exc.code
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise IntelError(str(exc)) from exc
    try:
        parsed = json.loads(body.decode("utf-8")) if body else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        parsed = {}
    return status, parsed
