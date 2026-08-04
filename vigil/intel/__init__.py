"""Threat-intel orchestration.

Runs the individual clients in parallel and collects their results. This
package is the entire network surface of VIGIL; nothing else in the project
opens a socket.

Design choices enforced here:
  * Hash-first. The file hash is looked up before anything else. The file
    itself is never uploaded unless ``allow_upload`` is set.
  * Bounded fan-out. IOCs are capped so a script stuffed with 10,000 domains
    cannot trigger 10,000 lookups (which would also blow the rate limits).
  * Graceful degradation. A missing key or a dead endpoint yields a
    skipped/error result with a note, never an exception that aborts scan.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

from ..ioc_extractor import IOC
from .abuseipdb_client import lookup_ip
from .base import IntelResult, RateLimiter
from .urlhaus_client import lookup_host, lookup_url
from .vt_client import lookup_hash

# Keep intel fan-out bounded and rate-limit-friendly.
MAX_IPS = 10
MAX_URLS = 10
MAX_DOMAINS = 10


@dataclass
class IntelConfig:
    vt_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    enable_vt: bool = True
    enable_abuseipdb: bool = True
    enable_urlhaus: bool = True
    allow_upload: bool = False
    max_workers: int = 6


@dataclass
class IntelBundle:
    results: list[IntelResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def malicious_count(self) -> int:
        return sum(1 for r in self.results if r.malicious)


def gather(sha256: str, iocs: list[IOC], config: Optional[IntelConfig] = None,
           vt_limiter: Optional[RateLimiter] = None) -> IntelBundle:
    """Look up the file hash plus a bounded set of IOCs across all sources,
    in parallel. Returns an :class:`IntelBundle`."""
    config = config or IntelConfig()
    bundle = IntelBundle()

    # VT's free tier is the tightest (4/min); serialize its calls through a
    # shared limiter so parallel workers don't burst past it.
    vt_limiter = vt_limiter or RateLimiter(min_interval=15.0)

    ips = [i for i in iocs if i.ioc_type in ("ipv4", "ipv6")][:MAX_IPS]
    urls = [i for i in iocs if i.ioc_type == "url"][:MAX_URLS]
    domains = [i for i in iocs if i.ioc_type == "domain"][:MAX_DOMAINS]

    dropped = []
    total_ips = sum(1 for i in iocs if i.ioc_type in ("ipv4", "ipv6"))
    if total_ips > MAX_IPS:
        dropped.append(f"{total_ips - MAX_IPS} IP(s)")
    total_urls = sum(1 for i in iocs if i.ioc_type == "url")
    if total_urls > MAX_URLS:
        dropped.append(f"{total_urls - MAX_URLS} URL(s)")
    total_domains = sum(1 for i in iocs if i.ioc_type == "domain")
    if total_domains > MAX_DOMAINS:
        dropped.append(f"{total_domains - MAX_DOMAINS} domain(s)")
    if dropped:
        bundle.notes.append(
            "intel lookups capped; skipped " + ", ".join(dropped)
            + " to respect rate limits"
        )

    tasks = []

    # Hash-first: this is always the first task queued.
    if config.enable_vt:
        tasks.append(("vt_hash", lambda: lookup_hash(
            sha256, api_key=config.vt_api_key, limiter=vt_limiter)))

    if config.enable_abuseipdb:
        for ioc in ips:
            tasks.append((f"abuse:{ioc.value}", (lambda i: lambda: lookup_ip(
                i.value, i.ioc_type, api_key=config.abuseipdb_api_key))(ioc)))

    if config.enable_urlhaus:
        for ioc in urls:
            tasks.append((f"urlhaus_url:{ioc.value}",
                          (lambda i: lambda: lookup_url(i.value))(ioc)))
        for ioc in domains:
            tasks.append((f"urlhaus_host:{ioc.value}",
                          (lambda i: lambda: lookup_host(i.value, "domain"))(ioc)))

    if not tasks:
        bundle.notes.append("all intel sources disabled")
        return bundle

    with ThreadPoolExecutor(max_workers=max(1, config.max_workers)) as pool:
        futures = [pool.submit(fn) for _, fn in tasks]
        for fut in futures:
            try:
                bundle.results.append(fut.result())
            except Exception as exc:  # a client should never raise, but be safe
                bundle.notes.append(f"intel lookup crashed: {exc}")

    # Surface skipped sources once, as a single note, so the report can tell
    # the analyst the picture is partial.
    skipped_sources = sorted({
        r.source for r in bundle.results if r.status == "skipped"
    })
    if skipped_sources:
        bundle.notes.append(
            "no API key for: " + ", ".join(skipped_sources)
            + " (results are partial; local analysis still applies)"
        )
    return bundle
