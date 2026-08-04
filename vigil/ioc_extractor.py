"""Indicator-of-compromise extraction over every deobfuscation layer.

Consumes the ``Layer`` tree from :mod:`vigil.deobfuscator` via ``flatten()``
so an IOC buried three decodes deep is found exactly like one in plaintext.
Every IOC carries the layer id and technique it was found in, so the report
can always answer "where did this come from."

Pure text analysis. No DNS resolution, no network, no filesystem.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable

from .deobfuscator import Layer, flatten

# Refang map: attackers and analysts both "defang" IOCs so they aren't
# clickable. We reverse the common encodings before matching so a defanged
# C2 address is caught, then report the original (fanged) value.
_REFANG_SUBSTITUTIONS = [
    ("[.]", "."), ("(.)", "."), ("{.}", "."), (" dot ", "."), ("[dot]", "."),
    ("[:]", ":"), ("[://]", "://"),
    ("hxxps", "https"), ("hxxp", "http"),
    ("fxp", "ftp"),
    ("[at]", "@"), ("(at)", "@"),
]

# TLD sanity list keeps random dotted tokens (version strings, filenames like
# config.json) from being reported as domains. Not exhaustive by design; it
# is a noise filter, not an allowlist of the internet.
_COMMON_TLDS = {
    "com", "net", "org", "io", "co", "ru", "cn", "info", "biz", "xyz", "top",
    "site", "online", "club", "shop", "pw", "cc", "tk", "ml", "ga", "cf", "gq",
    "gov", "edu", "mil", "int", "us", "uk", "de", "fr", "nl", "br", "in", "ir",
    "ua", "pl", "it", "es", "ca", "au", "jp", "kr", "tv", "me", "app", "dev",
    "su", "ws", "name", "pro", "mobi", "asia", "live", "life", "world", "link",
    "click", "download", "zip", "mov", "rest", "monster", "sbs", "cyou",
}

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_IPV6_RE = re.compile(
    r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"
)
_URL_RE = re.compile(
    r"\b(?:https?|ftp)://[^\s'\"<>()\[\]{}|\\^`]+",
    re.IGNORECASE,
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,24}\b"
)


@dataclass(frozen=True)
class IOCHit:
    layer_id: int
    technique: str


@dataclass
class IOC:
    value: str
    ioc_type: str  # "ipv4" | "ipv6" | "domain" | "url"
    hits: list[IOCHit] = field(default_factory=list)
    defanged: bool = False


def refang(text: str) -> tuple[str, bool]:
    """Return (refanged_text, changed). Case-insensitive for the scheme
    tokens; literal for the bracket tricks."""
    original = text
    lowered = text
    for needle, repl in _REFANG_SUBSTITUTIONS:
        if needle.lower() in lowered.lower():
            # rebuild case-insensitively for scheme words, literally for others
            lowered = re.sub(re.escape(needle), repl, lowered, flags=re.IGNORECASE)
    return lowered, (lowered != original)


def _is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def _is_public_ipv6(value: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def _plausible_domain(value: str) -> bool:
    value = value.rstrip(".")
    if len(value) > 253:
        return False
    labels = value.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1].lower()
    if tld not in _COMMON_TLDS:
        return False
    # A domain whose "name" is all digits and dots is an IP we already handle.
    if all(label.isdigit() for label in labels):
        return False
    return True


def _host_from_url(url: str) -> str:
    rest = url.split("://", 1)[1]
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    host = host.split("@")[-1]      # strip userinfo
    host = host.split(":")[0]       # strip port (ipv6 handled below)
    if rest.startswith("[") or host.startswith("["):
        # bracketed IPv6 literal
        m = re.search(r"\[([^\]]+)\]", rest)
        if m:
            return m.group(1)
    return host


def _extract_from_text(text: str) -> list[tuple[str, str, bool]]:
    """Return (value, ioc_type, defanged) tuples found in one text blob."""
    found: list[tuple[str, str, bool]] = []
    refanged, was_defanged = refang(text)

    for m in _URL_RE.finditer(refanged):
        url = m.group().rstrip(".,);'\"]}")
        found.append((url, "url", was_defanged))

    for m in _IPV4_RE.finditer(refanged):
        if _is_public_ipv4(m.group()):
            found.append((m.group(), "ipv4", was_defanged))

    for m in _IPV6_RE.finditer(refanged):
        if _is_public_ipv6(m.group()):
            found.append((m.group(), "ipv6", was_defanged))

    # Domains: from URLs' hostnames and from bare tokens.
    for value, ioc_type, _ in list(found):
        if ioc_type == "url":
            host = _host_from_url(value)
            if host and _plausible_domain(host):
                found.append((host.lower(), "domain", was_defanged))

    for m in _DOMAIN_RE.finditer(refanged):
        if _plausible_domain(m.group()):
            found.append((m.group().lower().rstrip("."), "domain", was_defanged))

    return found


def extract(root: Layer) -> list[IOC]:
    """Extract deduplicated IOCs across every layer of the tree.

    IOCs are deduped by (type, value); every layer an IOC appears in is
    recorded as a hit so provenance is preserved.
    """
    index: dict[tuple[str, str], IOC] = {}
    for layer in flatten(root):
        for value, ioc_type, defanged in _extract_from_text(layer.text):
            key = (ioc_type, value)
            if key not in index:
                index[key] = IOC(value=value, ioc_type=ioc_type, defanged=defanged)
            ioc = index[key]
            if defanged:
                ioc.defanged = True
            hit = IOCHit(layer_id=layer.id, technique=layer.technique)
            if hit not in ioc.hits:
                ioc.hits.append(hit)

    # Stable, useful ordering: type then value.
    order = {"url": 0, "domain": 1, "ipv4": 2, "ipv6": 3}
    return sorted(index.values(), key=lambda i: (order.get(i.ioc_type, 9), i.value))


def summarize(iocs: Iterable[IOC]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ioc in iocs:
        counts[ioc.ioc_type] = counts.get(ioc.ioc_type, 0) + 1
    return counts
