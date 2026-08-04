"""VirusTotal client — hash-first by default.

Hard rule: we look up a file by its SHA256. We NEVER upload the file itself
unless the caller passes ``allow_upload=True`` (wired to the CLI's
``--upload`` flag) — because a file uploaded to VT becomes retrievable by
VT's paid customers, and in a corporate SOC that can be a compliance
violation. Hash-first-by-default is what makes VIGIL deployable instead of
banned on day one.
"""

from __future__ import annotations

import os
from typing import Optional

from .base import IntelError, IntelResult, RateLimiter, http_json

API_BASE = "https://www.virustotal.com/api/v3"


def _api_key(explicit: Optional[str]) -> Optional[str]:
    return explicit or os.environ.get("VT_API_KEY") or None


def lookup_hash(sha256: str, api_key: Optional[str] = None,
                limiter: Optional[RateLimiter] = None) -> IntelResult:
    """Look up a file report by hash. No upload, ever, from this function."""
    key = _api_key(api_key)
    if not key:
        return IntelResult("virustotal", sha256, "hash", "skipped",
                           note="no VT_API_KEY configured")
    if limiter:
        limiter.acquire()
    try:
        status, body = http_json(
            "GET", f"{API_BASE}/files/{sha256}",
            headers={"x-apikey": key},
        )
    except IntelError as exc:
        return IntelResult("virustotal", sha256, "hash", "error",
                           note=f"network error: {exc}")

    if status == 404:
        return IntelResult("virustotal", sha256, "hash", "not_found",
                           note="hash unknown to VirusTotal")
    if status == 401:
        return IntelResult("virustotal", sha256, "hash", "error",
                           note="VT rejected the API key (401)")
    if status == 429:
        return IntelResult("virustotal", sha256, "hash", "error",
                           note="VT rate limit hit (429); try later")
    if status != 200:
        return IntelResult("virustotal", sha256, "hash", "error",
                           note=f"VT returned HTTP {status}")

    stats = (
        body.get("data", {}).get("attributes", {})
        .get("last_analysis_stats", {})
    )
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or None
    positives = malicious + suspicious
    return IntelResult(
        "virustotal", sha256, "hash",
        status="found" if positives else "clean",
        malicious=positives > 0,
        score=positives, total=total,
        detail={"stats": stats},
        note=f"{positives}/{total} engines flagged" if total else "",
    )


def upload_file(path: str, api_key: Optional[str] = None,
                allow_upload: bool = False,
                limiter: Optional[RateLimiter] = None) -> IntelResult:
    """Upload a file to VT for analysis. Refuses unless ``allow_upload`` is
    explicitly True. The CLI must also print a warning before calling this."""
    sha_placeholder = os.path.basename(path)
    if not allow_upload:
        return IntelResult("virustotal", sha_placeholder, "hash", "skipped",
                           note="upload not permitted (no --upload flag)")
    key = _api_key(api_key)
    if not key:
        return IntelResult("virustotal", sha_placeholder, "hash", "skipped",
                           note="no VT_API_KEY configured")
    if limiter:
        limiter.acquire()
    try:
        with open(path, "rb") as fh:
            file_bytes = fh.read()
    except OSError as exc:
        return IntelResult("virustotal", sha_placeholder, "hash", "error",
                           note=f"could not read file: {exc}")

    # multipart/form-data body
    boundary = "----vigilupload"
    filename = os.path.basename(path)
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + file_bytes + f"\r\n--{boundary}--\r\n".encode()
    try:
        status, resp = http_json(
            "POST", f"{API_BASE}/files",
            headers={
                "x-apikey": key,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            data=body,
        )
    except IntelError as exc:
        return IntelResult("virustotal", sha_placeholder, "hash", "error",
                           note=f"network error: {exc}")
    if status not in (200, 201):
        return IntelResult("virustotal", sha_placeholder, "hash", "error",
                           note=f"VT upload returned HTTP {status}")
    analysis_id = resp.get("data", {}).get("id", "")
    return IntelResult("virustotal", sha_placeholder, "hash", "found",
                       detail={"analysis_id": analysis_id},
                       note="uploaded; analysis queued (results not immediate)")
