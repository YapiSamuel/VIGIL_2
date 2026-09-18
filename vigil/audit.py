"""Operator audit logging.

Records *who ran what, when, and what left the machine* — the accountability
question that detection output alone cannot answer. This exists to support
organizational control requirements:

  NIST SP 800-171  3.3.1 / 3.3.2  (audit records; trace actions to users)
  NIST SP 800-53   AU-2, AU-3, AU-9
  ISO/IEC 27001    A.8.15 (logging), A.8.16 (monitoring activities)
  CIS Controls v8  Control 8 (Audit Log Management)

What is recorded: timestamp, operator, host, tool version, target identity
(path, hash, type), the verdict, and which egress paths were used.

What is NEVER recorded: file contents, decoded layer text, matched strings,
API keys, or any secret. The log is a record of *actions*, not of evidence —
so the log itself cannot become a data-leak channel.

Records are chained: each entry carries the hash of the previous entry, so
deletion or alteration of any line is detectable. This is tamper-*evidence*,
not tamper-*proofing*; an attacker with write access can rewrite the whole
chain. Ship the log to a WORM store or SIEM if you need the stronger property.

No network access. Local append-only file I/O only.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
from datetime import datetime, timezone
from typing import Optional

SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _operator() -> str:
    for getter in (getpass.getuser,):
        try:
            name = getter()
            if name:
                return str(name)
        except Exception:
            pass
    return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def _host() -> str:
    # platform.node() reads the local hostname; it performs no name resolution
    # and opens no socket.
    try:
        return platform.node() or "unknown"
    except Exception:
        return "unknown"


def _canonical(record: dict) -> str:
    """Stable serialization so the chain hash is reproducible."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      default=str)


def _last_hash(path: str) -> str:
    """Return the record_hash of the final entry, or the genesis value."""
    try:
        with open(path, "rb") as fh:
            tail = b""
            # Read the last chunk; audit lines are small, 8 KiB is ample.
            try:
                fh.seek(-8192, os.SEEK_END)
            except OSError:
                fh.seek(0)
            tail = fh.read()
    except (OSError, ValueError):
        return GENESIS_HASH
    lines = [ln for ln in tail.decode("utf-8", "replace").splitlines() if ln.strip()]
    for line in reversed(lines):
        try:
            return str(json.loads(line).get("record_hash") or GENESIS_HASH)
        except (json.JSONDecodeError, TypeError):
            continue
    return GENESIS_HASH


def build_record(event: str, target: Optional[dict] = None,
                 verdict: Optional[dict] = None,
                 egress: Optional[dict] = None,
                 vigil_version: str = "",
                 extra: Optional[dict] = None) -> dict:
    """Assemble an audit record. Contains no evidence text by construction."""
    record = {
        "schema": SCHEMA_VERSION,
        "ts": _utc_now(),
        "event": event,
        "operator": _operator(),
        "host": _host(),
        "vigil_version": vigil_version,
        "target": target or {},
        "verdict": verdict or {},
        "egress": egress or {},
    }
    if extra:
        record["extra"] = extra
    return record


def write(path: str, record: dict) -> bool:
    """Append ``record`` to the chained audit log. Returns True on success.

    Never raises: a failed audit write is reported to the caller so it can be
    surfaced as a note, but it does not abort the scan.
    """
    if not path:
        return False
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        prev = _last_hash(path)
        body = dict(record)
        body["prev_hash"] = prev
        body["record_hash"] = hashlib.sha256(
            (prev + _canonical(body)).encode("utf-8")
        ).hexdigest()
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, default=str) + "\n")
        return True
    except (OSError, TypeError, ValueError):
        return False


def verify(path: str) -> tuple[bool, int, Optional[int]]:
    """Verify the hash chain.

    Returns (ok, records_checked, first_bad_line). ``first_bad_line`` is
    1-indexed and None when the chain is intact.
    """
    prev = GENESIS_HASH
    checked = 0
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                checked += 1
                try:
                    body = json.loads(line)
                except json.JSONDecodeError:
                    return False, checked, lineno
                stated = body.get("record_hash")
                if body.get("prev_hash") != prev:
                    return False, checked, lineno
                recomputed_src = {k: v for k, v in body.items()
                                  if k != "record_hash"}
                expected = hashlib.sha256(
                    (prev + _canonical(recomputed_src)).encode("utf-8")
                ).hexdigest()
                if stated != expected:
                    return False, checked, lineno
                prev = str(stated)
    except OSError:
        return False, checked, None
    return True, checked, None
