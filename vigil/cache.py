"""SQLite-backed analysis cache keyed by SHA256.

A cache hit lets VIGIL skip re-analysis of a file it has already seen,
which matters most for the rate-limited intel lookups. The cache is a
convenience, never a correctness dependency: any storage failure degrades
silently to a miss so a broken DB can never break a scan.

No network access. Local SQLite only.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Optional

DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24 hours
SCHEMA_VERSION = 1


@dataclass
class CacheEntry:
    sha256: str
    created_at: float
    schema_version: int
    payload: dict


class Cache:
    """A thin wrapper over a SQLite table. Time is injected so tests are
    deterministic and the module never reaches for a live clock implicitly."""

    def __init__(self, db_path: str, ttl_seconds: int = DEFAULT_TTL_SECONDS,
                 clock=time.time):
        self.db_path = db_path
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._conn: Optional[sqlite3.Connection] = None
        self._broken = False
        self._connect()

    def _connect(self) -> None:
        try:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_cache (
                    sha256          TEXT PRIMARY KEY,
                    created_at      REAL NOT NULL,
                    schema_version  INTEGER NOT NULL,
                    payload         TEXT NOT NULL
                )
                """
            )
            self._conn.commit()
        except sqlite3.Error:
            # A cache we can't open is a cache we do without.
            self._broken = True
            self._conn = None

    def get(self, sha256: str) -> Optional[dict]:
        """Return the cached payload for ``sha256`` if present, current
        schema, and not expired. Otherwise None."""
        if self._broken or self._conn is None:
            return None
        try:
            row = self._conn.execute(
                "SELECT created_at, schema_version, payload FROM "
                "analysis_cache WHERE sha256 = ?",
                (sha256,),
            ).fetchone()
        except sqlite3.Error:
            return None
        if row is None:
            return None
        created_at, schema_version, payload_text = row
        if schema_version != SCHEMA_VERSION:
            return None
        if self._clock() - created_at > self.ttl_seconds:
            return None
        try:
            return json.loads(payload_text)
        except (json.JSONDecodeError, TypeError):
            return None

    def put(self, sha256: str, payload: dict) -> bool:
        """Store ``payload`` under ``sha256``. Returns True on success."""
        if self._broken or self._conn is None:
            return False
        try:
            payload_text = json.dumps(payload, default=str)
        except (TypeError, ValueError):
            return False
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO analysis_cache "
                "(sha256, created_at, schema_version, payload) "
                "VALUES (?, ?, ?, ?)",
                (sha256, self._clock(), SCHEMA_VERSION, payload_text),
            )
            self._conn.commit()
            return True
        except sqlite3.Error:
            return False

    def purge_expired(self) -> int:
        """Delete expired rows. Returns the number removed (0 if broken)."""
        if self._broken or self._conn is None:
            return 0
        cutoff = self._clock() - self.ttl_seconds
        try:
            cur = self._conn.execute(
                "DELETE FROM analysis_cache WHERE created_at < ?", (cutoff,)
            )
            self._conn.commit()
            return cur.rowcount
        except sqlite3.Error:
            return 0

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    def __enter__(self) -> "Cache":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
