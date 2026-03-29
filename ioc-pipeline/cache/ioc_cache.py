#!/usr/bin/env python3
"""
ioc_cache.py
============
SQLite-backed IOC cache with configurable TTL.
Prevents redundant API calls for recently seen indicators.

Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
"""

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


class IOCCache:
    """
    Persistent SQLite cache for IOC enrichment results.

    Schema:
        ioc_type  TEXT  — ip | hash | url | domain
        value     TEXT  — the indicator value
        data      TEXT  — JSON-encoded enrichment result
        cached_at REAL  — Unix timestamp when cached
        ttl       REAL  — seconds before expiry
    """

    CREATE_SQL = """
    CREATE TABLE IF NOT EXISTS ioc_cache (
        ioc_type  TEXT NOT NULL,
        value     TEXT NOT NULL,
        data      TEXT NOT NULL,
        cached_at REAL NOT NULL,
        ttl       REAL NOT NULL,
        PRIMARY KEY (ioc_type, value)
    );
    CREATE INDEX IF NOT EXISTS idx_ioc ON ioc_cache (ioc_type, value);
    """

    def __init__(self, db_path: str = "ioc-pipeline/cache/ioc_cache.db", ttl_seconds: int = 86400):
        """
        Args:
            db_path     : Path to SQLite database file
            ttl_seconds : Cache TTL in seconds (default: 24 hours)
        """
        self.db_path     = db_path
        self.ttl_seconds = ttl_seconds
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(self.CREATE_SQL)
        log.debug("IOC cache initialised at %s", self.db_path)

    def get(self, ioc_type: str, value: str) -> Optional[dict]:
        """
        Retrieve cached enrichment for an IOC.

        Returns:
            Enrichment dict if cache hit and not expired, else None.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT data, cached_at, ttl FROM ioc_cache WHERE ioc_type=? AND value=?",
                (ioc_type, value),
            ).fetchone()

        if not row:
            return None

        age = time.time() - row["cached_at"]
        if age > row["ttl"]:
            log.debug("Cache expired for %s:%s (age=%.0fs)", ioc_type, value[:20], age)
            self.delete(ioc_type, value)
            return None

        log.debug("Cache hit for %s:%s (age=%.0fs)", ioc_type, value[:20], age)
        return json.loads(row["data"])

    def set(self, ioc_type: str, value: str, data: dict, ttl: Optional[int] = None):
        """Store enrichment result in cache."""
        with self._conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO ioc_cache (ioc_type, value, data, cached_at, ttl)
                   VALUES (?, ?, ?, ?, ?)""",
                (ioc_type, value, json.dumps(data), time.time(), ttl or self.ttl_seconds),
            )
        log.debug("Cached %s:%s (ttl=%ds)", ioc_type, value[:20], ttl or self.ttl_seconds)

    def delete(self, ioc_type: str, value: str):
        """Remove a specific IOC from cache."""
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM ioc_cache WHERE ioc_type=? AND value=?",
                (ioc_type, value),
            )

    def purge_expired(self) -> int:
        """Delete all expired entries. Returns number of rows removed."""
        cutoff = time.time()
        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM ioc_cache WHERE (cached_at + ttl) < ?",
                (cutoff,),
            )
            removed = cursor.rowcount
        if removed:
            log.info("Purged %d expired cache entries", removed)
        return removed

    def stats(self) -> dict:
        """Return cache statistics."""
        with self._conn() as conn:
            total   = conn.execute("SELECT COUNT(*) FROM ioc_cache").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM ioc_cache WHERE (cached_at + ttl) < ?",
                (time.time(),),
            ).fetchone()[0]
            by_type = conn.execute(
                "SELECT ioc_type, COUNT(*) as cnt FROM ioc_cache GROUP BY ioc_type"
            ).fetchall()
        return {
            "total_entries": total,
            "expired"      : expired,
            "valid"        : total - expired,
            "by_type"      : {row["ioc_type"]: row["cnt"] for row in by_type},
            "db_path"      : self.db_path,
            "ttl_seconds"  : self.ttl_seconds,
        }
