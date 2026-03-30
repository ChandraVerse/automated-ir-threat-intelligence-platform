#!/usr/bin/env python3
"""
ioc_cache.py — SQLite-backed IOC cache with configurable TTL.
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

    def __init__(self, db_path: str = ":memory:", ttl_seconds: int = 86400):
        self.db_path     = db_path
        self.ttl_seconds = ttl_seconds
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(self.CREATE_SQL)

    def get(self, ioc_type: str, value: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT data, cached_at, ttl FROM ioc_cache WHERE ioc_type=? AND value=?",
                (ioc_type, value),
            ).fetchone()
        if not row:
            return None
        if time.time() - row["cached_at"] > row["ttl"]:
            self.delete(ioc_type, value)
            return None
        return json.loads(row["data"])

    def set(self, ioc_type: str, value: str, data: dict, ttl: Optional[int] = None):
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ioc_cache (ioc_type, value, data, cached_at, ttl) VALUES (?, ?, ?, ?, ?)",
                (ioc_type, value, json.dumps(data), time.time(), ttl or self.ttl_seconds),
            )

    def delete(self, ioc_type: str, value: str):
        with self._conn() as conn:
            conn.execute("DELETE FROM ioc_cache WHERE ioc_type=? AND value=?", (ioc_type, value))

    def purge_expired(self) -> int:
        with self._conn() as conn:
            cursor = conn.execute("DELETE FROM ioc_cache WHERE (cached_at + ttl) < ?", (time.time(),))
            return cursor.rowcount
