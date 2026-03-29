"""
AbuseIPDB v2 async client.
Docs: https://docs.abuseipdb.com/
"""
from __future__ import annotations
import asyncio
import os
from dataclasses import dataclass, field
from typing import Any

import aiohttp

BASE_URL = "https://api.abuseipdb.com/api/v2"


@dataclass
class AbuseIPDBResult:
    ip: str
    abuse_confidence_score: int        # 0-100
    total_reports: int
    country_code: str
    domain: str
    isp: str
    is_whitelisted: bool
    raw: dict = field(default_factory=dict)

    @property
    def normalised_score(self) -> float:
        """Map 0-100 confidence score to 0-100 threat score."""
        return float(self.abuse_confidence_score)


class AbuseIPDBClient:
    def __init__(self, api_key: str | None = None, max_age_days: int = 90):
        self._api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self._max_age_days = max_age_days
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "AbuseIPDBClient":
        self._session = aiohttp.ClientSession(
            headers={
                "Key": self._api_key,
                "Accept": "application/json",
            }
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._session:
            await self._session.close()

    async def check_ip(self, ip: str) -> AbuseIPDBResult:
        """Query /check endpoint for an IP address."""
        if not self._session:
            raise RuntimeError("Use async context manager")
        params = {
            "ipAddress": ip,
            "maxAgeInDays": self._max_age_days,
            "verbose": True,
        }
        async with self._session.get(f"{BASE_URL}/check", params=params) as resp:
            resp.raise_for_status()
            data = (await resp.json()).get("data", {})
        return AbuseIPDBResult(
            ip=data.get("ipAddress", ip),
            abuse_confidence_score=int(data.get("abuseConfidenceScore", 0)),
            total_reports=int(data.get("totalReports", 0)),
            country_code=data.get("countryCode", ""),
            domain=data.get("domain", ""),
            isp=data.get("isp", ""),
            is_whitelisted=bool(data.get("isWhitelisted", False)),
            raw=data,
        )

    async def check_bulk(self, ips: list[str]) -> list[AbuseIPDBResult]:
        return await asyncio.gather(*[self.check_ip(ip) for ip in ips])

    # ── Sync convenience wrappers ──────────────────────────────────────────
    def check_ip_sync(self, ip: str) -> AbuseIPDBResult:
        return asyncio.get_event_loop().run_until_complete(self._run_single(ip))

    async def _run_single(self, ip: str) -> AbuseIPDBResult:
        async with AbuseIPDBClient(self._api_key, self._max_age_days) as c:
            return await c.check_ip(ip)
