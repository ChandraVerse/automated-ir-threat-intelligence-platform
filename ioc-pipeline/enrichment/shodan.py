"""
Shodan REST async client.
Docs: https://developer.shodan.io/api
"""
from __future__ import annotations
import asyncio
import os
from dataclasses import dataclass, field
from typing import Any

import aiohttp

BASE_URL = "https://api.shodan.io"


@dataclass
class ShodanHostResult:
    ip: str
    open_ports: list[int]
    vulns: list[str]          # CVE IDs
    hostnames: list[str]
    org: str
    os: str | None
    country_code: str
    tags: list[str]
    raw: dict = field(default_factory=dict)

    @property
    def risk_score(self) -> float:
        """
        Simple heuristic: 10 pts per critical port, 15 pts per CVE, capped at 100.
        """
        RISKY_PORTS = {21, 22, 23, 445, 3389, 4444, 5900, 6667}
        score = (
            len([p for p in self.open_ports if p in RISKY_PORTS]) * 10
            + len(self.vulns) * 15
        )
        return min(float(score), 100.0)


class ShodanClient:
    def __init__(self, api_key: str | None = None):
        self._api_key = api_key or os.environ.get("SHODAN_API_KEY", "")
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "ShodanClient":
        self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._session:
            await self._session.close()

    async def host_info(self, ip: str) -> ShodanHostResult:
        """GET /shodan/host/{ip}"""
        if not self._session:
            raise RuntimeError("Use async context manager")
        url = f"{BASE_URL}/shodan/host/{ip}"
        async with self._session.get(url, params={"key": self._api_key}) as resp:
            resp.raise_for_status()
            data = await resp.json()
        return ShodanHostResult(
            ip=data.get("ip_str", ip),
            open_ports=list(data.get("ports", [])),
            vulns=list(data.get("vulns", {}).keys()),
            hostnames=list(data.get("hostnames", [])),
            org=data.get("org", ""),
            os=data.get("os"),
            country_code=data.get("country_code", ""),
            tags=list(data.get("tags", [])),
            raw=data,
        )

    async def host_info_bulk(self, ips: list[str]) -> list[ShodanHostResult]:
        return await asyncio.gather(*[self.host_info(ip) for ip in ips])

    # ── Sync convenience wrapper ───────────────────────────────────────────
    def host_info_sync(self, ip: str) -> ShodanHostResult:
        return asyncio.get_event_loop().run_until_complete(self._run_single(ip))

    async def _run_single(self, ip: str) -> ShodanHostResult:
        async with ShodanClient(self._api_key) as c:
            return await c.host_info(ip)
