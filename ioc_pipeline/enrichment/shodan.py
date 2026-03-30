"""
Shodan REST async client.
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
    open_ports: list
    vulns: list
    hostnames: list
    org: str
    os: str | None
    country_code: str
    tags: list
    raw: dict = field(default_factory=dict)


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

    # alias used by dispatcher
    lookup_host_async = host_info
