"""
VirusTotal v3 API client for IOC enrichment.
Supports IP, domain, URL, and file hash lookups.
"""

import asyncio
import aiohttp
import logging
from typing import Optional

logger = logging.getLogger(__name__)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(headers=self.headers)
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

    async def _get(self, endpoint: str) -> dict:
        session = await self._get_session()
        url = f"{VT_BASE_URL}{endpoint}"
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 404:
                    return {"error": "not_found"}
                elif resp.status == 429:
                    await asyncio.sleep(60)
                    return await self._get(endpoint)
                else:
                    return {"error": f"http_{resp.status}"}
        except aiohttp.ClientError as exc:
            return {"error": str(exc)}

    async def lookup_ip(self, ip: str) -> dict:
        raw = await self._get(f"/ip_addresses/{ip}")
        return self._parse_response(raw, ioc=ip, ioc_type="ip")

    async def lookup_domain(self, domain: str) -> dict:
        raw = await self._get(f"/domains/{domain}")
        return self._parse_response(raw, ioc=domain, ioc_type="domain")

    async def lookup_hash(self, file_hash: str) -> dict:
        raw = await self._get(f"/files/{file_hash}")
        return self._parse_response(raw, ioc=file_hash, ioc_type="hash")

    async def lookup_url(self, url: str) -> dict:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        raw = await self._get(f"/urls/{url_id}")
        return self._parse_response(raw, ioc=url, ioc_type="url")

    # aliases used by dispatcher
    lookup_ip_async   = lookup_ip
    lookup_hash_async = lookup_hash
    lookup_url_async  = lookup_url

    def _parse_response(self, raw: dict, ioc: str, ioc_type: str) -> dict:
        if "error" in raw:
            return {"source": "virustotal", "ioc": ioc, "ioc_type": ioc_type, "error": raw["error"],
                    "malicious": 0, "harmless": 0, "suspicious": 0, "undetected": 0, "reputation": 0}
        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "source": "virustotal", "ioc": ioc, "ioc_type": ioc_type,
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "harmless":    stats.get("harmless", 0),
            "undetected":  stats.get("undetected", 0),
            "reputation":  attrs.get("reputation", 0),
            "tags":        attrs.get("tags", []),
        }
