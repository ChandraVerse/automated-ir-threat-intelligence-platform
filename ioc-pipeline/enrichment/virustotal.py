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
    """
    Async VirusTotal v3 client.
    Supports lookups for IPs, domains, file hashes, and URLs.
    """

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
                    logger.warning("VT: IOC not found — %s", endpoint)
                    return {"error": "not_found"}
                elif resp.status == 429:
                    logger.warning("VT: Rate limit hit — backing off 60s")
                    await asyncio.sleep(60)
                    return await self._get(endpoint)
                else:
                    logger.error("VT: Unexpected status %s for %s", resp.status, endpoint)
                    return {"error": f"http_{resp.status}"}
        except aiohttp.ClientError as exc:
            logger.error("VT: Request error — %s", exc)
            return {"error": str(exc)}

    async def lookup_ip(self, ip: str) -> dict:
        """Look up an IP address on VirusTotal."""
        raw = await self._get(f"/ip_addresses/{ip}")
        return self._parse_response(raw, ioc=ip, ioc_type="ip")

    async def lookup_domain(self, domain: str) -> dict:
        """Look up a domain on VirusTotal."""
        raw = await self._get(f"/domains/{domain}")
        return self._parse_response(raw, ioc=domain, ioc_type="domain")

    async def lookup_hash(self, file_hash: str) -> dict:
        """Look up a file hash (MD5/SHA1/SHA256) on VirusTotal."""
        raw = await self._get(f"/files/{file_hash}")
        return self._parse_response(raw, ioc=file_hash, ioc_type="hash")

    async def lookup_url(self, url: str) -> dict:
        """Look up a URL on VirusTotal."""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        raw = await self._get(f"/urls/{url_id}")
        return self._parse_response(raw, ioc=url, ioc_type="url")

    def _parse_response(self, raw: dict, ioc: str, ioc_type: str) -> dict:
        """Normalise VirusTotal response into standard enrichment schema."""
        if "error" in raw:
            return {
                "source": "virustotal",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "error": raw["error"],
                "malicious_votes": 0,
                "total_engines": 0,
                "reputation": None,
                "tags": [],
                "categories": {},
            }

        attributes = raw.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        total = sum(last_analysis.values()) if last_analysis else 0

        return {
            "source": "virustotal",
            "ioc": ioc,
            "ioc_type": ioc_type,
            "malicious_votes": malicious,
            "suspicious_votes": suspicious,
            "total_engines": total,
            "reputation": attributes.get("reputation", 0),
            "tags": attributes.get("tags", []),
            "categories": attributes.get("categories", {}),
            "country": attributes.get("country", None),
            "as_owner": attributes.get("as_owner", None),
            "last_analysis_date": attributes.get("last_analysis_date", None),
        }
