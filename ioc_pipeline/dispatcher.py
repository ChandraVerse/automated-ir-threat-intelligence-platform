#!/usr/bin/env python3
"""
dispatcher.py — Async enrichment orchestrator.
Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
"""

import asyncio
import logging
import time

from ioc_pipeline.enrichment.virustotal import VirusTotalClient
from ioc_pipeline.enrichment.abuseipdb  import AbuseIPDBClient
from ioc_pipeline.enrichment.shodan     import ShodanClient
from ioc_pipeline.verdict_engine        import VerdictEngine
from ioc_pipeline.cache.ioc_cache       import IOCCache

log = logging.getLogger(__name__)


class EnrichmentDispatcher:
    def __init__(self, config: dict):
        self.vt     = VirusTotalClient(config["threat_intel"]["virustotal_api_key"])
        self.abuse  = AbuseIPDBClient(config["threat_intel"]["abuseipdb_api_key"])
        self.shodan = ShodanClient(config["threat_intel"]["shodan_api_key"])
        self.verdict_engine = VerdictEngine()
        self.cache  = IOCCache(
            db_path=config.get("cache", {}).get("db_path", ":memory:"),
            ttl_seconds=config.get("cache", {}).get("ttl_seconds", 86400),
        )

    async def _enrich_ip(self, ip: str) -> dict:
        cached = self.cache.get("ip", ip)
        if cached:
            return cached
        vt_result, abuse_result, shodan_result = await asyncio.gather(
            self.vt.lookup_ip_async(ip),
            self.abuse.check_ip_async(ip),
            self.shodan.lookup_host_async(ip),
            return_exceptions=True,
        )
        enrichment = {
            "ioc_type"  : "ip", "value": ip,
            "virustotal": vt_result    if not isinstance(vt_result, Exception)    else {"error": str(vt_result)},
            "abuseipdb" : abuse_result if not isinstance(abuse_result, Exception) else {"error": str(abuse_result)},
            "shodan"    : shodan_result if not isinstance(shodan_result, Exception) else {"error": str(shodan_result)},
        }
        verdict = self.verdict_engine.compute(enrichment)
        enrichment.update(verdict)
        self.cache.set("ip", ip, enrichment)
        return enrichment

    async def enrich_alert(self, alert) -> dict:
        start = time.perf_counter()
        tasks = [self._enrich_ip(ioc.value) for ioc in alert.iocs if ioc.ioc_type == "ip"]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.perf_counter() - start
        verdicts = [r.get("verdict", "UNKNOWN") for r in results if isinstance(r, dict)]
        overall = (
            "MALICIOUS" if "MALICIOUS" in verdicts else
            "SUSPICIOUS" if "SUSPICIOUS" in verdicts else
            "CLEAN" if verdicts else "UNKNOWN"
        )
        return {
            "alert_id": alert.alert_id, "iocs": results,
            "overall_verdict": overall, "enrichment_time_s": round(elapsed, 3),
        }
