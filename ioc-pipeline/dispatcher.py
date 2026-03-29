#!/usr/bin/env python3
"""
dispatcher.py
=============
Async enrichment orchestrator. Takes a list of IOCs, fans out
parallel async lookups to VirusTotal, AbuseIPDB, and Shodan,
merges results through the verdict engine, and returns enriched IOCs.

Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
"""

import asyncio
import logging
import time
from typing import Optional

from ioc_pipeline.enrichment.virustotal  import VirusTotalClient
from ioc_pipeline.enrichment.abuseipdb   import AbuseIPDBClient
from ioc_pipeline.enrichment.shodan      import ShodanClient
from ioc_pipeline.verdict_engine          import VerdictEngine
from ioc_pipeline.cache.ioc_cache         import IOCCache

log = logging.getLogger(__name__)


class EnrichmentDispatcher:
    """
    Orchestrates async multi-source IOC enrichment.

    Usage:
        dispatcher = EnrichmentDispatcher(config)
        enriched_iocs = await dispatcher.enrich_alert(normalised_alert)
    """

    def __init__(self, config: dict):
        self.vt     = VirusTotalClient(config["threat_intel"]["virustotal_api_key"])
        self.abuse  = AbuseIPDBClient(config["threat_intel"]["abuseipdb_api_key"])
        self.shodan = ShodanClient(config["threat_intel"]["shodan_api_key"])
        self.verdict_engine = VerdictEngine()
        self.cache  = IOCCache(
            db_path=config.get("cache", {}).get("db_path", "ioc-pipeline/cache/ioc_cache.db"),
            ttl_seconds=config.get("cache", {}).get("ttl_seconds", 86400),
        )
        self.rate_limit_delay = config.get("pipeline", {}).get("rate_limit_delay", 0.5)

    async def _enrich_ip(self, ip: str) -> dict:
        """Enrich a single IP across all three sources concurrently."""
        # Check cache first
        cached = self.cache.get("ip", ip)
        if cached:
            log.debug("Cache hit for IP: %s", ip)
            return cached

        vt_task    = asyncio.create_task(self.vt.lookup_ip_async(ip))
        abuse_task = asyncio.create_task(self.abuse.check_ip_async(ip))
        shodan_task= asyncio.create_task(self.shodan.lookup_host_async(ip))

        vt_result, abuse_result, shodan_result = await asyncio.gather(
            vt_task, abuse_task, shodan_task,
            return_exceptions=True,
        )

        enrichment = {
            "ioc_type"   : "ip",
            "value"      : ip,
            "virustotal" : vt_result    if not isinstance(vt_result, Exception)    else {"error": str(vt_result)},
            "abuseipdb"  : abuse_result if not isinstance(abuse_result, Exception) else {"error": str(abuse_result)},
            "shodan"     : shodan_result if not isinstance(shodan_result, Exception) else {"error": str(shodan_result)},
        }
        verdict = self.verdict_engine.compute(enrichment)
        enrichment["verdict"]    = verdict["verdict"]
        enrichment["confidence"] = verdict["confidence"]
        enrichment["risk_score"] = verdict["risk_score"]

        self.cache.set("ip", ip, enrichment)
        return enrichment

    async def _enrich_hash(self, file_hash: str) -> dict:
        """Enrich a file hash — only VirusTotal supports hash lookups."""
        cached = self.cache.get("hash", file_hash)
        if cached:
            log.debug("Cache hit for hash: %s", file_hash[:16])
            return cached

        vt_result = await self.vt.lookup_hash_async(file_hash)
        enrichment = {
            "ioc_type"   : "hash",
            "value"      : file_hash,
            "virustotal" : vt_result if not isinstance(vt_result, Exception) else {"error": str(vt_result)},
        }
        verdict = self.verdict_engine.compute(enrichment)
        enrichment["verdict"]    = verdict["verdict"]
        enrichment["confidence"] = verdict["confidence"]
        enrichment["risk_score"] = verdict["risk_score"]

        self.cache.set("hash", file_hash, enrichment)
        return enrichment

    async def _enrich_url(self, url: str) -> dict:
        """Enrich a URL via VirusTotal URL scan."""
        cached = self.cache.get("url", url)
        if cached:
            log.debug("Cache hit for URL")
            return cached

        vt_result = await self.vt.lookup_url_async(url)
        enrichment = {
            "ioc_type"   : "url",
            "value"      : url,
            "virustotal" : vt_result if not isinstance(vt_result, Exception) else {"error": str(vt_result)},
        }
        verdict = self.verdict_engine.compute(enrichment)
        enrichment["verdict"]    = verdict["verdict"]
        enrichment["confidence"] = verdict["confidence"]
        enrichment["risk_score"] = verdict["risk_score"]

        self.cache.set("url", url, enrichment)
        return enrichment

    async def enrich_ioc(self, ioc) -> dict:
        """Route a single IOC to the correct enrichment handler."""
        if ioc.ioc_type == "ip":
            return await self._enrich_ip(ioc.value)
        elif ioc.ioc_type == "hash":
            return await self._enrich_hash(ioc.value)
        elif ioc.ioc_type == "url":
            return await self._enrich_url(ioc.value)
        else:
            log.warning("Unsupported IOC type: %s", ioc.ioc_type)
            return {"ioc_type": ioc.ioc_type, "value": ioc.value, "verdict": "UNKNOWN"}

    async def enrich_alert(self, alert) -> dict:
        """
        Enrich all IOCs in a NormalisedAlert.

        Returns:
            Dict with enriched alert data and IOC results.
        """
        start = time.perf_counter()
        log.info(
            "Enriching alert %s — %d IOCs — rule: %s",
            alert.alert_id, len(alert.iocs), alert.rule_name
        )

        tasks = [self.enrich_ioc(ioc) for ioc in alert.iocs]
        enriched_iocs = await asyncio.gather(*tasks, return_exceptions=True)

        # Attach enrichment back to IOC objects
        results = []
        for ioc, enrichment in zip(alert.iocs, enriched_iocs):
            if isinstance(enrichment, Exception):
                log.error("Enrichment error for %s: %s", ioc.value, enrichment)
                enrichment = {"verdict": "ERROR", "error": str(enrichment)}
            ioc.enrichment = enrichment
            ioc.verdict    = enrichment.get("verdict", "UNKNOWN")
            results.append(enrichment)

        elapsed = time.perf_counter() - start
        log.info("Alert %s enriched in %.2fs", alert.alert_id, elapsed)

        # Determine highest-severity verdict across all IOCs
        verdicts = [r.get("verdict", "UNKNOWN") for r in results]
        overall  = "MALICIOUS" if "MALICIOUS" in verdicts else \
                   "SUSPICIOUS" if "SUSPICIOUS" in verdicts else \
                   "CLEAN" if verdicts else "UNKNOWN"

        return {
            "alert_id"         : alert.alert_id,
            "rule_name"        : alert.rule_name,
            "severity"         : alert.severity,
            "rule_level"       : alert.rule_level,
            "timestamp"        : alert.timestamp,
            "agent_name"       : alert.agent_name,
            "agent_ip"         : alert.agent_ip,
            "mitre_techniques" : alert.mitre_techniques,
            "mitre_tactics"    : alert.mitre_tactics,
            "iocs"             : results,
            "overall_verdict"  : overall,
            "enrichment_time_s": round(elapsed, 3),
            "raw_log"          : alert.raw_log,
        }

    async def enrich_batch(self, alerts: list) -> list[dict]:
        """Enrich a batch of NormalisedAlerts concurrently."""
        return await asyncio.gather(
            *[self.enrich_alert(a) for a in alerts],
            return_exceptions=True,
        )
