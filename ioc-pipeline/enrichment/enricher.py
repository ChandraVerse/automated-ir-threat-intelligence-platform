"""
Enrichment entry point — supports CLI usage and module import.
Run: python -m ioc_pipeline.enrichment.enricher --ioc 185.220.101.45 --type ip
"""

import asyncio
import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ioc_pipeline.enrichment.virustotal import VirusTotalClient
from ioc_pipeline.enrichment.abuseipdb import AbuseIPDBClient
from ioc_pipeline.enrichment.shodan import ShodanClient
from ioc_pipeline.cache.ioc_cache import IOCCache
from ioc_pipeline.verdict_engine import VerdictEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s — %(message)s")
logger = logging.getLogger(__name__)


async def enrich_ioc(ioc: str, ioc_type: str, config: dict) -> dict:
    """
    Fully enrich a single IOC against all three TI sources.
    Returns a combined enrichment result with a composite verdict.
    """
    cache = IOCCache(db_path=config.get("cache", {}).get("db_path", "ioc_cache.db"))
    verdict_engine = VerdictEngine()

    # Check cache first
    cached = cache.get(ioc, ioc_type)
    if cached:
        logger.info("Cache HIT for %s (%s)", ioc, ioc_type)
        return cached

    ti_cfg = config.get("threat_intel", {})
    vt_client = VirusTotalClient(api_key=ti_cfg.get("virustotal_api_key", ""))
    abuse_client = AbuseIPDBClient(api_key=ti_cfg.get("abuseipdb_api_key", ""))
    shodan_client = ShodanClient(api_key=ti_cfg.get("shodan_api_key", ""))

    tasks = []
    if ioc_type == "ip":
        tasks = [
            vt_client.lookup_ip(ioc),
            abuse_client.lookup_ip(ioc),
            shodan_client.lookup_ip(ioc),
        ]
    elif ioc_type == "domain":
        tasks = [
            vt_client.lookup_domain(ioc),
            asyncio.coroutine(lambda: {"source": "abuseipdb", "ioc": ioc, "error": "domain_not_supported"})(),
            asyncio.coroutine(lambda: {"source": "shodan", "ioc": ioc, "error": "domain_not_supported"})(),
        ]
    elif ioc_type == "hash":
        tasks = [
            vt_client.lookup_hash(ioc),
            asyncio.coroutine(lambda: {"source": "abuseipdb", "ioc": ioc, "error": "hash_not_supported"})(),
            asyncio.coroutine(lambda: {"source": "shodan", "ioc": ioc, "error": "hash_not_supported"})(),
        ]
    elif ioc_type == "url":
        tasks = [
            vt_client.lookup_url(ioc),
            asyncio.coroutine(lambda: {"source": "abuseipdb", "ioc": ioc, "error": "url_not_supported"})(),
            asyncio.coroutine(lambda: {"source": "shodan", "ioc": ioc, "error": "url_not_supported"})(),
        ]
    else:
        return {"error": f"Unsupported IOC type: {ioc_type}"}

    vt_result, abuse_result, shodan_result = await asyncio.gather(*tasks)
    await vt_client.close()

    verdict = verdict_engine.compute(
        vt_result=vt_result,
        abuse_result=abuse_result,
        shodan_result=shodan_result,
    )

    enriched = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "virustotal": vt_result,
        "abuseipdb": abuse_result,
        "shodan": shodan_result,
        "verdict": verdict,
    }

    ttl = config.get("cache", {}).get("ttl_seconds", 86400)
    cache.set(ioc, ioc_type, enriched, ttl=ttl)

    return enriched


def main():
    parser = argparse.ArgumentParser(description="Enrich a single IOC against VT, AbuseIPDB, and Shodan")
    parser.add_argument("--ioc", required=True, help="IOC value (IP, domain, hash, or URL)")
    parser.add_argument("--type", dest="ioc_type", required=True,
                        choices=["ip", "domain", "hash", "url"], help="IOC type")
    parser.add_argument("--config", default="config/config.yml", help="Path to config YAML")
    args = parser.parse_args()

    import yaml
    cfg = {}
    try:
        with open(args.config) as f:
            cfg = yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning("Config file not found at %s — using empty config", args.config)

    result = asyncio.run(enrich_ioc(args.ioc, args.ioc_type, cfg))
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
