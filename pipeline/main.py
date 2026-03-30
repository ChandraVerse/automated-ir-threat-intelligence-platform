"""
Pipeline entry point — Automated IR & Threat Intelligence Platform.

Modes:
  --alert-file  : Process a single Wazuh alert JSON file
  --mode webhook: Start an HTTP listener and process alerts in real time

Usage:
  python -m pipeline.main --alert-file samples/sample_alert.json
  python -m pipeline.main --mode webhook --port 8080
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

import yaml
from aiohttp import web

from wazuh_integration.parsers.alert_normaliser import normalise_alert
from wazuh_integration.parsers.ioc_extractor import extract_iocs_from_alert
from ioc_pipeline.dispatcher import EnrichmentDispatcher
from soar_automation.triage.triage_engine import TriageEngine
from soar_automation.responder import Responder
from report_generator.generator import generate_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s \u2014 %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("pipeline")


def load_config(config_path: str) -> dict:
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("Config not found at %s \u2014 using defaults", config_path)
        return {}


async def process_alert(alert_raw: dict, config: dict) -> dict:
    """Full pipeline: normalise \u2192 extract IOCs \u2192 enrich \u2192 triage \u2192 respond."""
    alert = normalise_alert(alert_raw)
    if alert is None:
        logger.error("Failed to normalise alert, skipping.")
        return {}

    logger.info("Processing alert: [%s] %s", alert.severity, alert.rule_name)

    iocs = extract_iocs_from_alert(alert_raw)
    logger.info("Extracted %d IOCs", len(iocs))

    dispatcher = EnrichmentDispatcher(config=config)
    enrichment_result = await dispatcher.enrich_alert(alert)
    logger.info("Enrichment complete: overall_verdict=%s", enrichment_result.get("overall_verdict"))

    triage_engine = TriageEngine()
    triage_result = triage_engine.triage(
        alert=alert_raw,
        ioc_score=enrichment_result.get("iocs", [{}])[0].get("risk_score", 0.0)
        if enrichment_result.get("iocs") else 0.0,
    )
    logger.info("Triage: %s (score=%.1f)", triage_result.priority.name, triage_result.score)

    responder = Responder(config=config)
    response_actions = await responder.execute(
        triage_result={"verdict": enrichment_result.get("overall_verdict", "UNKNOWN"),
                       "recommended_playbook": triage_result.recommended_playbook},
        alert=alert_raw,
    )
    logger.info("SOAR actions: %s", response_actions)

    return {
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "enrichment": enrichment_result,
        "triage_priority": triage_result.priority.name,
        "triage_score": triage_result.score,
        "response_actions": response_actions,
    }


async def handle_webhook(request: web.Request) -> web.Response:
    """Webhook handler for incoming Wazuh alert POST requests."""
    config = request.app["config"]
    try:
        alert_raw = await request.json()
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to parse webhook body: %s", exc)
        return web.Response(status=400, text="Invalid JSON")

    asyncio.create_task(process_alert(alert_raw, config))
    return web.Response(status=202, text="Accepted")


async def run_webhook_server(config: dict, port: int) -> None:
    app = web.Application()
    app["config"] = config
    app.router.add_post("/alert", handle_webhook)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)  # noqa: B104
    await site.start()
    logger.info("Webhook listener started on port %d", port)
    while True:
        await asyncio.sleep(3600)


def main() -> None:
    parser = argparse.ArgumentParser(description="Automated IR & Threat Intelligence Pipeline")
    parser.add_argument("--alert-file", help="Path to a Wazuh alert JSON file")
    parser.add_argument("--mode", choices=["webhook"], help="Pipeline mode")
    parser.add_argument("--port", type=int, default=8080, help="Webhook listener port")
    parser.add_argument("--config", default="config/config.yml", help="Path to config YAML")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.alert_file:
        with open(args.alert_file) as f:
            alert_raw = json.load(f)
        result = asyncio.run(process_alert(alert_raw, config))
        print(json.dumps(result, indent=2, default=str))

    elif args.mode == "webhook":
        asyncio.run(run_webhook_server(config, args.port))

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
