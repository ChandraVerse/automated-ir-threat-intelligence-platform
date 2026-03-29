"""
Pipeline entry point.
Supports two modes:
  1. --alert-file  : Process a single Wazuh alert JSON file
  2. --mode webhook: Start an HTTP listener and process alerts in real time

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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wazuh_integration.parsers.alert_normaliser import AlertNormaliser
from wazuh_integration.parsers.ioc_extractor import extract_iocs_from_alert
from ioc_pipeline.dispatcher import EnrichmentDispatcher
from soar_automation.triage.triage_engine import TriageEngine
from soar_automation.responder import Responder
from report_generator.generator import ReportGenerator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("pipeline")


def load_config(config_path: str) -> dict:
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("Config not found at %s — using defaults", config_path)
        return {}


async def process_alert(alert_raw: dict, config: dict) -> dict:
    """Full pipeline: normalise → extract IOCs → enrich → triage → respond → report."""
    normaliser = AlertNormaliser()
    alert = normaliser.normalise(alert_raw)
    logger.info("Processing alert: [%s] %s", alert.get("severity"), alert.get("description"))

    iocs = extract_iocs_from_alert(alert)
    logger.info("Extracted %d IOCs", len(iocs))

    dispatcher = EnrichmentDispatcher(config=config)
    enriched_iocs = await dispatcher.enrich_all(iocs)

    triage = TriageEngine(config=config)
    triage_result = triage.evaluate(alert=alert, enriched_iocs=enriched_iocs)
    logger.info("Triage result: %s (confidence: %s%%)", triage_result["verdict"], triage_result.get("confidence"))

    responder = Responder(config=config)
    response_actions = await responder.execute(triage_result=triage_result, alert=alert)
    logger.info("SOAR actions taken: %s", response_actions)

    report_gen = ReportGenerator(config=config)
    report_path = report_gen.generate(
        alert=alert,
        enriched_iocs=enriched_iocs,
        triage_result=triage_result,
        response_actions=response_actions,
    )
    logger.info("Report generated: %s", report_path)

    return {
        "alert": alert,
        "iocs": enriched_iocs,
        "triage": triage_result,
        "response_actions": response_actions,
        "report_path": str(report_path),
    }


async def handle_webhook(request: web.Request) -> web.Response:
    """Webhook handler for incoming Wazuh active-response POST requests."""
    config = request.app["config"]
    try:
        alert_raw = await request.json()
    except Exception as exc:
        logger.error("Failed to parse webhook body: %s", exc)
        return web.Response(status=400, text="Invalid JSON")

    asyncio.create_task(process_alert(alert_raw, config))
    return web.Response(status=202, text="Accepted")


async def run_webhook_server(config: dict, port: int):
    app = web.Application()
    app["config"] = config
    app.router.add_post("/alert", handle_webhook)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    logger.info("Webhook listener started on port %d — POST alerts to /alert", port)
    while True:
        await asyncio.sleep(3600)


def main():
    parser = argparse.ArgumentParser(description="Automated IR & Threat Intelligence Pipeline")
    parser.add_argument("--alert-file", help="Path to a Wazuh alert JSON file to process")
    parser.add_argument("--mode", choices=["webhook"], help="Pipeline mode")
    parser.add_argument("--port", type=int, default=8080, help="Webhook listener port (default: 8080)")
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
