"""
SOAR Responder
Executes automated response actions: firewall block, EDR isolate, Jira ticket, Slack notify.
"""
from __future__ import annotations
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class ResponderError(Exception):
    pass


class FirewallBlocker:
    """Stub for firewall API integration (e.g., Palo Alto, pfSense)."""

    def block_ip(self, ip: str, direction: str = "both", duration_hours: int = 72) -> dict:
        logger.info("[FIREWALL] Blocking IP %s (%s) for %dh", ip, direction, duration_hours)
        # Replace with actual API call
        return {"status": "blocked", "ip": ip, "duration_hours": duration_hours}

    def unblock_ip(self, ip: str) -> dict:
        logger.info("[FIREWALL] Unblocking IP %s", ip)
        return {"status": "unblocked", "ip": ip}


class EDRResponder:
    """Stub for EDR integration (e.g., CrowdStrike, SentinelOne)."""

    def isolate_host(self, host: str, reason: str = "") -> dict:
        logger.info("[EDR] Isolating host %s — %s", host, reason)
        return {"status": "isolated", "host": host}

    def quarantine_hash(self, file_hash: str, reason: str = "") -> dict:
        logger.info("[EDR] Quarantining hash %s — %s", file_hash, reason)
        return {"status": "quarantined", "hash": file_hash}


class JiraTicketCreator:
    """Creates Jira tickets via REST API."""

    def __init__(self, base_url: str | None = None, token: str | None = None):
        self.base_url = base_url or os.environ.get("JIRA_BASE_URL", "")
        self.token = token or os.environ.get("JIRA_API_TOKEN", "")

    def create(self, project: str, summary: str, description: str,
               issuetype: str = "Incident", priority: str = "High",
               labels: list[str] | None = None) -> dict:
        logger.info("[JIRA] Creating ticket in %s: %s", project, summary)
        # Real implementation: POST /rest/api/3/issue
        return {
            "status": "created",
            "key": f"{project}-AUTO",
            "summary": summary,
        }


class SlackNotifier:
    """Sends alerts to Slack via webhook or SDK."""

    def __init__(self, webhook_url: str | None = None, bot_token: str | None = None):
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL", "")
        self.bot_token = bot_token or os.environ.get("SLACK_BOT_TOKEN", "")

    def notify(self, channel: str, message: str) -> dict:
        logger.info("[SLACK] → %s: %s", channel, message[:80])
        if self.webhook_url:
            try:
                import requests
                resp = requests.post(self.webhook_url, json={"text": message}, timeout=10)
                return {"status": "sent", "http": resp.status_code}
            except Exception as exc:
                raise ResponderError(f"Slack webhook failed: {exc}") from exc
        return {"status": "stub", "channel": channel}


class Responder:
    """Orchestrates all response actions for a given playbook step."""

    def __init__(self):
        self.firewall = FirewallBlocker()
        self.edr = EDRResponder()
        self.jira = JiraTicketCreator()
        self.slack = SlackNotifier()

    def execute(self, action: str, params: dict[str, Any]) -> dict:
        """Dispatch a playbook action string to the correct handler."""
        handlers = {
            "firewall.block": lambda p: self.firewall.block_ip(
                p["target"], p.get("direction", "both"), p.get("duration_hours", 72)
            ),
            "firewall.unblock": lambda p: self.firewall.unblock_ip(p["target"]),
            "edr.isolate": lambda p: self.edr.isolate_host(p["host"], p.get("reason", "")),
            "edr.quarantine": lambda p: self.edr.quarantine_hash(p["hash"], p.get("reason", "")),
            "jira.create_ticket": lambda p: self.jira.create(
                p.get("project", "SEC"), p.get("summary", "Auto Ticket"),
                p.get("description", ""), p.get("issuetype", "Incident"),
                p.get("priority", "High"), p.get("labels", [])
            ),
            "slack.notify": lambda p: self.slack.notify(p["channel"], p["message"]),
        }
        if action not in handlers:
            raise ResponderError(f"Unknown action: {action}")
        return handlers[action](params)
