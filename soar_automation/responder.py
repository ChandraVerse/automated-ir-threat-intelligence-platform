"""
SOAR Responder — Executes automated response actions.
Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
"""
from __future__ import annotations
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class ResponderError(Exception):
    pass


class FirewallBlocker:
    def block_ip(self, ip: str, direction: str = "both", duration_hours: int = 72) -> dict:
        logger.info("[FIREWALL] Blocking IP %s (%s) for %dh", ip, direction, duration_hours)
        return {"status": "blocked", "ip": ip, "duration_hours": duration_hours}

    def unblock_ip(self, ip: str) -> dict:
        return {"status": "unblocked", "ip": ip}


class EDRResponder:
    def isolate_host(self, host: str, reason: str = "") -> dict:
        return {"status": "isolated", "host": host}

    def quarantine_hash(self, file_hash: str, reason: str = "") -> dict:
        return {"status": "quarantined", "hash": file_hash}


class JiraTicketCreator:
    def __init__(self, base_url: str | None = None, token: str | None = None):
        self.base_url = base_url or os.environ.get("JIRA_BASE_URL", "")
        self.token    = token or os.environ.get("JIRA_API_TOKEN", "")

    def create(self, project: str, summary: str, description: str,
               issuetype: str = "Incident", priority: str = "High",
               labels: list | None = None) -> dict:
        return {"status": "created", "key": f"{project}-AUTO", "summary": summary}


class SlackNotifier:
    def __init__(self, webhook_url: str | None = None, bot_token: str | None = None):
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL", "")
        self.bot_token   = bot_token or os.environ.get("SLACK_BOT_TOKEN", "")

    def notify(self, channel: str, message: str) -> dict:
        logger.info("[SLACK] -> %s: %s", channel, message[:80])
        if self.webhook_url:
            try:
                import requests
                resp = requests.post(self.webhook_url, json={"text": message}, timeout=10)
                return {"status": "sent", "http": resp.status_code}
            except Exception as exc:  # noqa: BLE001
                raise ResponderError(f"Slack webhook failed: {exc}") from exc
        return {"status": "stub", "channel": channel}


class Responder:
    def __init__(self, config: dict | None = None):
        self.config   = config or {}
        self.firewall = FirewallBlocker()
        self.edr      = EDRResponder()
        self.jira     = JiraTicketCreator(
            base_url=self.config.get("soar", {}).get("jira_url"),
            token=self.config.get("soar", {}).get("jira_token"),
        )
        self.slack    = SlackNotifier(
            webhook_url=self.config.get("soar", {}).get("slack_webhook_url"),
        )
        self.dry_run: bool = self.config.get("soar", {}).get("dry_run", False)

    async def execute(self, triage_result: dict, alert: dict) -> list:
        actions: list = []
        verdict  = triage_result.get("verdict", "")
        playbook = triage_result.get("recommended_playbook", "")
        if self.dry_run:
            return [{"action": "dry_run", "playbook": playbook, "verdict": verdict}]
        if verdict == "MALICIOUS" and playbook in ("malicious_ip", "suspicious_ip"):
            src_ip = alert.get("src_ip", "")
            if src_ip:
                actions.append(self.dispatch("firewall.block", {"target": src_ip}))
            actions.append(self.dispatch("slack.notify", {
                "channel": "#security-alerts",
                "message": f":rotating_light: MALICIOUS IP {src_ip} blocked.",
            }))
        elif verdict == "SUSPICIOUS":
            actions.append(self.dispatch("slack.notify", {
                "channel": "#security-alerts",
                "message": f":warning: SUSPICIOUS activity detected. Review required.",
            }))
        return actions

    def dispatch(self, action: str, params: dict[str, Any]) -> dict:
        handlers = {
            "firewall.block":   lambda p: self.firewall.block_ip(p["target"], p.get("direction", "both")),
            "firewall.unblock": lambda p: self.firewall.unblock_ip(p["target"]),
            "edr.isolate":      lambda p: self.edr.isolate_host(p["host"], p.get("reason", "")),
            "edr.quarantine":   lambda p: self.edr.quarantine_hash(p["hash"], p.get("reason", "")),
            "jira.create_ticket": lambda p: self.jira.create(
                p.get("project", "SEC"), p.get("summary", ""),
                p.get("description", ""), p.get("priority", "High"), p.get("labels", [])
            ),
            "slack.notify": lambda p: self.slack.notify(p["channel"], p["message"]),
        }
        if action not in handlers:
            raise ResponderError(f"Unknown action: {action}")
        result = handlers[action](params)
        result["action"] = action
        return result
