"""
SOAR Responder
Executes automated response actions: firewall block, EDR isolate, Jira ticket, Slack notify.
"""
from __future__ import annotations
import asyncio
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
    """Orchestrates all response actions for a given triage result."""

    def __init__(self, config: dict | None = None):
        self.config = config or {}
        self.firewall = FirewallBlocker()
        self.edr = EDRResponder()
        self.jira = JiraTicketCreator(
            base_url=self.config.get("soar", {}).get("jira_url"),
            token=self.config.get("soar", {}).get("jira_token"),
        )
        self.slack = SlackNotifier(
            webhook_url=self.config.get("soar", {}).get("slack_webhook_url"),
        )
        self.dry_run: bool = self.config.get("soar", {}).get("dry_run", False)

    async def execute(self, triage_result: dict, alert: dict) -> list[dict]:
        """
        Execute automated SOAR actions based on triage verdict.
        Called by pipeline/main.py with triage_result and alert dicts.

        Args:
            triage_result : Output from TriageEngine (dict with 'verdict', 'confidence' etc.)
            alert         : Normalised alert dict

        Returns:
            List of action result dicts
        """
        actions_taken: list[dict] = []
        verdict = triage_result.get("verdict", "")
        playbook = triage_result.get("recommended_playbook", "")
        agent = alert.get("agent_name", alert.get("agent", {}).get("name", "unknown"))

        if self.dry_run:
            logger.info("[DRY RUN] Would execute playbook=%s for verdict=%s", playbook, verdict)
            return [{"action": "dry_run", "playbook": playbook, "verdict": verdict}]

        # Malicious IP — block + ticket + notify
        if verdict == "MALICIOUS" and playbook in ("malicious_ip", "suspicious_ip"):
            src_ip = alert.get("src_ip") or alert.get("data", {}).get("srcip", "")
            if src_ip:
                actions_taken.append(self.dispatch("firewall.block", {"target": src_ip}))

            actions_taken.append(self.dispatch("jira.create_ticket", {
                "project": "SEC",
                "summary": f"MALICIOUS IOC detected: {src_ip or 'unknown'}",
                "description": f"Alert: {alert.get('rule_name', '')}\nAgent: {agent}\n"
                               f"Triage: {triage_result}",
                "priority": "High",
                "labels": ["auto-ir", "malicious"],
            }))

            actions_taken.append(self.dispatch("slack.notify", {
                "channel": "#security-alerts",
                "message": f":rotating_light: MALICIOUS IP {src_ip} blocked. Agent: {agent}",
            }))

        # Malicious hash — quarantine
        elif verdict == "MALICIOUS" and playbook == "malicious_hash":
            file_hash = alert.get("file_hash", "")
            if file_hash:
                actions_taken.append(self.dispatch("edr.quarantine", {
                    "hash": file_hash,
                    "reason": "MALICIOUS verdict from composite IOC engine",
                }))

        # Suspicious — notify only
        elif verdict == "SUSPICIOUS":
            actions_taken.append(self.dispatch("slack.notify", {
                "channel": "#security-alerts",
                "message": f":warning: SUSPICIOUS activity on agent {agent}. Manual review required.",
            }))

        logger.info("SOAR executed %d action(s) for verdict=%s", len(actions_taken), verdict)
        return actions_taken

    def dispatch(self, action: str, params: dict[str, Any]) -> dict:
        """Dispatch a single action string to the correct handler."""
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
        result = handlers[action](params)
        result["action"] = action
        return result
