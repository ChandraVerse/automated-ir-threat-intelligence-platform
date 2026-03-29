#!/usr/bin/env python3
"""
wazuh_client.py
===============
Wazuh REST API client and webhook listener.
Connects to the Wazuh Manager API to fetch alerts in real time
or listens on a local HTTP endpoint for Wazuh Active Response callbacks.

Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
Refs    : https://documentation.wazuh.com/current/user-manual/api/reference.html
"""

import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Callable, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Wazuh REST API Client
# ─────────────────────────────────────────────────────────────────────────────

class WazuhClient:
    """
    Connects to Wazuh Manager REST API (v4.x).
    Authenticates via JWT, fetches alerts with pagination support,
    and exposes a polling loop for continuous alert ingestion.
    """

    AUTH_ENDPOINT  = "/security/user/authenticate"
    ALERTS_INDEX   = "/wazuh-alerts-*/_search"
    AGENTS_ENDPOINT = "/agents"

    def __init__(self, host: str, user: str, password: str, verify_ssl: bool = False):
        """
        Args:
            host       : Wazuh Manager URL e.g. https://localhost:55000
            user       : API username (default: wazuh)
            password   : API password
            verify_ssl : Set True in production with valid certs
        """
        self.base_url   = host.rstrip("/")
        self.user       = user
        self.password   = password
        self.verify_ssl = verify_ssl
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0
        self.session = requests.Session()
        self.session.verify = verify_ssl

    # ── Authentication ────────────────────────────────────────────────────────

    def _authenticate(self) -> str:
        """Fetch a JWT token from Wazuh API. Tokens expire after 900s."""
        resp = self.session.post(
            f"{self.base_url}{self.AUTH_ENDPOINT}",
            auth=(self.user, self.password),
            timeout=15,
        )
        resp.raise_for_status()
        token = resp.json()["data"]["token"]
        self._token        = token
        self._token_expiry = time.time() + 850   # refresh 50s before expiry
        log.info("Wazuh JWT token obtained (expires in ~14 min)")
        return token

    def _get_token(self) -> str:
        """Return a valid token, re-authenticating if expired."""
        if not self._token or time.time() >= self._token_expiry:
            self._authenticate()
        return self._token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }

    # ── Alert Fetching ────────────────────────────────────────────────────────

    def get_alerts(
        self,
        since_minutes: int = 5,
        min_level: int = 3,
        limit: int = 100,
    ) -> list[dict]:
        """
        Fetch alerts from Wazuh Indexer (OpenSearch) via the alerts index.

        Args:
            since_minutes : Look back window in minutes
            min_level     : Minimum Wazuh alert level (1–15)
            limit         : Max alerts to return per call

        Returns:
            List of normalised alert dicts
        """
        since_ts = (
            datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": since_ts}}},
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
            "_source": [
                "timestamp", "id", "agent.name", "agent.ip",
                "rule.id", "rule.description", "rule.level", "rule.groups",
                "rule.mitre.id", "rule.mitre.tactic",
                "data.srcip", "data.dstip", "data.win.eventdata.sourceIp",
                "data.sha256", "data.md5", "data.url",
                "full_log", "location", "manager.name",
            ],
        }

        try:
            resp = self.session.post(
                f"{self.base_url}{self.ALERTS_INDEX}",
                headers=self._headers(),
                json=query,
                timeout=30,
            )
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
            alerts = [h["_source"] for h in hits]
            log.info("Fetched %d alerts (level >= %d, last %d min)", len(alerts), min_level, since_minutes)
            return alerts
        except requests.RequestException as exc:
            log.error("Failed to fetch alerts: %s", exc)
            return []

    def get_agents(self) -> list[dict]:
        """Return list of all registered Wazuh agents."""
        try:
            resp = self.session.get(
                f"{self.base_url}{self.AGENTS_ENDPOINT}",
                headers=self._headers(),
                params={"limit": 500},
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json().get("data", {}).get("affected_items", [])
        except requests.RequestException as exc:
            log.error("Failed to fetch agents: %s", exc)
            return []

    def send_active_response(self, agent_id: str, command: str, arguments: list) -> bool:
        """
        Trigger a Wazuh Active Response command on a specific agent.
        e.g. isolate host, block IP via firewall.
        """
        payload = {"command": command, "arguments": arguments, "alert": {}}
        try:
            resp = self.session.put(
                f"{self.base_url}/active-response",
                headers=self._headers(),
                params={"agents_list": agent_id},
                json=payload,
                timeout=15,
            )
            resp.raise_for_status()
            log.info("Active response '%s' sent to agent %s", command, agent_id)
            return True
        except requests.RequestException as exc:
            log.error("Active response failed: %s", exc)
            return False

    # ── Polling Loop ──────────────────────────────────────────────────────────

    def poll(
        self,
        callback: Callable[[list[dict]], None],
        interval_seconds: int = 60,
        min_level: int = 3,
    ):
        """
        Continuously poll Wazuh for new alerts and invoke callback.

        Args:
            callback         : Function to call with each batch of alerts
            interval_seconds : Poll frequency
            min_level        : Minimum rule severity level to forward
        """
        log.info(
            "Starting Wazuh poll loop (interval=%ds, min_level=%d)",
            interval_seconds, min_level
        )
        while True:
            try:
                alerts = self.get_alerts(
                    since_minutes=interval_seconds // 60 + 1,
                    min_level=min_level,
                )
                if alerts:
                    callback(alerts)
            except Exception as exc:
                log.error("Poll iteration error: %s", exc)
            time.sleep(interval_seconds)


# ─────────────────────────────────────────────────────────────────────────────
# Webhook Listener (for Wazuh Active Response / Integrations)
# ─────────────────────────────────────────────────────────────────────────────

class WazuhWebhookHandler(BaseHTTPRequestHandler):
    """HTTP request handler for incoming Wazuh webhook POSTs."""

    callback: Optional[Callable[[dict], None]] = None

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            alert = json.loads(body.decode("utf-8"))
            log.info(
                "Webhook received alert: rule=%s level=%s agent=%s",
                alert.get("rule", {}).get("id"),
                alert.get("rule", {}).get("level"),
                alert.get("agent", {}).get("name"),
            )
            if self.callback:
                self.callback(alert)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
        except (json.JSONDecodeError, Exception) as exc:
            log.error("Webhook parse error: %s", exc)
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"status": "error"}')

    def log_message(self, fmt, *args):
        log.debug("Webhook: " + fmt % args)


def start_webhook_server(
    port: int,
    callback: Callable[[dict], None],
    host: str = "0.0.0.0",
) -> Thread:
    """
    Start the Wazuh webhook HTTP server in a background thread.

    Args:
        port     : Port to listen on (e.g. 8080)
        callback : Function called with each inbound alert dict
        host     : Bind address

    Returns:
        The background Thread (daemon=True)
    """
    WazuhWebhookHandler.callback = callback
    server = HTTPServer((host, port), WazuhWebhookHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log.info("Wazuh webhook listener running on %s:%d", host, port)
    return thread
