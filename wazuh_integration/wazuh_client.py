#!/usr/bin/env python3
"""
wazuh_client.py
===============
Wazuh REST API client and webhook listener.

Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # nosec B501

log = logging.getLogger(__name__)


class WazuhClient:
    AUTH_ENDPOINT   = "/security/user/authenticate"
    ALERTS_INDEX    = "/wazuh-alerts-*/_search"
    AGENTS_ENDPOINT = "/agents"

    def __init__(self, host: str, user: str, password: str, verify_ssl: bool = True):
        self.base_url   = host.rstrip("/")
        self.user       = user
        self.password   = password
        self.verify_ssl = verify_ssl
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0
        self.session = requests.Session()
        self.session.verify = verify_ssl  # nosec B501

    def _authenticate(self) -> str:
        resp = self.session.post(
            f"{self.base_url}{self.AUTH_ENDPOINT}",
            auth=(self.user, self.password),
            timeout=15,
        )
        resp.raise_for_status()
        token = resp.json()["data"]["token"]
        self._token        = token
        self._token_expiry = time.time() + 850
        log.info("Wazuh JWT token obtained")
        return token

    def _get_token(self) -> str:
        if not self._token or time.time() >= self._token_expiry:
            self._authenticate()
        return self._token

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._get_token()}", "Content-Type": "application/json"}

    def get_alerts(self, since_minutes: int = 5, min_level: int = 3, limit: int = 100) -> list[dict]:
        since_ts = (
            datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": [
                {"range": {"timestamp": {"gte": since_ts}}},
                {"range": {"rule.level": {"gte": min_level}}},
            ]}},
        }
        try:
            resp = self.session.post(
                f"{self.base_url}{self.ALERTS_INDEX}",
                headers=self._headers(), json=query, timeout=30,
            )
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
            return [h["_source"] for h in hits]
        except requests.RequestException as exc:
            log.error("Failed to fetch alerts: %s", exc)
            return []

    def poll(self, callback: Callable[[list[dict]], None], interval_seconds: int = 60, min_level: int = 3):
        while True:
            try:
                alerts = self.get_alerts(since_minutes=interval_seconds // 60 + 1, min_level=min_level)
                if alerts:
                    callback(alerts)
            except Exception as exc:  # noqa: BLE001
                log.error("Poll error: %s", exc)
            time.sleep(interval_seconds)


class WazuhWebhookHandler(BaseHTTPRequestHandler):
    callback: Optional[Callable[[dict], None]] = None

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            alert = json.loads(body.decode("utf-8"))
            if self.callback:
                self.callback(alert)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
        except Exception as exc:  # noqa: BLE001
            log.error("Webhook parse error: %s", exc)
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"status": "error"}')

    def log_message(self, fmt, *args):
        log.debug("Webhook: " + fmt % args)


def start_webhook_server(port: int, callback: Callable[[dict], None], host: str = "0.0.0.0") -> Thread:
    WazuhWebhookHandler.callback = callback
    server = HTTPServer((host, port), WazuhWebhookHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log.info("Wazuh webhook listener running on %s:%d", host, port)
    return thread
