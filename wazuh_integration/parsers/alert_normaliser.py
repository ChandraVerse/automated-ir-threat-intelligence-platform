#!/usr/bin/env python3
"""
alert_normaliser.py — Normalises raw Wazuh alert JSON into standard IR schema.
Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
"""

import hashlib
import ipaddress
import re
import logging
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field, asdict

log = logging.getLogger(__name__)


@dataclass
class IOC:
    ioc_type: str
    value: str
    context: str = ""
    enrichment: dict = field(default_factory=dict)
    verdict: str = "UNKNOWN"


@dataclass
class NormalisedAlert:
    alert_id: str
    timestamp: str
    source: str
    rule_id: str
    rule_name: str
    rule_level: int
    severity: str
    agent_name: str
    agent_ip: str
    mitre_techniques: list
    mitre_tactics: list
    iocs: list
    raw_log: str
    location: str
    manager: str
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


_RE_IPV4   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
_RE_SHA1   = re.compile(r'\b[0-9a-fA-F]{40}\b')
_RE_MD5    = re.compile(r'\b[0-9a-fA-F]{32}\b')
_RE_URL    = re.compile(r'https?://[^\s"\'<>]+')

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]


def _is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def extract_iocs_from_text(text: str, context: str = "log") -> list:
    iocs = []
    seen: set = set()
    for ip in _RE_IPV4.findall(text):
        if ip not in seen and _is_public_ip(ip):
            iocs.append(IOC(ioc_type="ip", value=ip, context=context))
            seen.add(ip)
    for h in _RE_SHA256.findall(text):
        if h not in seen:
            iocs.append(IOC(ioc_type="hash", value=h.lower(), context=context))
            seen.add(h)
    for h in _RE_SHA1.findall(text):
        if h not in seen:
            iocs.append(IOC(ioc_type="hash", value=h.lower(), context=context))
            seen.add(h)
    for h in _RE_MD5.findall(text):
        if h not in seen:
            iocs.append(IOC(ioc_type="hash", value=h.lower(), context=context))
            seen.add(h)
    for url in _RE_URL.findall(text):
        if url not in seen:
            iocs.append(IOC(ioc_type="url", value=url, context=context))
            seen.add(url)
    return iocs


def _level_to_severity(level: int) -> str:
    if level >= 13: return "CRITICAL"
    if level >= 10: return "HIGH"
    if level >= 7:  return "MEDIUM"
    if level >= 4:  return "LOW"
    return "INFO"


def _make_alert_id(alert: dict) -> str:
    raw = f"{alert.get('rule', {}).get('id')}{alert.get('agent', {}).get('name')}{alert.get('timestamp')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16].upper()


def normalise_alert(raw: dict) -> Optional[NormalisedAlert]:
    if not raw or not isinstance(raw, dict):
        if raw is None:
            return None
        raw = {}
    try:
        rule  = raw.get("rule", {})
        agent = raw.get("agent", {})
        data  = raw.get("data", {})
        mitre = rule.get("mitre", {})
        rule_level = int(rule.get("level", 0))
        timestamp  = raw.get("timestamp", datetime.now(timezone.utc).isoformat())
        iocs = []
        for field_name, ctx in [("srcip", "source_ip"), ("dstip", "dest_ip")]:
            val = data.get(field_name)
            if val and isinstance(val, str) and _is_public_ip(val):
                iocs.append(IOC(ioc_type="ip", value=val, context=ctx))
        for hash_field, ctx in [("sha256", "file_sha256"), ("md5", "file_md5")]:
            val = data.get(hash_field)
            if val and isinstance(val, str) and len(val) in (32, 40, 64):
                iocs.append(IOC(ioc_type="hash", value=val.lower(), context=ctx))
        full_log = raw.get("full_log", "")
        if full_log:
            existing = {i.value for i in iocs}
            iocs.extend(i for i in extract_iocs_from_text(full_log, "full_log") if i.value not in existing)
        return NormalisedAlert(
            alert_id         = _make_alert_id(raw),
            timestamp        = timestamp,
            source           = "wazuh",
            rule_id          = str(rule.get("id", "")),
            rule_name        = rule.get("description", "Unknown Rule"),
            rule_level       = rule_level,
            severity         = _level_to_severity(rule_level),
            agent_name       = agent.get("name", "unknown"),
            agent_ip         = agent.get("ip", "unknown"),
            mitre_techniques = mitre.get("id", []) if isinstance(mitre.get("id"), list) else [],
            mitre_tactics    = mitre.get("tactic", []) if isinstance(mitre.get("tactic"), list) else [],
            iocs             = iocs,
            raw_log          = full_log,
            location         = raw.get("location", ""),
            manager          = raw.get("manager", {}).get("name", ""),
            extra            = {"rule_groups": rule.get("groups", [])},
        )
    except Exception as exc:  # noqa: BLE001
        log.error("Failed to normalise alert: %s", exc)
        return None


def normalise_alerts(raw_list: list) -> list:
    results = [normalise_alert(r) for r in raw_list]
    return [r for r in results if r is not None]
