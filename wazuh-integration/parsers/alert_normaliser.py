#!/usr/bin/env python3
"""
alert_normaliser.py
===================
Normalises raw Wazuh alert JSON into a standard IR schema consumed
by the enrichment pipeline and SOAR engine.

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

# ─────────────────────────────────────────────────────────────────────────────
# IR Alert Schema
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IOC:
    """A single Indicator of Compromise extracted from an alert."""
    ioc_type: str          # ip | hash | domain | url | email
    value: str
    context: str = ""      # e.g. "source_ip", "file_hash", "c2_domain"
    enrichment: dict = field(default_factory=dict)
    verdict: str = "UNKNOWN"  # MALICIOUS | SUSPICIOUS | CLEAN | UNKNOWN


@dataclass
class NormalisedAlert:
    """Standardised IR alert schema."""
    alert_id: str
    timestamp: str
    source: str                        # "wazuh"
    rule_id: str
    rule_name: str
    rule_level: int                    # Wazuh severity 1–15
    severity: str                      # CRITICAL | HIGH | MEDIUM | LOW | INFO
    agent_name: str
    agent_ip: str
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    iocs: list[IOC]
    raw_log: str
    location: str
    manager: str
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ─────────────────────────────────────────────────────────────────────────────
# IOC Extraction
# ─────────────────────────────────────────────────────────────────────────────

# Regex patterns
_RE_IPV4    = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_RE_MD5     = re.compile(r'\b[0-9a-fA-F]{32}\b')
_RE_SHA1    = re.compile(r'\b[0-9a-fA-F]{40}\b')
_RE_SHA256  = re.compile(r'\b[0-9a-fA-F]{64}\b')
_RE_DOMAIN  = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
_RE_URL     = re.compile(r'https?://[^\s"\'<>]+')

# Private / loopback ranges to skip
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


def extract_iocs_from_text(text: str, context: str = "log") -> list[IOC]:
    """Extract all IOCs from a raw text string."""
    iocs: list[IOC] = []
    seen: set[str] = set()

    # IPs
    for ip in _RE_IPV4.findall(text):
        if ip not in seen and _is_public_ip(ip):
            iocs.append(IOC(ioc_type="ip", value=ip, context=context))
            seen.add(ip)

    # SHA256
    for h in _RE_SHA256.findall(text):
        if h not in seen:
            iocs.append(IOC(ioc_type="hash", value=h.lower(), context=context))
            seen.add(h)

    # SHA1
    for h in _RE_SHA1.findall(text):
        if h not in seen:
            iocs.append(IOC(ioc_type="hash", value=h.lower(), context=context))
            seen.add(h)

    # MD5
    for h in _RE_MD5.findall(text):
        if h not in seen:
            iocs.append(IOC(ioc_type="hash", value=h.lower(), context=context))
            seen.add(h)

    # URLs (extract before domains to avoid double-counting)
    for url in _RE_URL.findall(text):
        if url not in seen:
            iocs.append(IOC(ioc_type="url", value=url, context=context))
            seen.add(url)

    return iocs


# ─────────────────────────────────────────────────────────────────────────────
# Alert Normaliser
# ─────────────────────────────────────────────────────────────────────────────

def _level_to_severity(level: int) -> str:
    if level >= 13:  return "CRITICAL"
    if level >= 10:  return "HIGH"
    if level >= 7:   return "MEDIUM"
    if level >= 4:   return "LOW"
    return "INFO"


def _make_alert_id(alert: dict) -> str:
    """Generate a stable alert ID from rule + agent + timestamp."""
    raw = f"{alert.get('rule', {}).get('id')}{alert.get('agent', {}).get('name')}{alert.get('timestamp')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16].upper()


def normalise_alert(raw: dict) -> Optional[NormalisedAlert]:
    """
    Convert a raw Wazuh alert dict to a NormalisedAlert.

    Args:
        raw: Raw Wazuh alert JSON (as Python dict)

    Returns:
        NormalisedAlert or None if alert is malformed / below threshold
    """
    try:
        rule        = raw.get("rule", {})
        agent       = raw.get("agent", {})
        data        = raw.get("data", {})
        mitre       = rule.get("mitre", {})

        rule_level  = int(rule.get("level", 0))
        timestamp   = raw.get("timestamp", datetime.now(timezone.utc).isoformat())

        # IOC extraction from structured fields + full log
        iocs: list[IOC] = []

        # Structured IP fields
        for field_path, ctx in [
            ("srcip", "source_ip"),
            ("dstip", "dest_ip"),
            ("win.eventdata.sourceIp", "win_source_ip"),
        ]:
            val = data.get(field_path) or data.get("win", {}).get("eventdata", {}).get("sourceIp")
            if val and isinstance(val, str) and _is_public_ip(val):
                iocs.append(IOC(ioc_type="ip", value=val, context=ctx))

        # Hash fields
        for hash_field, ctx in [("sha256", "file_sha256"), ("md5", "file_md5")]:
            val = data.get(hash_field)
            if val and isinstance(val, str) and len(val) in (32, 40, 64):
                iocs.append(IOC(ioc_type="hash", value=val.lower(), context=ctx))

        # URL field
        if data.get("url"):
            iocs.append(IOC(ioc_type="url", value=data["url"], context="alert_url"))

        # Free-text IOCs from full_log
        full_log = raw.get("full_log", "")
        if full_log:
            text_iocs = extract_iocs_from_text(full_log, context="full_log")
            existing_values = {i.value for i in iocs}
            iocs.extend(i for i in text_iocs if i.value not in existing_values)

        return NormalisedAlert(
            alert_id        = _make_alert_id(raw),
            timestamp       = timestamp,
            source          = "wazuh",
            rule_id         = str(rule.get("id", "")),
            rule_name       = rule.get("description", "Unknown Rule"),
            rule_level      = rule_level,
            severity        = _level_to_severity(rule_level),
            agent_name      = agent.get("name", "unknown"),
            agent_ip        = agent.get("ip", "unknown"),
            mitre_techniques= mitre.get("id", []) if isinstance(mitre.get("id"), list) else [],
            mitre_tactics   = mitre.get("tactic", []) if isinstance(mitre.get("tactic"), list) else [],
            iocs            = iocs,
            raw_log         = full_log,
            location        = raw.get("location", ""),
            manager         = raw.get("manager", {}).get("name", ""),
            extra           = {"rule_groups": rule.get("groups", [])},
        )

    except Exception as exc:
        log.error("Failed to normalise alert: %s | raw=%s", exc, str(raw)[:200])
        return None


def normalise_alerts(raw_list: list[dict]) -> list[NormalisedAlert]:
    """Normalise a list of raw Wazuh alerts."""
    results = []
    for raw in raw_list:
        alert = normalise_alert(raw)
        if alert:
            results.append(alert)
    log.info("Normalised %d / %d alerts", len(results), len(raw_list))
    return results
