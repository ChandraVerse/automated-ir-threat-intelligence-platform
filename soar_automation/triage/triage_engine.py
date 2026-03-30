"""
Alert Triage Engine — Prioritises incoming alerts.
Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
"""
from __future__ import annotations
import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

logger = logging.getLogger(__name__)


class Priority(IntEnum):
    CRITICAL = 1
    HIGH     = 2
    MEDIUM   = 3
    LOW      = 4
    INFO     = 5


HIGH_IMPACT_TACTICS = {
    "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
    "TA0006", "TA0008", "TA0010", "TA0040",
}


@dataclass
class TriageResult:
    alert_id: str
    priority: Priority
    score: float
    rationale: list
    recommended_playbook: str | None = None


class TriageEngine:
    LEVEL_WEIGHT  = 0.40
    IOC_WEIGHT    = 0.45
    TACTIC_WEIGHT = 0.15

    def triage(self, alert: dict[str, Any], ioc_score: float = 0.0) -> TriageResult:
        alert_id = str(alert.get("id", "unknown"))
        rule     = alert.get("rule", {})
        rule_level: int = int(rule.get("level", 0))
        mitre_tactics: list = rule.get("mitre", {}).get("tactic_id", [])
        level_score  = (rule_level / 15.0) * 100.0
        tactic_score = 100.0 if any(t in HIGH_IMPACT_TACTICS for t in mitre_tactics) else 30.0
        composite = (
            level_score  * self.LEVEL_WEIGHT +
            ioc_score    * self.IOC_WEIGHT   +
            tactic_score * self.TACTIC_WEIGHT
        )
        rationale = [
            f"Rule level {rule_level}/15 -> level_score={level_score:.1f}",
            f"IOC score={ioc_score:.1f}",
            f"MITRE tactics={mitre_tactics} -> tactic_score={tactic_score:.1f}",
            f"Composite={composite:.1f}",
        ]
        priority = self._map_priority(composite)
        playbook = self._recommend_playbook(alert, ioc_score, priority)
        logger.info("alert=%s priority=%s composite=%.1f", alert_id, priority.name, composite)
        return TriageResult(
            alert_id=alert_id, priority=priority,
            score=composite, rationale=rationale, recommended_playbook=playbook,
        )

    @staticmethod
    def _map_priority(score: float) -> Priority:
        if score >= 80: return Priority.CRITICAL
        if score >= 60: return Priority.HIGH
        if score >= 40: return Priority.MEDIUM
        if score >= 20: return Priority.LOW
        return Priority.INFO

    @staticmethod
    def _recommend_playbook(alert: dict, ioc_score: float, priority: Priority) -> str | None:
        verdict  = alert.get("ioc_verdict", "")
        ioc_type = alert.get("ioc_type", "ip")
        if verdict == "MALICIOUS" and ioc_type == "ip":   return "malicious_ip"
        if verdict == "SUSPICIOUS" and ioc_type == "ip":  return "suspicious_ip"
        if verdict == "MALICIOUS" and ioc_type == "hash": return "malicious_hash"
        return None
