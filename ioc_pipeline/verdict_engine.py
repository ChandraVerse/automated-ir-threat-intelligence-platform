#!/usr/bin/env python3
"""
verdict_engine.py — Weighted composite verdict engine.
Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
"""

import logging

log = logging.getLogger(__name__)


class VerdictEngine:
    WEIGHTS = {"virustotal": 0.50, "abuseipdb": 0.35, "shodan": 0.15}
    MALICIOUS_THRESHOLD  = 70
    SUSPICIOUS_THRESHOLD = 35

    def _vt_score(self, vt: dict) -> float:
        if not vt or "error" in vt or vt.get("verdict") == "NOT_FOUND":
            return 0.0
        malicious  = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        total      = malicious + suspicious + vt.get("harmless", 0) + vt.get("undetected", 0)
        if total == 0:
            return 0.0
        score = ((malicious * 1.0 + suspicious * 0.5) / total) * 100
        if vt.get("reputation", 0) < -10:
            score = min(score + 10, 100)
        return round(score, 2)

    def _abuseipdb_score(self, abuse: dict) -> float:
        if not abuse or "error" in abuse:
            return 0.0
        if abuse.get("is_whitelisted"):
            return 0.0
        return float(abuse.get("abuse_confidence_score", 0))

    def _shodan_score(self, shodan: dict) -> float:
        if not shodan or "error" in shodan or shodan.get("verdict") == "NOT_FOUND":
            return 0.0
        score = 0.0
        vulns      = shodan.get("vulns", [])
        open_ports = shodan.get("open_ports", [])
        tags       = shodan.get("tags", [])
        score += min(len(vulns) * 8, 40)
        dangerous_ports = {21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 4444, 5900, 6379, 8080, 27017}
        hits = len(set(open_ports) & dangerous_ports)
        score += min(hits * 5, 20)
        if "malware" in tags or "botnet" in tags or "tor" in tags:
            score += 30
        if "scanner" in tags or "honeypot" in tags:
            score += 15
        return min(round(score, 2), 100)

    def compute(self, enrichment: dict) -> dict:
        vt_score     = self._vt_score(enrichment.get("virustotal", {}))
        abuse_score  = self._abuseipdb_score(enrichment.get("abuseipdb", {}))
        shodan_score = self._shodan_score(enrichment.get("shodan", {}))
        weighted = (
            vt_score    * self.WEIGHTS["virustotal"] +
            abuse_score * self.WEIGHTS["abuseipdb"]  +
            shodan_score * self.WEIGHTS["shodan"]
        )
        risk_score = round(weighted, 1)
        if risk_score >= self.MALICIOUS_THRESHOLD:
            verdict    = "MALICIOUS"
            confidence = min(100, round(risk_score * 1.1))
        elif risk_score >= self.SUSPICIOUS_THRESHOLD:
            verdict    = "SUSPICIOUS"
            confidence = round(risk_score)
        else:
            verdict    = "CLEAN"
            confidence = round(100 - risk_score)
        return {
            "verdict"   : verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "component_scores": {
                "virustotal" : vt_score,
                "abuseipdb"  : abuse_score,
                "shodan"     : shodan_score,
            },
        }
