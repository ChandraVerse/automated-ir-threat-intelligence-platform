#!/usr/bin/env python3
"""
verdict_engine.py
=================
Weighted composite verdict engine. Merges enrichment results
from VirusTotal, AbuseIPDB, and Shodan into a single
MALICIOUS / SUSPICIOUS / CLEAN verdict with confidence score.

Author  : Chandra Sekhar Chakraborty
Project : Automated IR & Threat Intelligence Platform
"""

import logging

log = logging.getLogger(__name__)


class VerdictEngine:
    """
    Weighted scoring model for composite IOC verdicts.

    Weights (configurable):
        VirusTotal  : 0.50  (highest weight — most AV coverage)
        AbuseIPDB   : 0.35  (strong community signal for IPs)
        Shodan      : 0.15  (contextual / enrichment — lower direct weight)

    Thresholds:
        risk_score >= 70  → MALICIOUS   (high confidence threat)
        risk_score >= 35  → SUSPICIOUS  (investigate further)
        risk_score < 35   → CLEAN
    """

    WEIGHTS = {
        "virustotal": 0.50,
        "abuseipdb" : 0.35,
        "shodan"    : 0.15,
    }

    MALICIOUS_THRESHOLD  = 70
    SUSPICIOUS_THRESHOLD = 35

    def _vt_score(self, vt: dict) -> float:
        """
        Convert VirusTotal last_analysis_stats to a 0–100 score.
        Score = (malicious / total_engines) * 100
        """
        if not vt or "error" in vt or vt.get("verdict") == "NOT_FOUND":
            return 0.0
        malicious  = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        total      = malicious + suspicious + vt.get("harmless", 0) + vt.get("undetected", 0)
        if total == 0:
            return 0.0
        score = ((malicious * 1.0 + suspicious * 0.5) / total) * 100
        # Bonus if reputation is explicitly negative
        if vt.get("reputation", 0) < -10:
            score = min(score + 10, 100)
        return round(score, 2)

    def _abuseipdb_score(self, abuse: dict) -> float:
        """
        AbuseIPDB confidence score is already 0–100.
        Adjust: whitelisted IPs get 0.
        """
        if not abuse or "error" in abuse:
            return 0.0
        if abuse.get("is_whitelisted"):
            return 0.0
        return float(abuse.get("abuse_confidence_score", 0))

    def _shodan_score(self, shodan: dict) -> float:
        """
        Shodan doesn't give a direct maliciousness score.
        Infer risk from: known vulns, open dangerous ports, tags.
        """
        if not shodan or "error" in shodan or shodan.get("verdict") == "NOT_FOUND":
            return 0.0

        score = 0.0
        vulns      = shodan.get("vulns", [])
        open_ports = shodan.get("open_ports", [])
        tags       = shodan.get("tags", [])

        # CVE count
        score += min(len(vulns) * 8, 40)

        # Suspicious open ports
        dangerous_ports = {21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 4444, 5900, 6379, 8080, 27017}
        hits = len(set(open_ports) & dangerous_ports)
        score += min(hits * 5, 20)

        # Tags
        if "malware" in tags or "botnet" in tags or "tor" in tags:
            score += 30
        if "scanner" in tags or "honeypot" in tags:
            score += 15

        return min(round(score, 2), 100)

    def compute(self, enrichment: dict) -> dict:
        """
        Compute weighted composite verdict from enrichment dict.

        Args:
            enrichment: Dict with keys virustotal, abuseipdb, shodan (any may be absent)

        Returns:
            Dict with keys: verdict, confidence, risk_score, component_scores
        """
        vt_score    = self._vt_score(enrichment.get("virustotal", {}))
        abuse_score = self._abuseipdb_score(enrichment.get("abuseipdb", {}))
        shodan_score= self._shodan_score(enrichment.get("shodan", {}))

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

        result = {
            "verdict"   : verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "component_scores": {
                "virustotal" : vt_score,
                "abuseipdb"  : abuse_score,
                "shodan"     : shodan_score,
            },
        }
        log.debug(
            "Verdict for %s: %s (risk=%.1f, vt=%.1f, abuse=%.1f, shodan=%.1f)",
            enrichment.get("value", "?"), verdict, risk_score,
            vt_score, abuse_score, shodan_score,
        )
        return result
