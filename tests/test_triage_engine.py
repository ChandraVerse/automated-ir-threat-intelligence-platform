"""
Unit tests for soar-automation/triage/triage_engine.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from soar_automation.triage.triage_engine import TriageEngine


@pytest.fixture
def engine():
    return TriageEngine(config={})


def make_enriched_ioc(verdict="CLEAN", ioc="8.8.8.8"):
    return {
        "ioc": ioc,
        "ioc_type": "ip",
        "verdict": {"verdict": verdict, "confidence": 80, "score": 30},
    }


class TestTriageEngine:
    def test_malicious_ioc_triggers_malicious(self, engine):
        alert = {"severity": 10, "description": "Brute force", "src_ip": "185.220.101.45"}
        result = engine.evaluate(alert=alert, enriched_iocs=[make_enriched_ioc("MALICIOUS")])
        assert result["verdict"] == "MALICIOUS"

    def test_clean_ioc_returns_clean(self, engine):
        alert = {"severity": 3, "description": "Low severity event"}
        result = engine.evaluate(alert=alert, enriched_iocs=[make_enriched_ioc("CLEAN")])
        assert result["verdict"] in ["CLEAN", "SUSPICIOUS"]

    def test_result_has_playbook(self, engine):
        alert = {"severity": 10}
        result = engine.evaluate(alert=alert, enriched_iocs=[make_enriched_ioc("MALICIOUS")])
        assert "playbook" in result

    def test_empty_iocs_handled(self, engine):
        alert = {"severity": 5, "description": "Test"}
        result = engine.evaluate(alert=alert, enriched_iocs=[])
        assert "verdict" in result

    def test_confidence_in_result(self, engine):
        alert = {"severity": 8}
        result = engine.evaluate(alert=alert, enriched_iocs=[make_enriched_ioc("SUSPICIOUS")])
        assert "confidence" in result
