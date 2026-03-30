"""
Unit tests for ioc-pipeline/verdict_engine.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ioc-pipeline"))

import pytest
from verdict_engine import VerdictEngine


@pytest.fixture
def engine():
    return VerdictEngine()


def make_enrichment(vt_malicious=0, vt_total=70, abuse_score=0, vulns=None, ports=None, tags=None):
    """Build a single enrichment dict as VerdictEngine.compute() expects."""
    harmless = vt_total - vt_malicious
    return {
        "virustotal": {
            "malicious": vt_malicious,
            "suspicious": 0,
            "harmless": harmless,
            "undetected": 0,
            "reputation": -vt_malicious * 5,
        },
        "abuseipdb": {
            "abuse_confidence_score": abuse_score,
            "is_whitelisted": False,
        },
        "shodan": {
            "open_ports": ports or [],
            "vulns": vulns or [],
            "tags": tags or [],
        },
    }


class TestVerdictEngine:
    def test_clean_verdict(self, engine):
        result = engine.compute(make_enrichment(vt_malicious=0, abuse_score=0))
        assert result["verdict"] == "CLEAN"
        assert 0 <= result["confidence"] <= 100

    def test_malicious_verdict_high_vt(self, engine):
        result = engine.compute(make_enrichment(vt_malicious=50, abuse_score=90))
        assert result["verdict"] == "MALICIOUS"

    def test_suspicious_verdict(self, engine):
        result = engine.compute(make_enrichment(vt_malicious=5, abuse_score=30))
        assert result["verdict"] in ["SUSPICIOUS", "MALICIOUS"]

    def test_confidence_is_percentage(self, engine):
        result = engine.compute(make_enrichment(vt_malicious=2, abuse_score=20))
        assert 0 <= result["confidence"] <= 100

    def test_verdict_with_vulns(self, engine):
        result = engine.compute(make_enrichment(
            vt_malicious=0, abuse_score=0, vulns=["CVE-2021-44228"]
        ))
        assert result["verdict"] in ["SUSPICIOUS", "MALICIOUS"]

    def test_error_source_handled_gracefully(self, engine):
        enrichment = {
            "virustotal": {"error": "not_found"},
            "abuseipdb": {"abuse_confidence_score": 0, "is_whitelisted": False},
            "shodan": {"open_ports": [], "vulns": [], "tags": []},
        }
        result = engine.compute(enrichment)
        assert "verdict" in result
        assert "confidence" in result

    def test_component_scores_present(self, engine):
        result = engine.compute(make_enrichment(vt_malicious=10, abuse_score=50))
        assert "component_scores" in result
        assert "virustotal" in result["component_scores"]
        assert "abuseipdb" in result["component_scores"]
        assert "shodan" in result["component_scores"]
